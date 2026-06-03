"""Source code scanner.

Combines three techniques over OJS source files:

* **Taint analysis** (forward, intra-procedural) on PHP using a tree-sitter AST,
  tracking OJS-aware sources -> sanitizers -> sinks.
* **Regex pattern matching** driven by the YAML ruleset (PHP + JS rules).
* **Dedicated handlers** for Smarty templates (unescaped output) and a
  tree-sitter handler for Handler CSRF checks.
* **CVE-specific scanning** via structured multi-condition rules that target
  known OJS vulnerabilities with high precision.

If tree-sitter is unavailable the scanner degrades gracefully to regex-only.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..helpers.snippet_utils import build_code_snippet
from ..models import Finding, Rule, Severity
from ..ruleset.loader import Ruleset

logger = logging.getLogger("ojs_sast.source")

# --------------------------------------------------------------------------- #
# tree-sitter parser loading (graceful fallback)
# --------------------------------------------------------------------------- #
TREE_SITTER_AVAILABLE = False
_PARSERS: Dict[str, object] = {}

try:  # pragma: no cover - import guard
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from tree_sitter_languages import get_parser as _ts_get_parser  # type: ignore

    TREE_SITTER_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    logger.warning("tree-sitter not available, taint/AST analysis disabled: %s", exc)
    _ts_get_parser = None  # type: ignore


def _get_parser(language: str):
    if not TREE_SITTER_AVAILABLE:
        return None
    if language not in _PARSERS:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _PARSERS[language] = _ts_get_parser(language)
    return _PARSERS[language]


# --------------------------------------------------------------------------- #
# OJS-aware source / sanitizer / sink vocabularies (lowercased for matching)
# --------------------------------------------------------------------------- #
SUPERGLOBAL_SOURCES = {
    "$_get", "$_post", "$_request", "$_cookie", "$_files", "$_server",
}
# Request abstractions (matched by simple method/function name, OJS 2.x & 3.x).
REQUEST_SOURCE_NAMES = {
    "getuservar", "getuservars", "getquerystring", "getqueryarray",
    "getrequestedargs", "getrequestedarg",
}
# Weaker, attacker-influenced filename sources (path-traversal relevant only).
# "textcontent" covers DOMElement->textContent used in NativeXml import filters
# (CVE-2023-47271, CVE-2025-67890): XML node content used as a filename/path.
FILENAME_SOURCE_NAMES = {
    "getfilename", "getname", "getclientfilename", "getlocalizedname",
    "getoriginalfilename", "textcontent",
}

SANITIZER_FUNCS = {
    "htmlspecialchars", "htmlentities", "intval", "floatval", "strip_tags",
    "escapeshellarg", "escapeshellcmd", "urlencode", "rawurlencode",
    "filter_var", "preg_quote", "md5", "sha1", "hash", "password_hash",
    "bin2hex", "number_format", "ctype_alnum", "ctype_digit", "boolval",
}
SANITIZER_METHODS = {
    "htmlspecialchars", "regexp_replace", "strip_tags", "escape",
}
# Taint-preserving string wrappers (recursively check arguments).
PASSTHROUGH_FUNCS = {
    "trim", "ltrim", "rtrim", "strval", "sprintf", "vsprintf", "str_replace",
    "str_ireplace", "preg_replace", "substr", "ucfirst", "ucwords", "lcfirst",
    "strtolower", "strtoupper", "urldecode", "rawurldecode", "stripslashes",
    "htmlspecialchars_decode", "html_entity_decode", "str_pad", "nl2br",
    "implode", "join", "addslashes", "wordwrap",
}

XSS_SINK_FUNCS = {"printf", "vprintf"}
CODE_EXEC_FUNCS = {
    "eval", "assert", "system", "exec", "shell_exec", "passthru",
    "proc_open", "popen",
}
COMMAND_FUNCS = {"system", "exec", "shell_exec", "passthru", "proc_open", "popen"}
# function name -> indices of arguments that represent a filesystem path.
FILE_WRITE_FUNCS: Dict[str, Tuple[int, ...]] = {
    "file_put_contents": (0,),
    "move_uploaded_file": (1,),
    "copy": (0, 1),
    "rename": (0, 1),
    "fopen": (0,),
    "unlink": (0,),
}
# OJS-specific file-write methods whose first argument becomes the stored filename
# (CVE-2025-67890: setServerFileName($o->textContent) → writeFile() path traversal).
FILE_WRITE_METHODS = {
    "setserverfilename", "setfilename", "setoriginalfilename",
}
SQL_RAW_METHODS = {"raw", "statement", "unprepared"}  # any receiver
SQL_SCOPED_METHODS = {"query", "select", "insert", "update", "delete"}
SQL_DB_SCOPES = {"db", "capsule"}

# Built-in metadata fallbacks for taint rule ids (used if the ruleset lacks them).
_TAINT_DEFAULTS = {
    "RULE-SRC-002": (Severity.HIGH, "CWE-22", "Path traversal in file operation"),
    "RULE-SRC-005": (Severity.CRITICAL, "CWE-89", "SQL injection"),
    "RULE-SRC-006": (Severity.CRITICAL, "CWE-502", "Deserialization of user data"),
    "RULE-SRC-007": (Severity.HIGH, "CWE-79", "Cross-site scripting"),
    "RULE-SRC-008": (Severity.CRITICAL, "CWE-94", "Code/command execution"),
}

PHP_EXTENSIONS = {".php", ".phtml", ".inc", ".php3", ".php4", ".php5"}
SMARTY_EXTENSIONS = {".tpl", ".smarty"}
JS_EXTENSIONS = {".js", ".jsx"}
SCANNED_EXTENSIONS = PHP_EXTENSIONS | SMARTY_EXTENSIONS | JS_EXTENSIONS

DEFAULT_SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "bower_components",
    "__pycache__", ".idea", ".vscode",
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

_SCOPE_DEF_TYPES = {
    "function_definition", "method_declaration",
    "anonymous_function_creation_expression", "arrow_function",
}


# --------------------------------------------------------------------------- #
# PHP taint analyzer
# --------------------------------------------------------------------------- #
class PHPTaintAnalyzer:
    """Forward, intra-procedural taint tracking over a PHP tree-sitter AST."""

    def __init__(self, source: bytes, file_path: str, ruleset: Optional[Ruleset] = None):
        self.source = source
        self.file_path = file_path
        self.ruleset = ruleset
        self.findings: List[Finding] = []
        self._lines = source.split(b"\n")
        self._source_text = source.decode("utf-8", "replace")
        self._emitted: set = set()  # (rule_id, line, label) dedup within file

    # -- text / position helpers ------------------------------------------- #
    @staticmethod
    def _text(node) -> str:
        if node is None:
            return ""
        return node.text.decode("utf-8", "replace")

    def _line_text(self, line: int) -> str:
        if 1 <= line <= len(self._lines):
            return self._lines[line - 1].decode("utf-8", "replace").strip()
        return ""

    # -- call introspection ------------------------------------------------- #
    def _func_name(self, call_node) -> Optional[str]:
        fn = call_node.child_by_field_name("function")
        if fn is None:
            return None
        if fn.type == "name":
            return self._text(fn).lower()
        if fn.type == "qualified_name":
            return self._text(fn).split("\\")[-1].lower()
        return None  # dynamic / variable call

    def _scope_method(self, call_node) -> Tuple[str, str]:
        if call_node.type == "scoped_call_expression":
            scope = call_node.child_by_field_name("scope")
            name = call_node.child_by_field_name("name")
            s = self._text(scope).lstrip("\\").lower() if scope is not None else ""
            m = self._text(name).lower() if name is not None and name.type == "name" else ""
            return s, m
        if call_node.type == "member_call_expression":
            name = call_node.child_by_field_name("name")
            m = self._text(name).lower() if name is not None and name.type == "name" else ""
            return "", m
        return "", ""

    def _arg_nodes(self, call_node) -> List[object]:
        args = call_node.child_by_field_name("arguments")
        if args is None:
            return []
        out = []
        for c in args.named_children:
            if c.type == "argument":
                out.append(c.named_children[0] if c.named_children else c)
            elif c.type == "comment":
                continue
            else:
                out.append(c)
        return out

    # -- taint evaluation --------------------------------------------------- #
    def _taint_of(self, node, tainted: Dict[str, str], include_filename: bool = False) -> Optional[str]:
        if node is None:
            return None
        t = node.type

        if t == "variable_name":
            name = self._text(node)
            if name.lower() in SUPERGLOBAL_SOURCES:
                return name
            return tainted.get(name)

        if t == "subscript_expression":
            base = node.named_children[0] if node.named_children else None
            return self._taint_of(base, tainted, include_filename)

        if t == "member_access_expression":
            # $obj->prop : taint follows the object only for superglobal-ish bases
            base = node.child_by_field_name("object")
            return self._taint_of(base, tainted, include_filename)

        if t == "cast_expression":
            ct = next((c for c in node.children if c.type == "cast_type"), None)
            ctt = self._text(ct).lower() if ct is not None else ""
            val = node.child_by_field_name("value")
            if ctt in ("int", "integer", "float", "double", "real", "bool", "boolean"):
                return None
            return self._taint_of(val, tainted, include_filename)

        if t == "function_call_expression":
            fname = self._func_name(node)
            if fname is None:
                return None
            if fname in SANITIZER_FUNCS:
                return None
            if fname in REQUEST_SOURCE_NAMES:
                return f"{fname}()"
            if include_filename and fname in FILENAME_SOURCE_NAMES:
                return f"filename:{fname}()"
            if fname in PASSTHROUGH_FUNCS:
                return self._args_taint(node, tainted, include_filename)
            return None

        if t in ("scoped_call_expression", "member_call_expression"):
            _scope, method = self._scope_method(node)
            if method in SANITIZER_METHODS:
                return None
            if method in REQUEST_SOURCE_NAMES:
                return f"{method}()"
            if include_filename and method in FILENAME_SOURCE_NAMES:
                return f"filename:{method}()"
            return None

        if t == "binary_expression":
            left = self._taint_of(node.child_by_field_name("left"), tainted, include_filename)
            if left:
                return left
            return self._taint_of(node.child_by_field_name("right"), tainted, include_filename)

        if t == "unary_op_expression":
            return self._taint_of(node.named_children[-1] if node.named_children else None,
                                  tainted, include_filename)

        if t == "parenthesized_expression":
            return self._taint_of(node.named_children[0] if node.named_children else None,
                                  tainted, include_filename)

        if t == "conditional_expression":
            for c in node.named_children:
                lab = self._taint_of(c, tainted, include_filename)
                if lab:
                    return lab
            return None

        if t in ("encapsed_string", "string", "heredoc", "array_creation_expression"):
            for c in node.named_children:
                lab = self._taint_of(c, tainted, include_filename)
                if lab:
                    return lab
            return None

        if t in ("argument", "array_element_initializer", "pair"):
            for c in node.named_children:
                lab = self._taint_of(c, tainted, include_filename)
                if lab:
                    return lab
            return None

        # Literals / unknown: recurse named children conservatively.
        for c in node.named_children:
            lab = self._taint_of(c, tainted, include_filename)
            if lab:
                return lab
        return None

    def _args_taint(self, call_node, tainted, include_filename) -> Optional[str]:
        for a in self._arg_nodes(call_node):
            lab = self._taint_of(a, tainted, include_filename)
            if lab:
                return lab
        return None

    # -- main traversal ----------------------------------------------------- #
    def analyze(self) -> List[Finding]:
        parser = _get_parser("php")
        if parser is None:
            return []
        tree = parser.parse(self.source)
        self._walk(tree.root_node, {})
        return self.findings

    def _walk(self, node, tainted: Dict[str, str]) -> None:
        t = node.type

        if t in _SCOPE_DEF_TYPES:
            self._enter_scope(node, tainted)
            return

        if t in ("assignment_expression", "augmented_assignment_expression"):
            self._handle_assignment(node, tainted, augmented=t.startswith("augmented"))
            return

        if t == "echo_statement":
            for c in node.named_children:
                lab = self._taint_of(c, tainted)
                if lab and not lab.startswith("filename:"):
                    self._emit("RULE-SRC-007", node, lab, "an echo output sink")
                    break
            for c in node.named_children:
                self._walk(c, tainted)
            return

        if t == "print_intrinsic":
            for c in node.named_children:
                lab = self._taint_of(c, tainted)
                if lab and not lab.startswith("filename:"):
                    self._emit("RULE-SRC-007", node, lab, "a print output sink")
                    break
            for c in node.named_children:
                self._walk(c, tainted)
            return

        if t == "foreach_statement":
            self._handle_foreach(node, tainted)
            return

        if t == "function_call_expression":
            self._check_function_sink(node, tainted)
            for c in node.named_children:
                self._walk(c, tainted)
            return

        if t in ("scoped_call_expression", "member_call_expression"):
            self._check_method_sink(node, tainted)
            for c in node.named_children:
                self._walk(c, tainted)
            return

        # Default: recurse in source order.
        for c in node.named_children:
            self._walk(c, tainted)

    def _enter_scope(self, node, outer: Dict[str, str]) -> None:
        body = node.child_by_field_name("body")
        new_scope: Dict[str, str] = {}
        if node.type == "arrow_function":
            new_scope = dict(outer)  # fn() auto-captures by value
        elif node.type == "anonymous_function_creation_expression":
            for c in node.named_children:
                if c.type == "anonymous_function_use_clause":
                    for v in c.named_children:
                        if v.type == "variable_name":
                            name = self._text(v)
                            if name in outer:
                                new_scope[name] = outer[name]
        if body is not None:
            self._walk(body, new_scope)

    def _handle_assignment(self, node, tainted: Dict[str, str], augmented: bool) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if right is not None:
            self._walk(right, tainted)  # detect sinks / closures on the RHS
        if left is not None and left.type == "variable_name":
            name = self._text(left)
            label = self._taint_of(right, tainted, include_filename=True) if right is not None else None
            if label:
                tainted[name] = label
            elif not augmented:
                tainted.pop(name, None)

    def _handle_foreach(self, node, tainted: Dict[str, str]) -> None:
        children = node.named_children
        collection = children[0] if children else None
        body = node.child_by_field_name("body")
        coll_taint = self._taint_of(collection, tainted, include_filename=True) if collection else None

        value_var = None
        for c in children:
            if c is body:
                break
            if c.type == "variable_name":
                value_var = c
            elif c.type == "pair":
                vs = [x for x in c.named_children if x.type == "variable_name"]
                if vs:
                    value_var = vs[-1]
        if coll_taint and value_var is not None:
            tainted[self._text(value_var)] = coll_taint
        if collection is not None:
            self._walk(collection, tainted)
        if body is not None:
            self._walk(body, tainted)

    # -- sink handlers ------------------------------------------------------ #
    def _check_function_sink(self, node, tainted: Dict[str, str]) -> None:
        fname = self._func_name(node)
        if fname is None:
            return
        args = self._arg_nodes(node)

        if fname in XSS_SINK_FUNCS:
            for a in args:
                lab = self._taint_of(a, tainted)
                if lab and not lab.startswith("filename:"):
                    self._emit("RULE-SRC-007", node, lab, f"{fname}()")
                    return

        if fname in CODE_EXEC_FUNCS:
            for a in args:
                # assert() with a boolean/comparison expression is safe in PHP 7+:
                # the expression is evaluated as bool, never eval'd as PHP code.
                # Only flag assert() when the argument is a string type that could
                # be executed by the legacy string-eval behaviour.
                if fname == "assert" and a.type not in (
                    "string", "encapsed_string", "heredoc", "nowdoc",
                ):
                    continue
                lab = self._taint_of(a, tainted, include_filename=True)
                if lab:
                    cwe = "CWE-78" if fname in COMMAND_FUNCS else "CWE-95"
                    self._emit("RULE-SRC-008", node, lab, f"{fname}()", cwe_override=cwe)
                    return

        if fname in FILE_WRITE_FUNCS:
            for idx in FILE_WRITE_FUNCS[fname]:
                if idx < len(args):
                    lab = self._taint_of(args[idx], tainted, include_filename=True)
                    if lab:
                        self._emit("RULE-SRC-002", node, lab, f"{fname}() path argument")
                        return

        if fname == "unserialize":
            if args:
                lab = self._taint_of(args[0], tainted, include_filename=True)
                if lab:
                    self._emit("RULE-SRC-006", node, lab, "unserialize()")

    def _check_method_sink(self, node, tainted: Dict[str, str]) -> None:
        scope, method = self._scope_method(node)
        args = self._arg_nodes(node)

        is_raw = method in SQL_RAW_METHODS
        is_scoped_sql = method in SQL_SCOPED_METHODS and scope in SQL_DB_SCOPES
        if is_raw or is_scoped_sql:
            if not args:
                return
            # Only inspect the first (SQL string) argument; later args are bindings.
            lab = self._taint_of(args[0], tainted, include_filename=True)
            if lab:
                scope_node = node.child_by_field_name("scope")
                name_node = node.child_by_field_name("name")
                disp_scope = self._text(scope_node) + "::" if scope_node is not None else ""
                disp_method = self._text(name_node) if name_node is not None else method
                self._emit("RULE-SRC-005", node, lab, f"{disp_scope}{disp_method}() SQL string")
            return

        # OJS-specific file-naming methods: filename stored via setServerFileName()
        # etc. is later used by writeFile() / file_put_contents() (CVE-2025-67890).
        if method in FILE_WRITE_METHODS and args:
            lab = self._taint_of(args[0], tainted, include_filename=True)
            if lab:
                self._emit("RULE-SRC-002", node, lab, f"{method}() filename argument")

    # -- emission ----------------------------------------------------------- #
    def _emit(self, rule_id: str, node, label: str, sink_desc: str,
              cwe_override: Optional[str] = None) -> None:
        line = node.start_point[0] + 1
        key = (rule_id, line, label)
        if key in self._emitted:
            return
        self._emitted.add(key)

        rule: Optional[Rule] = self.ruleset.get(rule_id) if self.ruleset else None
        if rule is not None:
            severity = rule.severity
            cwe = cwe_override or rule.cwe
            title = rule.name
            remediation = rule.remediation
            owasp = rule.owasp
            cvss = rule.cvss_score
            cves = list(rule.cve_references)
        else:
            sev, dcwe, dtitle = _TAINT_DEFAULTS.get(rule_id, (Severity.HIGH, None, rule_id))
            severity, cwe, title = sev, cwe_override or dcwe, dtitle
            remediation, owasp, cvss, cves = "", None, None, []

        pretty_source = label.split(":", 1)[1] if label.startswith("filename:") else label
        detail = f"Tainted data from {pretty_source} reaches {sink_desc} without sanitization."
        self.findings.append(Finding(
            rule_id=rule_id,
            module="source_code",
            severity=severity,
            file_path=self.file_path,
            title=title,
            detail=detail,
            remediation=remediation,
            line=line,
            column=node.start_point[1] + 1,
            cwe=cwe,
            owasp=owasp,
            cvss_score=cvss,
            cve_references=cves,
            code_snippet=build_code_snippet(self._source_text, line),
            taint_source=pretty_source,
            confidence="high",
        ))


# --------------------------------------------------------------------------- #
# Regex pattern engine
# --------------------------------------------------------------------------- #
class RegexEngine:
    """Applies regex-type rules from the ruleset to a file's text."""

    def __init__(self, ruleset: Ruleset):
        self.rules = [r for r in ruleset.by_module("source_code") if r.pattern_type == "regex"]
        self._compiled: Dict[str, re.Pattern] = {}
        for r in self.rules:
            if r.pattern:
                try:
                    self._compiled[r.id] = re.compile(r.pattern, re.MULTILINE)
                except re.error as exc:  # pragma: no cover - validated at load
                    logger.error("Rule %s has invalid regex: %s", r.id, exc)

    def scan(self, file_path: str, ext: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = text.splitlines()
        for rule in self.rules:
            if rule.file_extensions and ext not in rule.file_extensions:
                continue
            pattern = self._compiled.get(rule.id)
            if pattern is None:
                continue
            for m in pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                line_text = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else ""
                if self._suppressed(rule, line_text):
                    continue
                findings.append(Finding(
                    rule_id=rule.id,
                    module="source_code",
                    severity=rule.severity,
                    file_path=file_path,
                    title=rule.name,
                    detail=rule.description,
                    remediation=rule.remediation,
                    line=line_no,
                    column=(m.start() - text.rfind("\n", 0, m.start())),
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    cvss_score=rule.cvss_score,
                    cve_references=list(rule.cve_references),
                    code_snippet=build_code_snippet(text, line_no),
                    confidence="medium",
                ))
        return findings

    @staticmethod
    def _suppressed(rule: Rule, line_text: str) -> bool:
        for exc in rule.false_positive_exceptions:
            pat = exc.get("pattern")
            if pat and re.search(pat, line_text):
                return True
        return False


# --------------------------------------------------------------------------- #
# Smarty template scanner
# --------------------------------------------------------------------------- #
_SMARTY_COMMENT_RE = re.compile(r"\{\*.*?\*\}", re.DOTALL)
_SMARTY_VAR_TAG_RE = re.compile(r"\{\$[^{}\n]*\}")

# Getters that always return a plain integer — cannot carry an XSS payload.
# This regex matches the Smarty tag itself, so it must start with {$.
_NUMERIC_GETTER_RE = re.compile(
    r"\{\$[\w.\[\]>-]*->get(?:"
    r"Id|Major|Minor|Revision|Build|Seq|Num|Total|Status|Count|Order|"
    r"ReviewRound(?:Id)?|StageId|SubmissionId|CurrentRound|Position"
    r")\s*\(",
    re.IGNORECASE,
)

# PHP framework-rendered HTML widgets / element IDs.  These Smarty variables are
# assigned entirely by the PHP Form Builder stack, never by user-submitted text.
# Flagging them as XSS would only create noise with zero actionable signal.
_SAFE_FRAMEWORK_VAR_RE = re.compile(
    r"\{\$(?:"
    r"FBV_(?:textInput|buttonParams|checkboxParams|type|disabled|checked|"
    r"required|selected|translate|validation|layoutInfo)\b"
    r"|pluploadControl|browseButtonId|uploadFormId|metadataFormId"
    r"|reviewRoundTabsId|inEl\b"          # inEl is a PHP-hardcoded tag name
    r")\b",
    re.IGNORECASE,
)


def scan_smarty(file_path: str, text: str, rule: Optional[Rule]) -> List[Finding]:
    """Flag ``{$var}`` output tags that lack a security-aware output modifier."""
    findings: List[Finding] = []
    # Blank out comments so offsets are preserved but their content is ignored.
    cleaned = _SMARTY_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)
    lines = text.splitlines()

    for m in _SMARTY_VAR_TAG_RE.finditer(cleaned):
        tag = m.group(0)
        lower = tag.lower()

        # Already has a recognised security-aware output filter.
        # |escape covers html/url/js/mail variants; |strip_unsafe_html strips
        # dangerous tags from rich-text stored by privileged users (intended
        # behaviour — not a vulnerability).
        if ("|escape" in lower or "|strip_unsafe_html" in lower
                or "nofilter" in lower or "|@escape" in lower):
            continue

        # Smarty built-in read-only variables.
        if tag.startswith("{$smarty."):
            continue

        # Modifiers whose output is intrinsically safe (numeric/structural).
        # NOTE: nl2br is intentionally NOT here — it converts \n to <br> but does
        # NOT sanitize HTML.  {$var|nl2br} without |strip_unsafe_html is the
        # exact CVE-2025-13469 pattern.
        if re.search(
            r"\|\s*(?:intval|count|json_encode|date_format|number_format|"
            r"string_format|lower|upper|trim|truncate|wordwrap|spacify)\b",
            lower,
        ):
            continue

        # Getters guaranteed to return a plain integer (e.g. ->getId(), ->getMajor()).
        if _NUMERIC_GETTER_RE.search(tag):
            continue

        # PHP Form Builder / framework-generated IDs/attributes — never user data.
        if _SAFE_FRAMEWORK_VAR_RE.search(tag):
            continue

        line_no = text.count("\n", 0, m.start()) + 1
        line_text = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else tag
        findings.append(Finding(
            rule_id=rule.id if rule else "RULE-SRC-001",
            module="source_code",
            severity=rule.severity if rule else Severity.HIGH,
            file_path=file_path,
            title=rule.name if rule else "Smarty output without escape filter",
            detail=(f"Smarty tag {tag} emits a value without an |escape modifier. "
                    f"{rule.description if rule else ''}").strip(),
            remediation=rule.remediation if rule else "Apply {$var|escape}.",
            line=line_no,
            column=(m.start() - text.rfind("\n", 0, m.start())),
            cwe=rule.cwe if rule else "CWE-79",
            owasp=rule.owasp if rule else "A03:2021",
            cvss_score=rule.cvss_score if rule else 6.1,
            cve_references=list(rule.cve_references) if rule else [],
            code_snippet=build_code_snippet(text, line_no),
            confidence="medium",
        ))
    return findings


# --------------------------------------------------------------------------- #
# CSRF AST handler (Handler classes with state-changing POST methods)
# --------------------------------------------------------------------------- #
_CSRF_CHECK_TOKENS = (
    "_checkcsrf", "validatecsrftoken", "requirecsrf", "getcsrftoken",
    "checkcsrf", "csrf_token", "->addpolicy", "new csrf",
)
# FormValidatorCSRF is the OJS mechanism for protecting Form subclasses.
_FORM_CSRF_TOKENS = ("formvalidatorcsrf", "checkcsrf") + _CSRF_CHECK_TOKENS

_MUTATING_NAME_RE = re.compile(
    r"(?:save|update|delete|insert|create|upload|import|edit|remove|store|add|"
    r"execute|process|submit|register|assign|publish|unpublish|restore|move)",
    re.IGNORECASE,
)


def scan_csrf(file_path: str, source: bytes, rule: Optional[Rule]) -> List[Finding]:
    """Heuristic CSRF detection covering three OJS patterns:

    1. Handler class state-changing methods without any CSRF check token.
    2. Form subclasses whose constructor lacks FormValidatorCSRF
       (CVE-2023-5626 pattern).
    3. Static authentication methods (e.g. Validation::login) that process POST
       without checkCSRF() (CVE-2025-67892 pattern).
    """
    parser = _get_parser("php")
    if parser is None:
        return []
    tree = parser.parse(source)
    findings: List[Finding] = []

    def text(node) -> str:
        return node.text.decode("utf-8", "replace")

    def find_classes(node):
        if node.type == "class_declaration":
            yield node
        for c in node.children:
            yield from find_classes(c)

    def _make_finding(cls_name, mname, line_no, col, detail):
        src_text = source.decode("utf-8", "replace")
        return Finding(
            rule_id=rule.id if rule else "RULE-SRC-003",
            module="source_code",
            severity=rule.severity if rule else Severity.MEDIUM,
            file_path=file_path,
            title=rule.name if rule else "Handler/Form POST method missing CSRF check",
            detail=detail,
            remediation=rule.remediation if rule else "Validate a CSRF token for POST handlers.",
            line=line_no,
            column=col,
            cwe=rule.cwe if rule else "CWE-352",
            owasp=rule.owasp if rule else "A01:2021",
            cvss_score=rule.cvss_score if rule else 4.3,
            cve_references=list(rule.cve_references) if rule else [],
            code_snippet=build_code_snippet(src_text, line_no),
            confidence="low",
        )

    for cls in find_classes(tree.root_node):
        name_node = cls.child_by_field_name("name")
        cls_name = text(name_node) if name_node is not None else ""
        cls_lower = cls_name.lower()
        cls_text_lower = text(cls).lower()

        # ── Pattern 1: Handler classes ──────────────────────────────────────
        if "handler" in cls_lower:
            has_csrf = any(tok in cls_text_lower for tok in _CSRF_CHECK_TOKENS)
            if not has_csrf:
                body = cls.child_by_field_name("body")
                if body is not None:
                    for member in body.named_children:
                        if member.type != "method_declaration":
                            continue
                        mname_node = member.child_by_field_name("name")
                        mname = text(mname_node) if mname_node is not None else ""
                        mtext = text(member)
                        reads_input = bool(
                            re.search(r"\$_(?:POST|REQUEST)\b", mtext)
                            or re.search(r"getUserVar\s*\(", mtext)
                        )
                        mutating = (
                            bool(_MUTATING_NAME_RE.search(mname))
                            or "->update" in mtext.lower()
                            or "->insert" in mtext.lower()
                        )
                        if reads_input and mutating:
                            findings.append(_make_finding(
                                cls_name, mname,
                                member.start_point[0] + 1,
                                member.start_point[1] + 1,
                                (f"Method {cls_name}::{mname}() consumes request input and "
                                 f"appears state-changing, but no CSRF validation was found "
                                 f"in {cls_name}. Heuristic — verify the authorize()/policy chain."),
                            ))

        # ── Pattern 2: Form subclasses missing FormValidatorCSRF ────────────
        # Targets CVE-2023-5626: PaymentTypesForm (and similar) whose constructor
        # performs state-changing saves without adding FormValidatorCSRF.
        elif "form" in cls_lower:
            has_csrf = any(tok in cls_text_lower for tok in _FORM_CSRF_TOKENS)
            if has_csrf:
                continue
            # Only flag Form classes that read input AND write/save state.
            reads_input = bool(
                re.search(r"getUserVar\s*\(", cls_text_lower)
                or re.search(r"\$_(?:POST|REQUEST)\b", cls_text_lower)
            )
            mutating_class = bool(_MUTATING_NAME_RE.search(cls_text_lower))
            if not (reads_input and mutating_class):
                continue
            body = cls.child_by_field_name("body")
            if body is None:
                continue
            for member in body.named_children:
                if member.type != "method_declaration":
                    continue
                mname_node = member.child_by_field_name("name")
                mname = text(mname_node) if mname_node is not None else ""
                if mname.lower() not in ("__construct", "initialize", "execute"):
                    continue
                mtext = text(member)
                if bool(_MUTATING_NAME_RE.search(mtext)) or "addsetting" in mtext.lower():
                    findings.append(_make_finding(
                        cls_name, mname,
                        member.start_point[0] + 1,
                        member.start_point[1] + 1,
                        (f"Form class {cls_name}::{mname}() is state-changing but "
                         f"no FormValidatorCSRF was found. Add "
                         f"$this->addCheck(new FormValidatorCSRF($this)) to the constructor."),
                    ))

        # ── Pattern 3: Authentication methods without checkCSRF ─────────────
        # Targets CVE-2025-67892: Validation::login() that processes POST but
        # never calls $request->checkCSRF() before authenticating.
        elif cls_lower in ("validation", "authvalidation", "pkpvalidation"):
            if "checkcsrf" in cls_text_lower:
                continue
            body = cls.child_by_field_name("body")
            if body is None:
                continue
            for member in body.named_children:
                if member.type != "method_declaration":
                    continue
                mname_node = member.child_by_field_name("name")
                mname = text(mname_node) if mname_node is not None else ""
                if mname.lower() not in ("login", "authenticate", "signin"):
                    continue
                mtext = text(member)
                if re.search(r"getUserVar\s*\(|\$_POST\b", mtext):
                    findings.append(_make_finding(
                        cls_name, mname,
                        member.start_point[0] + 1,
                        member.start_point[1] + 1,
                        (f"Authentication method {cls_name}::{mname}() processes POST data "
                         f"but no $request->checkCSRF() guard was found. "
                         f"Without this check login CSRF is possible (CVE-2025-67892 pattern)."),
                    ))

    return findings


# --------------------------------------------------------------------------- #
# Orchestrating scanner
# --------------------------------------------------------------------------- #
class SourceScanner:
    """Scans a directory tree of OJS source files and returns findings."""

    def __init__(self, ruleset: Ruleset, ojs_version: Optional[str] = None,
                 verbose: bool = False,
                 progress_cb: Optional[Callable[[str], None]] = None,
                 skip_dirs: Optional[Sequence[str]] = None):
        self.ruleset = ruleset
        self.ojs_version = ojs_version
        self.verbose = verbose
        self.progress_cb = progress_cb
        self.skip_dirs = set(skip_dirs) if skip_dirs else set(DEFAULT_SKIP_DIRS)
        self.regex_engine = RegexEngine(ruleset)
        self._smarty_rule = ruleset.get("RULE-SRC-001")
        self._csrf_rule = ruleset.get("RULE-SRC-003")
        self.files_scanned = 0

        # Build set of rule IDs that have reporting enabled.
        # Rules with reporting: false are internal diagnostics only.
        self._non_reporting_rules: set = set()
        for rule in ruleset:
            if rule.params.get("reporting") is False:
                self._non_reporting_rules.add(rule.id)

        # CVE scanner for structured, CVE-specific detection.
        from .cve_scanner import CVEScanner
        self._cve_scanner = CVEScanner(ruleset, ojs_version=ojs_version)

    def _progress(self, msg: str) -> None:
        if self.progress_cb:
            self.progress_cb(msg)

    def iter_files(self, root: Path):
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            if any(part in self.skip_dirs for part in path.parts):
                continue
            if path.suffix.lower() not in SCANNED_EXTENSIONS:
                continue
            yield path

    def scan(self, root_path) -> List[Finding]:
        root = Path(root_path)
        findings: List[Finding] = []
        for path in self.iter_files(root):
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    logger.debug("Skipping large file %s", path)
                    continue
                raw = path.read_bytes()
            except OSError as exc:  # pragma: no cover
                logger.warning("Cannot read %s: %s", path, exc)
                continue
            if b"\x00" in raw[:4096]:  # binary heuristic
                continue
            rel = str(path.relative_to(root)) if _is_relative(path, root) else str(path)
            self.files_scanned += 1
            if self.verbose:
                self._progress(f"source: {rel}")
            findings.extend(self.scan_file(path, rel, raw))
        logger.info("Source scan complete: %d files, %d findings", self.files_scanned, len(findings))
        return findings

    def scan_file(self, path: Path, rel: str, raw: bytes) -> List[Finding]:
        ext = path.suffix.lower()
        text = raw.decode("utf-8", "replace")
        findings: List[Finding] = []

        if ext in PHP_EXTENSIONS:
            if TREE_SITTER_AVAILABLE:
                findings.extend(PHPTaintAnalyzer(raw, rel, self.ruleset).analyze())
                if self._csrf_rule is None or self._csrf_rule.pattern_type == "ast":
                    findings.extend(scan_csrf(rel, raw, self._csrf_rule))
            findings.extend(self.regex_engine.scan(rel, ext, text))
            # CVE-specific scanning for PHP files.
            findings.extend(self._cve_scanner.scan_file(path, rel, raw, text))

        elif ext in SMARTY_EXTENSIONS:
            findings.extend(scan_smarty(rel, text, self._smarty_rule))
            findings.extend(self.regex_engine.scan(rel, ext, text))
            # CVE-specific scanning for Smarty template files.
            findings.extend(self._cve_scanner.scan_file(path, rel, raw, text))

        elif ext in JS_EXTENSIONS:
            findings.extend(self.regex_engine.scan(rel, ext, text))

        # Filter out findings from non-reporting (internal diagnostic) rules.
        findings = [
            f for f in findings
            if f.rule_id not in self._non_reporting_rules
        ]

        return findings


def _is_relative(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
