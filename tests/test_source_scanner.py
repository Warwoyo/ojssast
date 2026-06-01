"""Tests for the source code scanner (taint, regex, Smarty, JS, CSRF)."""

from pathlib import Path

import pytest

from ojs_sast.detectors.source_scanner import (TREE_SITTER_AVAILABLE,
                                               PHPTaintAnalyzer, RegexEngine,
                                               SourceScanner, scan_csrf,
                                               scan_smarty)

from .conftest import FIXTURES

requires_ts = pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not available")


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# ----------------------------- taint analysis ----------------------------- #
@requires_ts
def test_taint_detects_xss_echo(ruleset):
    code = b"<?php $x = $_GET['q']; echo $x;"
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-007" in _rule_ids(findings)
    assert any(f.cwe == "CWE-79" for f in findings)


@requires_ts
def test_taint_sanitizer_clears(ruleset):
    code = b"<?php echo PKPString::htmlspecialchars($_GET['q']); echo intval($_GET['n']); echo (int)$_POST['m'];"
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert findings == []


@requires_ts
def test_taint_sqli_via_concat(ruleset):
    code = b'<?php $t = $_GET["t"]; $sql = "SELECT * FROM s WHERE x=" . $t; DB::raw($sql);'
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-005" in _rule_ids(findings)
    assert any(f.severity.value == "CRITICAL" for f in findings)


@requires_ts
def test_taint_sql_bindings_not_flagged(ruleset):
    # Value passed as a binding (2nd arg), not concatenated into the SQL string.
    code = b'<?php DB::select("SELECT * FROM s WHERE id = ?", [$_GET["id"]]);'
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-005" not in _rule_ids(findings)


@requires_ts
def test_taint_code_exec_and_command(ruleset):
    code = b"<?php eval($_GET['c']); system($_POST['cmd']);"
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-008" in _rule_ids(findings)
    cwes = {f.cwe for f in findings if f.rule_id == "RULE-SRC-008"}
    assert "CWE-95" in cwes and "CWE-78" in cwes


@requires_ts
def test_taint_unserialize(ruleset):
    code = b"<?php $d = $_COOKIE['s']; $o = unserialize($d);"
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-006" in _rule_ids(findings)


@requires_ts
def test_taint_file_write_with_filename(ruleset):
    code = b'<?php $n = $file->getFilename(); file_put_contents($n, "data");'
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-002" in _rule_ids(findings)


@requires_ts
def test_taint_scope_isolation(ruleset):
    # $x tainted in one function must not leak into another.
    code = b"<?php function a(){ $x = $_GET['v']; } function b(){ echo $x; }"
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-007" not in _rule_ids(findings)


@requires_ts
def test_taint_foreach_propagation(ruleset):
    code = b"<?php foreach ($_GET as $v) { echo $v; }"
    findings = PHPTaintAnalyzer(code, "t.php", ruleset).analyze()
    assert "RULE-SRC-007" in _rule_ids(findings)


# ----------------------------- regex engine ------------------------------- #
def test_regex_sqli_inline(ruleset):
    eng = RegexEngine(ruleset)
    findings = eng.scan("t.php", ".php", 'DB::raw("SELECT " . $id);')
    assert "RULE-SRC-005" in _rule_ids(findings)


def test_regex_js_rules(ruleset):
    eng = RegexEngine(ruleset)
    js = "el.innerHTML = user;\ndocument.write(x);\neval(code);\nel.innerHTML = \"\";\n"
    ids = _rule_ids(eng.scan("t.js", ".js", js))
    assert {"RULE-SRC-010", "RULE-SRC-011", "RULE-SRC-012"} <= ids


def test_regex_js_static_not_flagged(ruleset):
    eng = RegexEngine(ruleset)
    findings = eng.scan("t.js", ".js", 'el.innerHTML = "hello world";')
    assert "RULE-SRC-010" not in _rule_ids(findings)


# ----------------------------- Smarty ------------------------------------- #
def test_smarty_unescaped_flagged(ruleset):
    text = (FIXTURES / "templates" / "unescaped.tpl").read_text()
    findings = scan_smarty("unescaped.tpl", text, ruleset.get("RULE-SRC-001"))
    assert len(findings) == 2  # the two unescaped tags only
    assert all(f.rule_id == "RULE-SRC-001" for f in findings)


def test_smarty_escaped_not_flagged(ruleset):
    findings = scan_smarty("x.tpl", '<p>{$name|escape}</p>{$u|escape:"url"}', ruleset.get("RULE-SRC-001"))
    assert findings == []


# ----------------------------- CSRF --------------------------------------- #
@requires_ts
def test_csrf_handler_flagged(ruleset):
    code = b"<?php class FooHandler extends Handler { function saveFoo(){ $x = $_POST['x']; } }"
    findings = scan_csrf("FooHandler.php", code, ruleset.get("RULE-SRC-003"))
    assert "RULE-SRC-003" in _rule_ids(findings)


@requires_ts
def test_csrf_with_check_not_flagged(ruleset):
    code = (b"<?php class FooHandler extends Handler { function saveFoo(){ "
            b"$this->validateCSRFToken(); $x = $_POST['x']; } }")
    findings = scan_csrf("FooHandler.php", code, ruleset.get("RULE-SRC-003"))
    assert findings == []


# ----------------------------- orchestration ------------------------------ #
def test_source_scanner_on_fixtures(ruleset):
    scanner = SourceScanner(ruleset)
    findings = scanner.scan(FIXTURES / "vulnerable_php")
    ids = _rule_ids(findings)
    # SQLi (regex always; taint when available) and JS rules are deterministic.
    assert "RULE-SRC-005" in ids
    assert {"RULE-SRC-010", "RULE-SRC-011", "RULE-SRC-012"} <= ids
    if TREE_SITTER_AVAILABLE:
        assert "RULE-SRC-007" in ids  # XSS via taint


def test_scanner_skips_large_and_binary(ruleset, tmp_path):
    big = tmp_path / "big.php"
    big.write_text("<?php\n" + "// pad\n" * 10)
    # craft a > 10MB file
    with big.open("ab") as fh:
        fh.write(b"x" * (10 * 1024 * 1024 + 10))
    binf = tmp_path / "b.php"
    binf.write_bytes(b"<?php\x00\x00 echo $_GET['x'];")
    scanner = SourceScanner(ruleset)
    findings = scanner.scan(tmp_path)
    assert findings == []  # both skipped
