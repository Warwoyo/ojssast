# ojs-sast

**An OJS-aware Extended Static Application Security Testing (SAST) CLI for
[Open Journal Systems](https://pkp.sfu.ca/software/ojs/) deployments.**

`ojs-sast` understands OJS-specific code patterns (PKP request abstractions,
Smarty templates, NativeXML import filenames), the `config.inc.php` structure,
and the upload-directory layout. It combines **data-flow taint analysis**,
**ruleset-driven pattern matching**, **configuration hardening checks**, and a
**layered upload-directory scanner** into a single tool, and emits JSON, HTML
and SARIF reports.

> Built as a research tool for a thesis on OJS application security.

---

## Features

| Module | Technique | Highlights |
| ------ | --------- | ---------- |
| **Source code** | tree-sitter AST taint analysis + regex + Smarty/JS handlers | OJS-aware sources (`getUserVar`, superglobals), sanitizers (`PKPString::htmlspecialchars`, casts), and sinks (echo, `DB::raw`, `eval`, file writes, `unserialize`). Smarty `{$var}` without `\|escape`. |
| **Config** | INI-style `config.inc.php` parser + Nginx regexes | Salt/secret strength, breached DB passwords (SecLists top-500 embedded), `allowed_hosts`, SSL/cookie hardening, `files_dir` web-root placement, Nginx PHP-execution & header checks. Secure-by-default version awareness. |
| **Upload directory** | 5 layered checks + `python-magic` | Dangerous extensions, double extensions, MIME/extension mismatch, PHP webshell signatures, malicious-PDF markers. |

All findings are normalized to a single schema, de-duplicated by
`(rule_id, file, line)`, severity-calibrated to CWE, and tagged with CWE / OWASP /
CVSS / CVE metadata.

---

## Installation

Requires **Python 3.10+** and the system **libmagic** library (for
`python-magic`).

```bash
# Debian/Ubuntu: system dependency for MIME detection
sudo apt-get install -y libmagic1

# Install the tool (editable for development)
pip install -e .
```

Python dependencies (installed automatically): `click`, `tree-sitter==0.21.3`,
`tree-sitter-languages` (bundles the PHP & JS grammars), `python-magic`,
`PyYAML`, `Jinja2`, `rich`.

> If `tree-sitter` is unavailable the source scanner degrades gracefully to
> regex-only rules; if `libmagic` is missing the MIME-dependent upload layers
> are skipped. The tool still runs.

---

## Usage

```bash
ojs-sast scan <ojs_path> [OPTIONS]
ojs-sast list-rules [--module MODULE]
ojs-sast version
```

### `scan` options

| Option | Description |
| ------ | ----------- |
| `--output-dir PATH` | Where to write reports (default `./ojs_sast_report/`). |
| `--format TEXT` | Report formats: `json,html,sarif` (default `json,html`). JSON is always written. |
| `--severity LEVEL` | Minimum severity to report: `CRITICAL/HIGH/MEDIUM/LOW/INFO`. |
| `--category TEXT` | Limit to `source_code,config,upload_directory` (comma-separated). |
| `--upload-dir PATH` | Override the upload directory (skips `config.inc.php` lookup). |
| `--skip-source` / `--skip-config` / `--skip-upload` | Skip a module. |
| `--nginx-config PATH` | Path to an Nginx config file or directory. |
| `--ruleset-dir PATH` | Use a custom ruleset directory. |
| `--ojs-version TEXT` | Force the OJS version (e.g. `3.3.0-13`) if auto-detect fails. |
| `--verbose` | Show detailed progress. |

### Examples

```bash
# Full scan with all three report formats
ojs-sast scan /var/www/ojs --format json,html,sarif

# Only critical/high issues, source + config only
ojs-sast scan /var/www/ojs --severity HIGH --category source_code,config

# Scan an exported upload directory without an OJS tree
ojs-sast scan /var/www/ojs --skip-source --skip-config \
  --upload-dir /backups/ojs-files

# Include the web-server config
ojs-sast scan /var/www/ojs --nginx-config /etc/nginx/sites-enabled/ojs.conf

# List the active ruleset
ojs-sast list-rules --module source_code
```

---

## How it works (orchestration)

1. **OJS detection** — verifies `config.inc.php` plus at least one core marker
   (`lib/pkp/`, `classes/core/(PKP)Application.php`) and reads the version from
   `dbscripts/xml/version.xml`.
2. **Ruleset loading** — merges every `*_rules.yaml` in the ruleset directory,
   validates the schema, and rejects duplicate ids.
3. **Module execution** (sequential) — source → config → upload.
4. **De-duplication** — merges findings sharing `(rule_id, file, line)`, keeping
   the highest severity / confidence and unioning CVE references.
5. **Report generation** — JSON always; HTML and SARIF on request.

### Source taint analysis

A forward, intra-procedural data-flow pass over the PHP AST:

* **Sources**: `$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES/$_SERVER`,
  `getUserVar()`, `getQueryString()`, `getQueryArray()`, `getRequestedArgs()`,
  and (for path findings) `getFilename()/getName()`.
* **Sanitizers** (clear taint): `PKPString::htmlspecialchars()`,
  `htmlspecialchars()`, `htmlentities()`, `intval()/floatval()`, `(int)/(float)`
  casts, `strip_tags()`, `PKPString::regexp_replace()`, and SQL bindings.
* **Sinks**: echo/print/`printf` (XSS), `DB::raw`/`Capsule::raw`/`->statement`
  (SQLi), `file_put_contents`/`move_uploaded_file`/`copy`/`rename` (path
  traversal), `eval`/`system`/`exec`/`shell_exec`/… (code/command execution),
  `unserialize` (deserialization).

Scopes are isolated per function/method, concatenation propagates taint, and
SQL **binding** arguments are deliberately ignored to avoid false positives.

---

## Rules & CVE mapping

Rules live in `ojs_sast/ruleset/*.yaml`. Run `ojs-sast list-rules` for the full
set (33 rules across the three modules).

| Rule | Issue | CWE | CVE mapping (thesis ground truth) |
| ---- | ----- | --- | --- |
| RULE-SRC-001 | Smarty output without `\|escape` | CWE-79 | CVE-2023-5897, CVE-2025-67885/67888 |
| RULE-SRC-002 | NativeXML/tainted filename in file op | CWE-22 | CVE-2023-5897, CVE-2025-67886 |
| RULE-SRC-003 | Handler POST method missing CSRF check | CWE-352 | (mapped in ground-truth dataset) |
| RULE-SRC-004 | LESS compiler injection | CWE-94 | CVE-2025-67887 |
| RULE-SRC-005 | SQLi via `DB::raw`/`Capsule::raw` | CWE-89 | CVE-2025-67889 |
| RULE-SRC-006 | `unserialize()` on user data | CWE-502 | — |
| RULE-SRC-007/008 | Tainted XSS / code-exec sinks | CWE-79 / 94 / 78 | — |
| OJS-CFG-SEC-003 | Insecure `allowed_hosts` | CWE-644 | CVE-2022-24181 |
| RULE-UPLOAD-001…005 | Upload threats (5 layers) | CWE-434 / 94 | — |

### Severity calibration

CWE-89 (SQLi) → **CRITICAL** · CWE-502 (deserialization) → **CRITICAL** ·
CWE-94 (code injection) → **CRITICAL** · CWE-79 (XSS) → **HIGH** ·
CWE-22 (path traversal) → **HIGH** · CWE-352 (CSRF) → **MEDIUM**. Uploads: PHP
executable → **CRITICAL**, other executables → **HIGH**.

### Adding a rule

```yaml
rules:
  - id: RULE-SRC-099
    name: "My custom check"
    module: source_code
    cwe: CWE-79
    severity: HIGH
    pattern_type: regex          # regex | smarty | ast | taint | builtin
    file_extensions: [".php"]
    pattern: 'dangerous_call\s*\('
    description: "..."
    remediation: "..."
    false_positive_exceptions:
      - pattern: '@safe'
        description: "Annotated as reviewed."
```

Point the tool at it with `--ruleset-dir /path/to/rules`.

---

## False-positive handling & OJS version awareness

* Smarty tags using `|escape` (any context) are never flagged.
* PHP values passing through a recognized sanitizer or numeric cast clear taint.
* Where a directive is **absent but secure-by-default** in newer OJS (e.g.
  `session_cookie_httponly` / `session_samesite` from OJS 3.3.0), the finding is
  downgraded to **INFO** and notes the version that changed the default.
* SQL parameter bindings are not treated as injection.

---

## Reports

* **`findings.json`** — `scan_metadata`, `summary` (counts by severity/module),
  and the full `findings` array.
* **`report.html`** — self-contained dashboard: severity badges, a
  sortable/filterable findings table, and expandable per-finding detail with
  code snippets and remediation.
* **`findings.sarif`** — SARIF 2.1.0 with rule metadata and `security-severity`,
  ready to upload to GitHub Advanced Security.

---

## Project layout

```
ojs_sast/
├── cli.py                 # Click CLI (scan / list-rules / version)
├── orchestrator.py        # detection, scheduling, dedup, reporting
├── models.py              # Severity, Rule, RuleMatch, Finding, ScanResult
├── detectors/
│   ├── source_scanner.py  # PHP taint + regex + Smarty + JS + CSRF
│   ├── config_scanner.py  # config.inc.php + Nginx
│   └── upload_scanner.py  # 5-layer upload scanner
├── ruleset/
│   ├── loader.py
│   ├── source_rules.yaml
│   ├── config_rules.yaml  # includes embedded SecLists top-500 passwords
│   └── upload_rules.yaml  # includes webshell signatures
└── reporters/             # json / html / sarif
```

---

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The suite covers taint analysis, pattern matching, the five upload layers,
config (insecure vs. hardened), report generation, and an end-to-end
orchestrator run against a mock OJS tree.

---

## Limitations

* Taint analysis is intra-procedural (no cross-file/cross-function flow).
* JavaScript scanning is pattern-based only (no JS taint).
* The CSRF check is a heuristic; verify against the handler's `authorize()`
  policy chain.
* Webshell/PDF signatures are heuristic and read only the first 64 KB / 1 MB.

## License

MIT.
