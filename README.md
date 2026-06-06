# ojs-sast — SAST Service & Core

**An OJS-aware Extended Static Application Security Testing (SAST) service and
core library for
[Open Journal Systems](https://pkp.sfu.ca/software/ojs/) deployments.**

> **This repository is the OJS-SAST service/core repository.**
> Install this **only** on the SAST service node (VPS 1).
>
> **Do not install this repository on the OJS target node** if the goal is to
> keep the SAST core, ruleset, and detectors off the target machine.
>
> For the OJS node (VPS 2), install the thin agent:
> [`Warwoyo/ojs-sast-agent`](https://github.com/Warwoyo/ojs-sast-agent)

---

## Architecture

```text
VPS 1 — SAST Service Node
  Repository: Warwoyo/ojssast (this repo)
  Receives bundles from the agent, validates API keys,
  safely extracts source.tar.gz, runs Orchestrator.run_bundle(),
  matches ruleset, runs detectors, generates reports.

VPS 2 — OJS Target Node
  Repository: Warwoyo/ojs-sast-agent (separate repo)
  Thin collector: builds source.tar.gz + meta.json,
  submits to the service, polls for results, downloads reports.
  Does NOT contain SAST core, ruleset, or detector code.
```

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

# Install the core tool
pip install -e .

# Install with the SAST service (FastAPI)
pip install -e '.[service]'
```

Python dependencies (installed automatically): `click`, `tree-sitter==0.21.3`,
`tree-sitter-languages` (bundles the PHP & JS grammars), `python-magic`,
`PyYAML`, `Jinja2`, `rich`.

> If `tree-sitter` is unavailable the source scanner degrades gracefully to
> regex-only rules; if `libmagic` is missing the MIME-dependent upload layers
> are skipped. The tool still runs.

---

## Deployment

### VPS 1 — SAST Service Node

```bash
git clone -b SAST-as-a-Service https://github.com/Warwoyo/ojssast.git
cd ojssast
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[service]'

# Generate an API key for the agent
ojs-sast-service gen-key

# Start the service
ojs-sast-service start --config /etc/ojs-sast/service.yml
```

### VPS 2 — OJS Target Node

```bash
git clone https://github.com/Warwoyo/ojs-sast-agent.git
cd ojs-sast-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[agent]'

# Submit a scan
ojs-agent scan --ojs-path /var/www/ojs \
  --sast-url https://vps1:8000 \
  --api-key-file /etc/ojs-agent/key.txt
```

> **VPS 2 never clones the `Warwoyo/ojssast` repository.**

---

## Usage (Local CLI)

The local CLI is still available for direct scanning on a machine where the
core is installed:

```bash
ojs-sast scan <ojs_path> [OPTIONS]
ojs-sast scan-bundle --source source.tar.gz --meta meta.json
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

## Service API

The SAST service exposes the following endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (no auth) |
| `/scan` | POST | Submit a scan bundle (multipart: `source_code` + `meta`) |
| `/status/{scan_id}` | GET | Check scan status |
| `/result/{scan_id}` | GET | Get full scan result JSON |
| `/report/{scan_id}/{fmt}` | GET | Download report (json/html/sarif) |

All endpoints except `/health` require `X-API-Key` header.

### Bundle contract (`meta.json`)

```json
{
  "schema_version": 1,
  "agent_version": "1.0.0",
  "agent_id": "ojs-vps-2",
  "bundle_id": "uuid",
  "created_at": "2026-06-06T00:00:00Z",
  "ojs_version": "3.3.0-22",
  "ojs_detected": true,
  "detection_markers": ["config.inc.php", "lib/pkp"],
  "source_label": "ojs-prod",
  "scan_options": {
    "categories": ["source_code", "config", "upload_directory"],
    "min_severity": "MEDIUM",
    "formats": ["json", "html", "sarif"]
  },
  "source_archive": {
    "filename": "source.tar.gz",
    "sha256": "...",
    "bytes": 123456,
    "top_level_dir": "source"
  },
  "config_files": {
    "config.inc.php": "...",
    "nginx:/etc/nginx/sites-enabled/ojs.conf": "..."
  },
  "upload_manifest": {
    "entries": [
      {
        "path": "journals/1/articles/55/shell.php.jpg",
        "filename": "shell.php.jpg",
        "extension": ".jpg",
        "size_bytes": 1204,
        "head_hex": "3c3f706870206576616c28...",
        "detected_mime": "application/x-php",
        "null_byte_in_name": false,
        "is_hidden": false
      }
    ]
  }
}
```

### Security

- API key validation (SHA-256 hashed, constant-time comparison)
- IP allowlist
- Upload size limits
- Safe tar extraction (path traversal, symlink/hardlink, device rejection)
- Max files/bytes per archive
- Limited active scans per key
- Audit log (never logs raw keys, config text, or passwords)
- Sandbox cleanup after scan

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

---

## Project layout

```
ojs_sast/
├── cli.py                 # Click CLI (scan / scan-bundle / list-rules / version)
├── orchestrator.py        # detection, scheduling, dedup, reporting; run_local + run_bundle
├── models/                # Severity, Rule, RuleMatch, Finding, ScanResult, ScanBundle
├── detectors/
│   ├── cve_scanner.py     # PHP taint + regex + Smarty + JS + CSRF
│   ├── config_scanner.py  # config.inc.php + Nginx (scan / scan_payload / scan_texts)
│   ├── upload_scanner.py  # 5-layer upload scanner (local files)
│   └── upload_manifest_scanner.py  # same 5 layers over raw-evidence manifest entries
├── service/               # SAST service: FastAPI app, auth, storage, queue, worker, sandbox
├── helpers/               # path/PHP/Smarty/snippet/version/rule-applicability utilities
├── ruleset/
│   ├── loader.py
│   ├── cve_rules.yaml
│   ├── config_rules.yaml  # includes embedded SecLists top-500 passwords
│   └── upload_rules.yaml  # includes webshell signatures
├── reporters/             # json / html / sarif
└── utils/                 # logger
```

> **Note:** The `ojs_sast/agent/` package has been removed from this repository.
> The thin agent now lives in
> [`Warwoyo/ojs-sast-agent`](https://github.com/Warwoyo/ojs-sast-agent).

---

## Testing

```bash
pip install -e ".[dev]"            # core suite
pip install -e ".[test-service]"   # also runs the FastAPI service tests
pytest -q
```

The suite covers taint analysis, pattern matching, the five upload layers,
config (insecure vs. hardened), report generation, an end-to-end orchestrator
run against a mock OJS tree, plus the service path: bundle round-trip, worker
`scan_options` enforcement, `scan_payload`, the upload-manifest scanner with
service-side webshell/PDF detection from `head_hex`, sandboxed archive
extraction, and FastAPI service integration tests. The service tests skip
automatically when the `service` extra is not installed.

---

## Limitations

* Taint analysis is intra-procedural (no cross-file/cross-function flow).
* JavaScript scanning is pattern-based only (no JS taint).
* The CSRF check is a heuristic; verify against the handler's `authorize()`
  policy chain.
* Webshell/PDF signatures are heuristic and read only the first 512 bytes of
  `head_hex` (configurable in the manifest schema).

## License

MIT.
