# ojs-sast — OJS SAST Core & Remote Service

**OJS-aware Extended Static Application Security Testing core and remote SAST service for [Open Journal Systems](https://pkp.sfu.ca/software/ojs/) deployments.**

This repository contains the SAST brain — detection engine, ruleset, API service, and reporter. Install it **only on the SAST service node (VPS 1)**.

Do not install this repository on the OJS target node if the goal is to keep the SAST core, ruleset, and detectors off the target machine.

For the OJS target node, install:
```
Warwoyo/ojs-sast-agent
```

---

## Architecture

```
VPS 2 (OJS target)          VPS 1 (SAST service)
┌──────────────────┐         ┌──────────────────────────┐
│ ojs-sast-agent   │         │ ojs-sast (this repo)     │
│                  │         │                          │
│  snapshot        ├─source.tar.gz + meta.json─►       │
│  config collect  │         │  validate API key        │
│  upload manifest │         │  validate IP allowlist   │
│                  │         │  validate SHA256         │
└──────────────────┘         │  safe extract            │
                             │  Orchestrator.run_bundle │
                             │  ├── CVEScanner          │
                             │  ├── ConfigScanner       │
                             │  └── UploadManifest      │
                             │       Scanner            │
                             │  deduplicate + report    │
                             └──────────────────────────┘
```

---

## Features

| Module | Technique | Highlights |
| ------ | --------- | ---------- |
| **Source code** | tree-sitter AST taint analysis + regex + Smarty/JS | OJS-aware sources, sanitizers, and sinks. |
| **Config** | INI-style `config.inc.php` parser + Nginx regexes | Salt/secret strength, breached DB passwords, `allowed_hosts`, SSL/cookie hardening, `files_dir` web-root placement. |
| **Upload directory** | 5 layered checks (head_hex based) | Dangerous extensions, double extensions, MIME/extension mismatch, PHP webshell signatures, malicious-PDF markers — computed from raw `head_hex` bytes. |

---

## Installation on VPS 1 (SAST service node)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git libmagic1

git clone https://github.com/Warwoyo/ojssast.git
cd ojssast

python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[service]'
```

---

## Creating `service.yml`

```bash
# Generate an API key (share the first line with the agent on VPS 2)
ojs-sast-service gen-key
```

Create `/etc/ojs-sast/service.yml`:

```yaml
host: "0.0.0.0"
port: 8000
data_dir: "/var/lib/ojs-sast"

api_keys:
  - agent_id: "ojs-vps-2"
    key_hash: "sha256:<hash-from-gen-key>"

ip_allowlist:
  - "<IP_VPS2>/32"

max_upload_bytes: 209715200        # 200 MB
max_files_per_archive: 50000
max_total_extracted_bytes: 524288000  # 500 MB
max_file_bytes: 52428800           # 50 MB
max_active_scans_per_key: 1

audit_log_path: "/var/log/ojs-sast/audit.jsonl"
```

---

## Running the service

```bash
ojs-sast-service start --config /etc/ojs-sast/service.yml
```

The service listens on `host:port` and exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check (no auth required) |
| `/scan` | POST | Submit a scan bundle (multipart: `source_code` + `meta`) |
| `/status/{scan_id}` | GET | Poll scan status |
| `/result/{scan_id}` | GET | Fetch full result JSON |
| `/report/{scan_id}/{fmt}` | GET | Download report (json/html/sarif) |

---

## Receiving scans from the agent

The agent on VPS 2 sends:

```
POST /scan
X-API-Key: <raw-api-key>

source_code = source.tar.gz      # PHP source snapshot
meta        = meta.json           # provenance + config payload + upload manifest
```

`meta.json` schema:

```json
{
  "source_archive": {"sha256": "...", "bytes": 123, "top_level_dir": "source"},
  "config_files": {
    "config.inc.php": "...",
    "nginx:/etc/nginx/sites-enabled/ojs.conf": "..."
  },
  "upload_manifest": {
    "total_files": 10,
    "entries": [
      {
        "path": "journals/1/articles/55/shell.php.jpg",
        "filename": "shell.php.jpg",
        "extension": ".jpg",
        "size_bytes": 1204,
        "detected_mime": "application/x-php",
        "head_hex": "3c3f706870...",
        "null_byte_in_name": false,
        "is_hidden": false
      }
    ]
  },
  "scan_options": {
    "categories": ["source_code", "config", "upload_directory"],
    "min_severity": "MEDIUM",
    "formats": ["json", "html", "sarif"]
  }
}
```

**Key routing for `config_files`:**
- `"config.inc.php"` → OJS INI checks
- `"nginx:*"` keys → Nginx config checks
- `"apache:*"` and other keys → ignored

---

## Proof: `ojs-agent` is not exposed

This repository contains no `ojs-agent` command. Verify with:

```bash
pip install -e '.[service]'
ojs-agent --help   # → command not found
ojs-sast-service --help   # → available
ojs-sast --help           # → available (local CLI)
```

---

## Local CLI (optional)

The `ojs-sast` command can scan a local OJS install directly:

```bash
ojs-sast scan /var/www/ojs --format json,html,sarif
ojs-sast scan-bundle --source source.tar.gz --meta meta.json
ojs-sast list-rules --module source_code
```

> **Note:** The `ojs_sast/agent/` package has been removed from this repository.
> The thin agent now lives in
> [`Warwoyo/ojs-sast-agent`](https://github.com/Warwoyo/ojs-sast-agent).

---

## Testing

```bash
pip install -e ".[dev]"            # core suite (no service)
pip install -e ".[test-service]"   # also runs the FastAPI service tests
pytest -q
```

---

## Project layout

```
ojs_sast/
├── cli.py                 # ojs-sast local CLI
├── orchestrator.py        # run_local + run_bundle, dedup, metadata
├── models/                # Severity, Rule, Finding, ScanResult, ScanBundle
├── detectors/
│   ├── cve_scanner.py     # PHP taint + regex + Smarty
│   ├── config_scanner.py  # config.inc.php + Nginx (scan_payload routes nginx: only)
│   ├── upload_scanner.py  # 5-layer local upload scanner
│   └── upload_manifest_scanner.py  # same 5 layers from head_hex bytes
├── service/               # FastAPI app, auth, storage, queue, worker, safe extract
├── ruleset/               # YAML rules + loader
└── reporters/             # json / html / sarif
```

---

## License

MIT.
