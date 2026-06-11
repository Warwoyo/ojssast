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

The service listens on `host:port` and exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check (no auth required) |
| `/scan` | POST | Submit a scan bundle (multipart: `source_code` + `meta`) |
| `/status/{scan_id}` | GET | Poll scan status |
| `/result/{scan_id}` | GET | Fetch full result JSON |
| `/report/{scan_id}/{fmt}` | GET | Download report (json/html/sarif) |

### Development / all-in-one (uvicorn)

```bash
ojs-sast-service start --config /etc/ojs-sast/service.yml
```

One process: FastAPI under uvicorn with the scan-worker pool embedded. Simplest
to run, ideal for local testing — but a single process can't use all cores and a
restart loses in-flight work.

### Production (gunicorn + worker pool)

For a VPS, run the API under **gunicorn** and the scans in **separate worker
processes**, both managed by systemd. The API only accepts uploads and enqueues
jobs; the workers drain a shared, persistent **SQLite-backed queue**, so the two
are decoupled and jobs survive restarts.

```bash
# API (process manager) — reads service.yml via OJS_SAST_CONFIG
OJS_SAST_CONFIG=/etc/ojs-sast/service.yml \
  gunicorn -c deploy/gunicorn.conf.py ojs_sast.service.asgi:app

# One or more scan workers (run several for parallelism)
ojs-sast-service worker --config /etc/ojs-sast/service.yml
```

```
Agent ─► [Nginx] ─► gunicorn + FastAPI ─► SQLite persistent queue ─► worker pool ─► result/reports
```

Ready-to-use **systemd units**, a tuned **`gunicorn.conf.py`**, an Nginx example,
and sizing guidance for a 4 vCPU / 16 GB VPS (4 API workers + 3 scan workers)
live in [`deploy/`](deploy/README.md). Optional worker/queue knobs in
`service.yml` (defaults shown):

```yaml
worker_concurrency: 1          # threads per worker process (scale processes, not threads)
poll_interval_seconds: 0.5     # how often an idle worker checks the queue
heartbeat_interval_seconds: 15 # a running job refreshes its heartbeat this often
heartbeat_timeout_seconds: 60  # ...and is "orphaned" (worker died) after this long
reclaim_interval_seconds: 30   # how often workers scan for orphaned jobs
max_attempts: 2                # (re)attempts before recovery gives up and errors a job
```

**Crash recovery:** running jobs heartbeat periodically; if a worker dies, another
worker requeues the job (while its source archive is present and `attempts <
max_attempts`) or marks it `error`. The per-key `max_active_scans_per_key` limit
is enforced atomically, so concurrent requests across gunicorn workers can't
exceed it.

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
├── service/               # remote SAST service
│   ├── app.py             # FastAPI app factory (create_app, run_worker toggle)
│   ├── asgi.py            # gunicorn ASGI entrypoint (reads OJS_SAST_CONFIG)
│   ├── cli.py             # start (dev) + worker (production pool) + gen-key
│   ├── storage.py         # SQLite + filesystem; doubles as the persistent queue
│   ├── queue.py           # SQLite-backed shared queue (atomic claim)
│   ├── worker.py          # scan-worker pool: claim, heartbeat, crash recovery
│   ├── auth.py            # API-key hashing + IP allowlist + audit log
│   └── extract.py         # safe archive extraction
├── ruleset/               # YAML rules + loader
└── reporters/             # json / html / sarif

deploy/                    # production deployment (gunicorn + systemd)
├── gunicorn.conf.py       # tuned for the reference 4 vCPU / 16 GB VPS
├── systemd/               # ojs-sast-api.service + ojs-sast-worker@.service
├── nginx-ojs-sast.conf.example
└── README.md              # step-by-step VPS deployment + sizing
```

---

## License

MIT.
