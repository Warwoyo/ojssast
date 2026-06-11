# Production deployment (VPS 1 — SAST service node)

This directory holds everything to run ojs-sast in production with **gunicorn**
(API process manager) + a **separate scan-worker pool**, both under systemd.

```
Agent (VPS 2)
   │  POST /scan  (X-API-Key)
   ▼
[ Nginx (optional, TLS) ]
   ▼
gunicorn  ──►  FastAPI (API only)  ──►  enqueue ─┐
 (ojs-sast-api.service)                          │
                                                 ▼
                                   SQLite-backed persistent queue
                                      (<data_dir>/ojs_sast.db)
                                                 ▲
                                                 │  claim (atomic)
ojs-sast-worker@1..N  ──►  SAST scan  ──►  result.json + reports
 (ojs-sast-worker@.service)
```

The API and the workers are **decoupled**: a submission is just a `queued` row
in SQLite, and any worker process can pick it up. The queue is therefore shared
and survives restarts (unlike the old in-process `queue.Queue`).

---

## Why this layout (vs. plain `ojs-sast-service start`)

`ojs-sast-service start` runs uvicorn in **one** process with the worker
embedded — great for development, but a single process can't use all cores and
a restart loses in-flight work. In production we instead run:

| Unit | What | Scale |
|------|------|-------|
| `ojs-sast-api.service` | gunicorn + UvicornWorker, FastAPI **API only** | `GUNICORN_WORKERS` (≈ vCPU) |
| `ojs-sast-worker@N.service` | one scan process each, drains the queue | enable `@1..@K` (≈ vCPU − 1) |

---

## Recommended sizing — reference VPS (4 vCPU / 16 GB)

* **API**: `workers = 4` (default in `gunicorn.conf.py`; API is I/O-bound since
  scanning is offloaded).
* **Workers**: enable **3** instances (`ojs-sast-worker@1..3`) → up to 3 scans
  in parallel, leaving ~1 core for the API + OS. Each worker is single-threaded
  on purpose: Python's GIL makes extra threads useless for CPU-bound scanning —
  scale **processes**, not threads.
* **service.yml**: keep `max_active_scans_per_key` modest (e.g. `2`) so one agent
  can't monopolise the queue; the limit is now enforced atomically.

16 GB RAM comfortably covers 4 API workers + 3 scan processes for typical OJS
trees. Watch `max_total_extracted_bytes` × concurrent workers for the worst case.

---

## Install

```bash
sudo useradd --system --home /opt/ojssast --shell /usr/sbin/nologin sastojs || true
sudo mkdir -p /opt/ojssast /var/lib/ojs-sast /var/log/ojs-sast /etc/ojs-sast
sudo chown -R sastojs:sastojs /opt/ojssast /var/lib/ojs-sast /var/log/ojs-sast

# Code + venv (as the service user, or chown afterwards)
sudo -u sastojs git clone https://github.com/Warwoyo/ojssast.git /opt/ojssast
cd /opt/ojssast
sudo -u sastojs python3 -m venv .venv
sudo -u sastojs .venv/bin/pip install -e '.[service]'   # pulls in gunicorn + uvicorn[standard]
```

Create `/etc/ojs-sast/service.yml` (see the repo README; add worker knobs if you
want to override defaults):

```yaml
host: "0.0.0.0"
port: 8000
data_dir: "/var/lib/ojs-sast"
# ... api_keys, ip_allowlist, max_* as usual ...
max_active_scans_per_key: 2

# worker pool / queue tuning (defaults shown; all optional)
worker_concurrency: 1
poll_interval_seconds: 0.5
heartbeat_interval_seconds: 15
heartbeat_timeout_seconds: 60
reclaim_interval_seconds: 30
max_attempts: 2
```

## Install the systemd units

```bash
sudo cp deploy/systemd/ojs-sast-api.service        /etc/systemd/system/
sudo cp deploy/systemd/ojs-sast-worker@.service    /etc/systemd/system/
sudo systemctl daemon-reload

# API + 3 scan workers
sudo systemctl enable --now ojs-sast-api.service
sudo systemctl enable --now ojs-sast-worker@1 ojs-sast-worker@2 ojs-sast-worker@3
```

Check it:

```bash
curl -s http://127.0.0.1:8000/health
systemctl status 'ojs-sast-*'
journalctl -u ojs-sast-api -f
journalctl -u 'ojs-sast-worker@*' -f
```

## Manual run (without systemd)

```bash
# Terminal 1 — API
OJS_SAST_CONFIG=/etc/ojs-sast/service.yml \
  .venv/bin/gunicorn -c deploy/gunicorn.conf.py ojs_sast.service.asgi:app

# Terminal 2 — a worker (repeat for more parallelism)
.venv/bin/ojs-sast-service worker --config /etc/ojs-sast/service.yml
```

---

## Crash recovery

Each running job records a periodic **heartbeat**. On start-up and every
`reclaim_interval_seconds`, every worker requeues jobs whose heartbeat is older
than `heartbeat_timeout_seconds` (their worker died): the job is retried while
its source archive is still present and `attempts < max_attempts`, otherwise it
is marked `error` ("stale"). This is multi-process safe — a job being actively
scanned elsewhere keeps a fresh heartbeat and is left alone.

`queued` jobs need no special handling: they simply stay in the queue across a
restart and are claimed when a worker comes back.

## Optional: Nginx + TLS

See `deploy/nginx-ojs-sast.conf.example`. Read the IP-allowlist note at the top
before enabling it.
