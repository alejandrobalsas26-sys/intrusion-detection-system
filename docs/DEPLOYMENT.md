# Deployment Guide

This is a **local-first, Windows-friendly** deployment. The supported production
server is [Waitress](https://docs.pylonsproject.org/projects/waitress/) (pure
Python, runs natively on Windows — unlike gunicorn, which is POSIX-only). There
is no Docker/Compose story by design; the system is meant to run directly on the
host it protects.

## 1. Local (development)

```powershell
copy .env.example .env          # fill in real values (see §4)
pip install -r requirements.txt
python -m auth.cli enroll admin_user     # scan QR, store recovery codes
python -m auth.cli set-role admin_user admin
python -m dashboard --check              # validate configuration before serving
python -m dashboard                      # Flask dev server, http://127.0.0.1:5000
```

Optional components:

```powershell
python -m fim --baseline ; python -m fim --check    # file integrity
python -m detection --interval 60                   # correlation daemon
python -m network                                   # sensor (admin + consent)
python -m logs stats                                # DB operational stats
```

## 2. Production (Windows host + Waitress)

```powershell
copy .env.example .env
# Edit .env: set FLASK_ENV=production and strong secrets (see §4).
pip install -r requirements.txt        # includes waitress
python -m dashboard --check             # MUST report READY before serving
python -m dashboard --production        # serves via Waitress on 127.0.0.1:5000
```

`--production` sets `FLASK_ENV=production` for you, which turns on secure
cookies, HSTS, and HTTPS redirection (Talisman). Useful flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--production` | off | Serve via Waitress with production settings |
| `--server {auto,waitress,flask}` | `auto` | Force a server (auto = waitress in prod, else flask) |
| `--host` | `127.0.0.1` | Bind address (keep on loopback behind a proxy) |
| `--port` | `5000` | Listen port |
| `--threads` | `8` | Waitress worker threads (`WAITRESS_THREADS`) |
| `--check` | — | Run config diagnostics and exit (0 = ready, 1 = blocking issue) |

Because Talisman forces HTTPS in production, terminate TLS at a reverse proxy
(IIS/ARR, nginx, Caddy, or Traefik on the host) and forward to Waitress on
loopback with `X-Forwarded-Proto: https`. Health probes (`/healthz`, `/readyz`)
should go through the proxy so they are not 301-redirected to HTTPS.

### Running as a Windows service

Either approach keeps the dashboard running across reboots:

* **Task Scheduler** — create a task, trigger "At startup", action
  `python -m dashboard --production`, run whether or not a user is logged on.
* **NSSM** (Non-Sucking Service Manager, optional external tool):
  ```powershell
  nssm install AntigravityIDS "C:\Path\to\python.exe" "-m dashboard --production"
  nssm set AntigravityIDS AppDirectory "C:\Path\to\intrusion-detection-system"
  nssm start AntigravityIDS
  ```

The correlation engine and retention are separate scheduled jobs (Task
Scheduler): `python -m detection --interval 60` (incident generation) and a
daily `python -m logs purge --vacuum` (retention). The **network sensor** runs
on the host with administrator privileges and explicit consent
(`NETWORK_MONITOR_CONSENT=true`); it is never auto-started without that gate.

## 3. Production hardening checklist

- [ ] `python -m dashboard --check` reports **READY** (no `[x]` lines)
- [ ] `FLASK_SECRET_KEY`: 64-hex random (`python -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] `MFA_ENCRYPTION_KEY`: fresh Fernet key; back it up offline (losing it orphans all TOTP secrets)
- [ ] `FLASK_ENV=production` (secure cookies + HSTS + HTTPS redirect)
- [ ] Reverse proxy with TLS in front of Waitress; restrict `/metrics` there or set `METRICS_TOKEN`
- [ ] `MFA_BACKOFF_MODE=reject` for web deployments (dashboard defaults to this)
- [ ] `ALERT_DEDUP_WINDOW_SECONDS=300` to stop alert storms
- [ ] `RETENTION_DAYS` per your compliance window (default 90)
- [ ] SMTP app password, not the account password
- [ ] Database file on encrypted storage (BitLocker/LUKS — encryption at rest is delegated to the volume)
- [ ] (Optional) Schedule `python -m logs seal` for tamper-evident audit sealing; export the printed anchor hash off-box
- [ ] (Optional) Drop IOC watchlists at `IOC_IP_LIST_PATH` / `IOC_DOMAIN_LIST_PATH`
- [ ] Backups: see docs/OPERATIONS.md §3

## 4. Environment variables

All variables are documented in `.env.example`. Highlights:

| Variable | Default | Purpose |
|----------|---------|---------|
| `FLASK_ENV` | `development` | `production` enables secure cookies, HSTS, HTTPS redirect |
| `DASHBOARD_HOST` / `DASHBOARD_PORT` | `127.0.0.1` / `5000` | Dashboard bind address/port |
| `WAITRESS_THREADS` | `8` | Waitress worker threads |
| `MFA_BACKOFF_MODE` | `sleep` (`reject` inside the dashboard) | non-blocking auth rate limiting for web workers |
| `LOGIN_RATE_LIMIT_ATTEMPTS` / `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | 5 / 60 | HTTP login rate limit |
| `EVENT_DEDUP_WINDOW_SECONDS` | 0 (off) | sensor duplicate-event suppression |
| `ALERT_DEDUP_WINDOW_SECONDS` | 0 (off) | duplicate e-mail suppression |
| `SSE_MAX_LIFETIME_SECONDS` / `SSE_POLL_INTERVAL_SECONDS` | 900 / 5 | SSE stream bounds |
| `RETENTION_DAYS` | 90 | event retention horizon |
| `CORRELATION_*` | see `.env.example` | correlation rule thresholds (brute force, password spray, success-after-failures) |
| `IOC_IP_LIST_PATH` / `IOC_DOMAIN_LIST_PATH` | unset | optional local threat-intel watchlists |
| `PHISHING_PROTECTED_BRANDS` | builtin list | extra brands for the phishing URL analyzer |
| `METRICS_TOKEN` | unset | optional bearer token gating `/metrics` |
| `AI_BACKEND` / `AI_ENDPOINT` / `AI_MODEL` | off | local LLM summarization |

## 5. PostgreSQL migration path (future)

SQLite (WAL) is the supported default and is adequate for single-host, homelab,
and SMB scale. When multi-writer scale is needed:

1. Schemas intentionally use ANSI-portable types (INTEGER/TEXT/REAL/DATETIME);
   the only SQLite-isms are `AUTOINCREMENT` (→ `GENERATED ... AS IDENTITY`) and
   `datetime('now', ...)` (→ `now() - interval`).
2. Export with `sqlite3 ids_database.sqlite3 .dump`, transform with pgloader.
3. Database access is concentrated in small modules (`logs/logger.py`,
   `dashboard/queries.py`, `auth/core.py`, `fim/monitor.py`,
   `detection/correlation.py`, `logs/maintenance.py`, `logs/integrity.py`) — a
   thin adapter swap, no ORM rewrite required.
4. Keep SQLite as the default; PostgreSQL becomes an opt-in `DB_URL` backend.
