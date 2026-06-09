# Deployment Guide

## 1. Local (development)

```bash
cp .env.example .env          # fill in real values (see §4)
pip install -r requirements.txt
python -m auth.cli enroll admin_user     # scan QR, store recovery codes
python -m auth.cli set-role admin_user admin
python -m dashboard                       # http://127.0.0.1:5000
```

Optional components:

```bash
python -m fim --baseline && python -m fim --check   # file integrity
python -m detection --interval 60                   # correlation daemon
python -m network                                   # sensor (admin/root + consent)
python -m logs stats                                # DB operational stats
```

## 2. Docker (recommended for homelab/SMB)

```bash
cp .env.example .env   # configure secrets first
docker compose up -d --build
```

This starts:

| Service | Role |
|---------|------|
| `dashboard` | gunicorn on `127.0.0.1:8000`, read-only rootfs, non-root user |
| `correlator` | `python -m detection --interval 60` (incident generation) |
| `retention` | daily `python -m logs purge --vacuum` |

The event store lives on the `ids-data` volume. The **network sensor is not
containerized** — it needs `CAP_NET_RAW`, host networking, and explicit legal
consent (`NETWORK_MONITOR_CONSENT=true`); run it on the host with admin/root
privileges, pointing `DB_PATH` at a shared location.

Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in front of the
dashboard for any non-localhost access; set `FLASK_ENV=production` so secure
cookies, HSTS, and HTTPS enforcement activate.

## 3. Production hardening checklist

- [ ] `FLASK_SECRET_KEY`: 64-hex random (`python -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] `MFA_ENCRYPTION_KEY`: fresh Fernet key; back it up offline (losing it orphans all TOTP secrets)
- [ ] `FLASK_ENV=production` (secure cookies + HSTS + HTTPS redirect)
- [ ] Reverse proxy with TLS in front of `:8000`; restrict `/metrics` there if needed
- [ ] `MFA_BACKOFF_MODE=reject` for web deployments (dashboard defaults to this)
- [ ] `ALERT_DEDUP_WINDOW_SECONDS=300` to stop alert storms
- [ ] `RETENTION_DAYS` per your compliance window (default 90)
- [ ] SMTP app password, not the account password
- [ ] Database file on encrypted storage (encryption at rest is delegated to the volume: LUKS/BitLocker)
- [ ] Backups: see docs/OPERATIONS.md §3

## 4. Environment variables

All variables are documented in `.env.example`. New in this release:

| Variable | Default | Purpose |
|----------|---------|---------|
| `MFA_BACKOFF_MODE` | `sleep` (`reject` inside the dashboard) | non-blocking auth rate limiting for web workers |
| `LOGIN_RATE_LIMIT_ATTEMPTS` / `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | 5 / 60 | HTTP login rate limit |
| `EVENT_DEDUP_WINDOW_SECONDS` | 0 (off) | sensor duplicate-event suppression |
| `ALERT_DEDUP_WINDOW_SECONDS` | 0 (off) | duplicate e-mail suppression |
| `SSE_MAX_LIFETIME_SECONDS` / `SSE_POLL_INTERVAL_SECONDS` | 900 / 5 | SSE stream bounds |
| `RETENTION_DAYS` | 90 | event retention horizon |
| `CORRELATION_*` | see `.env.example` | correlation rule thresholds |
| `AI_BACKEND` / `AI_ENDPOINT` / `AI_MODEL` | off | local LLM summarization |

## 5. PostgreSQL migration path (Phase 3)

SQLite (WAL) is the supported default and is adequate for single-host,
homelab, and SMB scale. When multi-writer scale is needed:

1. Schemas intentionally use ANSI-portable types (INTEGER/TEXT/REAL/DATETIME);
   the only SQLite-isms are `AUTOINCREMENT` (→ `GENERATED ... AS IDENTITY`) and
   `datetime('now', ...)` (→ `now() - interval`).
2. Export with `sqlite3 ids_database.sqlite3 .dump`, transform with pgloader.
3. Database access is concentrated in small modules (`logs/logger.py`,
   `dashboard/queries.py`, `auth/core.py`, `fim/monitor.py`,
   `detection/correlation.py`, `logs/maintenance.py`) — a thin adapter swap,
   no ORM rewrite required.
4. Keep SQLite as the default; PostgreSQL becomes an opt-in `DB_URL` backend.
