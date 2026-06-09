# Operations Runbook

## 1. Health & monitoring

| Endpoint | Meaning |
|----------|---------|
| `GET /healthz` | liveness — process serving requests |
| `GET /readyz` | readiness — audit DB reachable and readable (503 otherwise) |
| `GET /metrics` | Prometheus text exposition (aggregate counters only — no event payloads, usernames, or IPs) |

Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: antigravity-ids
    static_configs: [{ targets: ["127.0.0.1:8000"] }]
```

Useful alerts: `ids_ready == 0` (DB unavailable), `increase(ids_audit_events_total{level="CRITICAL"}[5m]) > 0`, `ids_open_incidents > 0`.

## 2. Database maintenance

```bash
python -m logs stats            # row counts + size
python -m logs check            # PRAGMA integrity_check (exit 1 on corruption)
python -m logs purge --days 90  # retention purge (audit, fim, auth_attempts, closed incidents)
python -m logs purge --vacuum   # purge + reclaim disk space
```

Retention never touches identity data (users, recovery codes) or file
baselines, and never deletes open/acknowledged incidents.

## 3. Backups & disaster recovery

* **What:** the SQLite file at `DB_PATH` (default `logs/ids_database.sqlite3`)
  plus `.env` (stored separately, encrypted — it holds key material).
* **How:** use SQLite's online backup; never copy the live file mid-write:
  ```bash
  sqlite3 logs/ids_database.sqlite3 ".backup 'backup/ids-$(date +%F).sqlite3'"
  ```
* **Cadence:** daily backup, 7 daily + 4 weekly retained.
* **Restore:** stop services → replace the DB file → `python -m logs check` →
  restart. TOTP enrollments survive as long as `MFA_ENCRYPTION_KEY` is the
  same — losing that key orphans every enrolled secret (re-enroll required).

## 4. Incident triage workflow

1. `GET /api/incidents?status=open` (or the dashboard) — sorted newest first,
   each with `risk_score`, `mitre_techniques`, `entities`, and a summary.
2. Correlation sweeps run via the `correlator` service or `python -m detection`.
   Sweeps are idempotent — re-running never duplicates incidents.
3. Acknowledge/close (until the UI grows controls) directly and audibly:
   ```bash
   sqlite3 $DB_PATH "UPDATE incidents SET status='acknowledged' WHERE id=<n>;"
   ```
4. Optional AI assist: with a local model running (e.g. `ollama serve`), set
   `AI_BACKEND=ollama` and use `ai.summarize_incident(incident)` from a shell
   or notebook. Falls back to deterministic summaries when the model is down.

## 5. Common failures

| Symptom | Cause | Action |
|---------|-------|--------|
| `/readyz` 503 | DB file missing/locked/corrupt | `python -m logs check`; restore from backup |
| `logs/failsafe.log` growing | SQLite writes failing | disk full? permissions? check failsafe entries for the original error |
| 429 on login | login rate limit (5/min/IP default) | wait for `Retry-After`; tune `LOGIN_RATE_LIMIT_*` |
| `RATE_LIMITED` auth events | MFA backoff in reject mode | expected under brute force; investigate the source |
| No alert e-mails | SMTP creds/network, or `ALERT_DEDUP_WINDOW_SECONDS` suppressing duplicates | check audit log for `SMTP` entries |
| Sensor exits immediately | missing consent or privileges | set `NETWORK_MONITOR_CONSENT=true`, run elevated |
