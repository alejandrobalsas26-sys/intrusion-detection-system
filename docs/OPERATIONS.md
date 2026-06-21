# Operations Runbook

## 1. Health & monitoring

| Endpoint | Meaning |
|----------|---------|
| `GET /healthz` | liveness — process serving requests |
| `GET /readyz` | readiness — audit DB reachable and readable (503 otherwise) |
| `GET /metrics` | Prometheus text exposition (aggregate counters only — no event payloads, usernames, or IPs) |

Before serving, run `python -m dashboard --check` to validate configuration
(secret key, Fernet key, DB path, production server availability). It exits 0
when READY and 1 on a blocking misconfiguration — wire it into your service
start script.

Prometheus scrape config (default Waitress port is 5000; scrape through your
reverse proxy if TLS is terminated there):

```yaml
scrape_configs:
  - job_name: antigravity-ids
    static_configs: [{ targets: ["127.0.0.1:5000"] }]
```

Exposed series include `ids_up`, `ids_ready`, `ids_audit_events_total{level}`,
`ids_fim_events_total`, `ids_network_events_total`, `ids_active_users`,
`ids_open_incidents`, `ids_database_size_bytes`, and
`ids_last_event_timestamp_seconds`.

Useful alerts:
* `ids_ready == 0` — DB unavailable
* `increase(ids_audit_events_total{level="CRITICAL"}[5m]) > 0` — critical activity
* `ids_open_incidents > 0` — uncleared incidents
* `time() - ids_last_event_timestamp_seconds > 3600` — telemetry stalled (a sensor likely stopped)
* `ids_database_size_bytes` trending up unexpectedly — retention not keeping pace

## 2. Database maintenance

```bash
python -m logs stats            # row counts + size
python -m logs check            # PRAGMA integrity_check (exit 1 on corruption)
python -m logs check --quick    # faster PRAGMA quick_check (routine health probe)
python -m logs purge --days 90  # retention purge (audit, fim, auth_attempts, closed incidents)
python -m logs purge --vacuum   # purge + reclaim disk space
python -m logs checkpoint       # flush + truncate the WAL (hygiene after a large purge)
```

Retention never touches identity data (users, recovery codes) or file
baselines, and never deletes open/acknowledged incidents.

## 2b. Tamper-evident audit sealing (optional)

```bash
python -m logs seal             # fold new audit events into the hash chain
python -m logs verify-chain     # recompute the chain; exit 1 if tampering is found
```

`seal` is an out-of-band batch job (run it from the daily retention task). It
never touches the hot logging path. `verify-chain` reports any modification,
deletion, or insertion within a sealed range, while treating rows that aged out
under retention as expected (not tampering). For a stronger guarantee, export
the `anchor` hash printed by `verify-chain` to off-box/WORM storage so a forger
who rewrites the checkpoint table cannot cover their tracks.

> Coordinate sealing with retention: seal within your retention window, and
> after a purge the aged-out segments are reported as "aged out", not failures.

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
   each with `risk_score`, `mitre_techniques`, `entities`, a summary, and
   read-time enrichment: `tactic`, `confidence`, `remediation` steps, and
   `references`. Incident rules include brute force, **password spray**,
   **successful login after a failure burst** (possible compromise), replay,
   recon→auth, network→FIM, and **threat-intel (IOC) matches**.
2. Correlation sweeps run via `python -m detection` (one-shot or `--interval`).
   Sweeps are idempotent — re-running never duplicates incidents.
   * To enable IOC matching, point `IOC_IP_LIST_PATH` / `IOC_DOMAIN_LIST_PATH`
     at plain-text watchlists (one indicator per line; CIDR and parent-domain
     matching supported). Off until configured.
   * To triage a suspicious link from a phishing/smishing report, run
     `python -m detection.phishing <url>` for an explainable, fully-local risk
     verdict (homoglyph/punycode, typosquatting, brand impersonation, abused
     TLDs, scam keywords). No data leaves the host.
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
