# End-to-end demo

Generates a realistic multi-stage attack chain into the platform's own SQLite
audit store, then lets the correlation engine turn it into incidents. Fully
local: no live traffic, no admin rights, no camera, no external APIs, and
outbound e-mail alerts are suppressed by default.

## What it simulates

| Stage | Telemetry | Detection |
|-------|-----------|-----------|
| Recon | SYN scan from `203.0.113.66` (RFC 5737 doc space) | `syn_scan` event |
| Credential attack | 5 failures against `admin`, then 1 failure each against 5 more accounts | brute force + password spray |
| Compromise | successful `admin` login right after the burst | `auth_success_after_failures` |
| Persistence | **real file tampering**: `demo/protected/` is copied to `demo/protected_live/`, baselined by FIM, then modified + a new file planted | `FIM_MODIFIED` + `FIM_CREATED` from a genuine `fim.check_integrity()` run |
| Threat intel | the attacker IP is written to a local IOC watchlist | `ioc_match` |

Expected incident rules after the sweep: `brute_force_burst`,
`password_spray`, `auth_success_after_failures`, `recon_then_auth`,
`network_then_fim`, `ioc_match`.

## Run it

```bash
python demo/generate_attack_chain.py       # generate + correlate (default)
# or, in two explicit steps:
python demo/generate_attack_chain.py --no-sweep
python -m detection                        # idempotent sweep -> incidents
# or through the orchestrator:
python -m ids demo
```

Then inspect the results:

```bash
python -m dashboard                        # http://127.0.0.1:5000 (TOTP login)
#   -> /api/incidents returns the JSON incident feed (after login)
sqlite3 logs/ids_database.sqlite3 "SELECT rule_name, title, risk_score FROM incidents;"
```

No dashboard user yet? Enroll one first: `python -m auth.cli enroll <name>`
(scan the QR with any TOTP app). The demo itself needs no credentials and
hardcodes no secrets.

## Replay variants

```bash
python -m detection.replay demo/sample_events.jsonl --sweep   # JSONL event replay
python -m network.replay samples/syn_scan.pcap                # PCAP through live detectors
```

## Generated artifacts (safe to delete, recreated on each run)

* `demo/protected_live/` — tampered scratch copy of `demo/protected/`
* `demo/_fim_demo_config.json` — FIM config pointing at the scratch copy
* `demo/_demo_ioc_ips.txt` — one-line IOC watchlist with the attacker IP

Re-running the demo is safe: incident creation is idempotent per event
timeline (a fresh run creates a fresh timeline, so new incidents appear —
that is the point of a demo).
