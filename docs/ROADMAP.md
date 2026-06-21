# Antigravity-IDS — Repository Audit & Modernization Roadmap

> Audit date: 2026-06-09 · Baseline: 48 tests passed, 1 skipped · Python ≥ 3.11

This document is the result of a full repository audit (architecture, security
posture, detection capabilities, observability, performance, deployment
readiness) and defines the prioritized roadmap toward a production-grade
IDS/SIEM platform. **No existing functionality is removed at any phase.**

---

## 1. Current State (what exists and works)

| Layer | Module | Capability | Quality |
|-------|--------|------------|---------|
| L0 | `logs/` | SQLite forensic audit log (WAL), failsafe text fallback, parameterized inserts | Solid |
| L1 | `alerts/` | SMTP/STARTTLS alerting, MIME attachments with size/MIME guards, granular error telemetry | Solid |
| L2 | `network/` | Scapy sniffer (daemon thread), plug-in detector architecture, ARP-spoof + SYN-scan detectors with sliding windows and O(1) amortized counting, consent gate, privilege check (POSIX + Windows) | Solid |
| L7 | `auth/` | TOTP MFA, Fernet-encrypted secrets, scrypt-hashed recovery codes, replay protection (fingerprint + unique index race guard), exponential backoff, anti-enumeration, soft-delete revocation, CLI (enroll/revoke/list with QR) | Solid |
| FIM | `fim/` | SHA-256 baselines, integrity checks (MODIFIED/DELETED), config-driven, CLI | Solid |
| L8 | `dashboard/` | Flask app-factory, read-only DB access (`mode=ro` URI), TOTP login, CSRF (Flask-WTF), CSP/headers (Talisman), session fixation mitigation, SSE event stream | Good |

**Test coverage:** auth (enrollment, verify, backoff, recovery, revocation,
CLI), network detectors, FIM, dashboard routes/queries. 48 passing.

---

## 2. Gap Analysis

### 2.1 Security vulnerabilities / weaknesses (Priority 1)

| ID | Finding | Risk | Status |
|----|---------|------|--------|
| S-1 | **No HTTP-layer rate limiting on `/login`.** The MFA backoff sleeps *inside* the request handler, so an attacker can hold worker threads (slow-loris-style resource exhaustion) and parallel requests bypass the serialized delay. A skipped test documents the regression (Flask-Limiter removed in commit 6c61030). | High | **Fixed** — in-process fixed-window limiter, 429 + `Retry-After`, test un-skipped |
| S-2 | **Blocking `time.sleep()` backoff in `auth.core`.** DoS vector when called from a web worker; concurrent attempts are not actually delayed. | High | **Fixed** — opt-in `MFA_BACKOFF_MODE=reject` returns a `RATE_LIMITED` event instead of sleeping (dashboard enables it; CLI keeps legacy sleep) |
| S-3 | **RBAC absent.** `users.role` column exists but is never read or enforced. | Medium | **Fixed** — role surfaced in auth + `require_role` decorator in dashboard |
| S-4 | **SSE stream is unbounded** — one worker per client, forever; session never re-validated. | Medium | **Fixed** — bounded lifetime + heartbeats |
| S-5 | Signed-cookie sessions cannot be revoked server-side (documented in README). | Medium | Documented; server-side sessions on PostgreSQL/Redis path (Phase 3) |
| S-6 | No dependency auditing / SBOM / SAST in automation (CI workflow removed by owner; local validation only). | Medium | Documented in `docs/SECURITY.md` (pip-audit / ruff S-rules locally) |
| S-7 | Alert flooding: a noisy detector can trigger unlimited SMTP sends (mailbox flooding + SMTP throttling). | Medium | **Fixed** — opt-in duplicate-suppression window in `alerts` |
| S-8 | `logs/ids_database.sqlite3` lives inside the repo working tree by default. | Low | Documented; `DB_PATH` already externalizes it |

### 2.2 Detection capability gaps (Priority 2)

| ID | Gap | Status |
|----|-----|--------|
| D-1 | No **event normalization** — three sibling dataclasses (`DetectionEvent`, `AuthEvent`, `FimEvent`) with divergent shapes, no common envelope | **Fixed** — `detection/normalize.py` canonical `NormalizedEvent` |
| D-2 | No **MITRE ATT&CK mapping** | **Fixed** — `detection/mitre.py` technique map for every event type |
| D-3 | No **risk scoring** (severity is a bare string) | **Fixed** — `detection/scoring.py` numeric 0–100 risk model |
| D-4 | No **correlation engine** — events are islands; a SYN scan followed by auth failures is never connected | **Fixed** — `detection/correlation.py` sliding-window rules → `incidents` table |
| D-5 | No **event deduplication** | **Fixed** — `detection/dedup.py` fingerprint suppressor |
| D-6 | No Sigma rule support | Phase 2 (rule compiler targeting `NormalizedEvent`) |
| D-7 | FIM detects MODIFIED/DELETED but not CREATED (new files in monitored dirs); per-file config only | Phase 2 (directory baselines) |
| D-8 | No behavioral analytics / anomaly baselines | Phase 3 |

### 2.3 Observability gaps (Priority 4)

| ID | Gap | Status |
|----|-----|--------|
| O-1 | No health/readiness endpoints | **Fixed** — `/healthz`, `/readyz` |
| O-2 | No metrics | **Fixed** — `/metrics` Prometheus text exposition (no new deps) |
| O-3 | No structured (JSON) log output for shipping to external SIEMs | Phase 2 (JSON stream handler option in `logs`) |
| O-4 | No tracing | Phase 3 (OpenTelemetry, optional extra) |

### 2.4 Data layer gaps

| ID | Gap | Status |
|----|-----|--------|
| DB-1 | No retention policy — `audit_events` grows forever | **Fixed** — `logs/maintenance.py` purge + `python -m logs` CLI |
| DB-2 | No integrity verification / VACUUM procedure | **Fixed** — same module |
| DB-3 | `fim_events` lacks timestamp index | **Fixed** — additive `CREATE INDEX IF NOT EXISTS` |
| DB-4 | SQLite single-writer ceiling | Phase 3 — PostgreSQL migration path documented in `docs/DEPLOYMENT.md`; schema kept ANSI-compatible |

### 2.5 Platform / SOC usability gaps

| ID | Gap | Status |
|----|-----|--------|
| P-1 | No incident view — analysts see raw events only | **Fixed** — `/api/incidents` + correlation engine (now with read-time remediation/confidence/tactic enrichment) |
| P-2 | No deployment story | **Fixed** — local Windows + Waitress production server, startup config diagnostics (`python -m dashboard --check`), `docs/DEPLOYMENT.md`. (Docker/CI removed by owner in favor of a strictly local Windows environment.) |
| P-3 | No operational runbook | **Fixed** — `docs/OPERATIONS.md` |
| P-4 | No AI-assisted triage | **Fixed (architecture)** — `ai/` local-LLM summarizer, fully optional, privacy-preserving |
| P-5 | Dashboard search/filter/timeline | Phase 2 |

### 2.6 Technical debt & dangerous assumptions

* `auth/storage.py` bootstraps the DB **at import time** (side effect on import;
  swallows errors with `print`). Kept for compatibility — flagged for Phase 2.
* `fim/monitor.py` accepts TOCTOU between hash reads (documented as accepted MVP debt).
* SSE polls the DB every 5 s per client — acceptable at homelab scale; switch to
  a notify queue at Phase 3 scale.
* `requirements.txt` pins `pytest==9.0.2` while `pyproject.toml` dev extra wants
  `pytest>=8.0` — harmless but duplicated dependency sources.
* Mixed Spanish/English comments — cosmetic; left as-is (no functional impact).

---

## 3. Modernization Roadmap

### Phase 1 — *this iteration* (security + detection core + ops baseline)

1. ✅ Detection engine package (`detection/`): normalization, MITRE mapping,
   risk scoring, dedup, correlation → `incidents` table.
2. ✅ Dashboard hardening: login rate limiting, `login_required`/`require_role`,
   `/healthz`, `/readyz`, `/metrics`, bounded SSE, `/api/incidents`.
3. ✅ Auth hardening: non-blocking backoff mode (opt-in), role helpers.
4. ✅ DB operations: retention, integrity check, VACUUM, indexes.
5. ✅ Alert throttling (opt-in duplicate suppression).
6. ✅ AI architecture: local-LLM summarizer with graceful no-op fallback.
7. ✅ Local Windows + Waitress deployment, operations/security documentation.

### Phase 1.5 — production hardening (this iteration)

1. ✅ Deployment readiness: Waitress production server (Windows-native),
   `python -m dashboard --check` configuration diagnostics, dependency cleanup
   (gunicorn → waitress).
2. ✅ Detection depth: `password_spray` and `auth_success_after_failures`
   correlation rules; case-insensitive entity extraction fix that enables
   success-to-user correlation.
3. ✅ Threat intelligence: optional local IOC watchlists (IP/CIDR + domain) and
   the `ioc_match` rule (`detection/intel.py`).
4. ✅ Phishing/scam triage: deterministic, explainable, fully-local URL analyzer
   (`detection/phishing.py`).
5. ✅ Alert quality: per-rule tactic/confidence/remediation playbooks
   (`detection/playbook.py`), surfaced on `/api/incidents` and in AI summaries.
6. ✅ Audit integrity: tamper-evident hash-chain sealing (`logs/integrity.py`,
   `python -m logs seal` / `verify-chain`).
7. ✅ Observability/DB: `ids_database_size_bytes` + `ids_last_event_timestamp_seconds`
   metrics, `quick_check`, and WAL `checkpoint` maintenance.

### Phase 2 — detection depth & analyst workflow

* Sigma rule loader compiling to `NormalizedEvent` predicates.
* FIM: directory baselines, CREATED detection, scheduled daemon mode.
* JSON structured-log stream handler (ship to external SIEM).
* Dashboard: search/filter, event drill-down, incident timeline view.
* DNS / ICMP-sweep / beaconing detectors.
* pip-audit + SBOM (CycloneDX) generation task.

### Phase 3 — scale & enterprise

* PostgreSQL migration (SQLAlchemy core or thin adapter; SQLite stays default).
* Server-side sessions (Redis) → true logout revocation.
* OpenTelemetry traces + Grafana dashboards.
* Multi-sensor agent → collector architecture (mTLS).
* Behavioral analytics (per-entity baselines, EWMA anomaly scoring).
* Analyst copilot (ai/ module + investigation context retrieval).

---

## 4. Compatibility guarantees

* All existing tables, columns, routes, CLIs, env vars, and module APIs are
  preserved. New schema objects are additive (`CREATE TABLE/INDEX IF NOT EXISTS`).
* New behaviors that change runtime characteristics (reject-mode backoff, alert
  throttling) are **opt-in via env vars** and default to legacy behavior.
* The full pre-existing test suite must pass unmodified (except the
  intentionally skipped rate-limit test, which is re-enabled now that the
  feature exists at the chosen layer).
