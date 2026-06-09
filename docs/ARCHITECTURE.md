# Antigravity-IDS — Architecture

## Overview

Antigravity-IDS is a modular host/network intrusion detection platform built as
independent Python packages that share a single SQLite event store (WAL mode)
and a common alerting channel. Each layer can run standalone (`python -m <pkg>`).

```
                         ┌────────────────────────────────────────────┐
                         │                 Dashboard (L8)             │
                         │  Flask app-factory · TOTP login · CSRF     │
                         │  CSP/Talisman · rate-limited /login        │
                         │  /healthz /readyz /metrics /api/incidents  │
                         └────────────────┬───────────────────────────┘
                                          │ read-only (file:...?mode=ro)
            ┌─────────────────────────────▼─────────────────────────────┐
            │                SQLite event store (WAL)                   │
            │  audit_events · fim_events · users · recovery_codes       │
            │  auth_attempts · file_baselines · incidents               │
            └───▲──────────────▲──────────────▲──────────────▲──────────┘
                │              │              │              │
        ┌───────┴──────┐ ┌─────┴──────┐ ┌─────┴──────┐ ┌─────┴────────┐
        │ network/ (L2)│ │ fim/       │ │ auth/ (L7) │ │ detection/   │
        │ scapy sniffer│ │ SHA-256    │ │ TOTP MFA   │ │ correlation  │
        │ ARP + SYN    │ │ baselines  │ │ recovery   │ │ scoring      │
        │ detectors    │ │ integrity  │ │ backoff    │ │ MITRE map    │
        └───────┬──────┘ └─────┬──────┘ └─────┬──────┘ │ dedup        │
                │              │              │        └─────┬────────┘
                └──────────────┴──────┬───────┴──────────────┘
                                      ▼
                          ┌──────────────────────┐        ┌─────────────┐
                          │  logs/ (L0) audit    │        │  ai/        │
                          │  SQLite handler +    │        │  local LLM  │
                          │  failsafe text log   │        │  summarizer │
                          └──────────┬───────────┘        │  (optional) │
                                     ▼                    └─────────────┘
                          ┌──────────────────────┐
                          │  alerts/ (L1) SMTP   │
                          │  STARTTLS · throttle │
                          └──────────────────────┘
```

## Packages

### `logs/` — L0 forensic audit log
`SQLiteAuditHandler` (a `logging.Handler`) persists every record to
`audit_events` with parameterized SQL. If SQLite is unavailable it degrades to
an append-only text failsafe, then to stderr. `logs/maintenance.py` provides
retention purges, `PRAGMA integrity_check`, and VACUUM (`python -m logs`).

### `alerts/` — L1 notification channel
`send_security_alert()` sends SMTP/STARTTLS mail with MIME attachments
(existence/size/type guarded). Optional duplicate-suppression window
(`ALERT_DEDUP_WINDOW_SECONDS`) prevents mailbox flooding; disabled by default.

### `network/` — L2 sensor
`start_sensor()` validates consent (`NETWORK_MONITOR_CONSENT=true`) and OS
privileges, then sniffs with a BPF filter on a daemon thread. Detectors are
plug-ins implementing `process_packet(pkt) -> DetectionEvent | None`:

* `ArpDetector` — MAC flapping per IP within a sliding window (lazy eviction).
* `SynDetector` — distinct destination ports per source IP, O(1) amortized.

### `auth/` — L7 identity & MFA
TOTP secrets encrypted at rest (Fernet), recovery codes hashed with scrypt and
per-code salts, token replay protection via SHA-256 fingerprints with a unique
index as a race-condition backstop, exponential backoff on failures
(sleep-based legacy mode, or non-blocking `reject` mode for web contexts),
anti-enumeration responses, and soft-delete revocation. CLI: enroll (QR),
revoke, list.

### `fim/` — file integrity monitoring
Config-driven SHA-256 baselines; `check_integrity()` raises MODIFIED/DELETED
events to the DB, audit log, and email.

### `detection/` — detection engineering core (new)
* `normalize.py` — converts `DetectionEvent`/`AuthEvent`/`FimEvent`/raw
  `audit_events` rows into one canonical `NormalizedEvent` envelope.
* `mitre.py` — MITRE ATT&CK technique mapping per event type.
* `scoring.py` — numeric risk score (0–100) from severity, technique, and
  contextual amplifiers.
* `dedup.py` — fingerprint-based duplicate suppression (sliding window).
* `correlation.py` — rule-driven sliding-window correlation over
  `audit_events`/`fim_events`; emits incidents into the `incidents` table.
* `python -m detection` — one-shot or interval correlation sweeps.

### `dashboard/` — L8 read-only SOC console
App-factory Flask UI. Defense in depth: every query runs over a
read-only URI connection (`mode=ro`) so writes are rejected by the engine
itself. TOTP login (delegated to `auth.core`), CSRF protection, strict CSP,
session fixation mitigation, 15-minute sessions, fixed-window login rate
limiting, RBAC decorator over the existing `users.role` column, `/healthz`,
`/readyz`, Prometheus `/metrics`, bounded SSE stream, and `/api/incidents`.

### `ai/` — local LLM assistance (new, optional)
Provider-agnostic client for OpenAI-compatible local endpoints (Ollama,
llama.cpp, vLLM). Summarizes alerts/incidents for analysts. Disabled unless
`AI_BACKEND` is configured; all failures degrade to deterministic non-LLM
summaries. No event data ever leaves the host unless the operator points the
endpoint elsewhere.

## Data model

All schema files are idempotent (`IF NOT EXISTS`) and additive-only.

| Table | Owner | Purpose |
|-------|-------|---------|
| `audit_events` | logs | every log record (epoch timestamp, level, module, message, JSON context) |
| `users` | auth | identities; `role` (RBAC), `is_active` (soft delete) |
| `recovery_codes` | auth | scrypt-hashed one-time codes |
| `auth_attempts` | auth | success/failure trail + replay fingerprints |
| `token_blacklist` | auth | reserved for future session/token revocation |
| `file_baselines` | fim | SHA-256 baselines |
| `fim_events` | fim | integrity violations |
| `incidents` | detection | correlated multi-event incidents (rule, score, MITRE, status) |

## Trust boundaries

1. **Network capture → detectors**: untrusted packet data; detectors never eval
   or format-execute packet contents; per-detector exception isolation keeps the
   sniffer alive.
2. **Browser → dashboard**: CSRF tokens, strict CSP, HttpOnly/SameSite=Strict
   cookies, rate-limited login, anti-enumeration messages.
3. **Dashboard → DB**: engine-enforced read-only connections.
4. **Secrets**: TOTP secrets encrypted (Fernet) with key from env; recovery
   codes irreversibly hashed; SMTP credentials only in env.
5. **ai/ module**: outbound calls only to the operator-configured local
   endpoint; payloads are event summaries, opt-in.
