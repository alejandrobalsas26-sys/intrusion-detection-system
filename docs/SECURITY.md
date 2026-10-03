# Security Documentation

## Threat model & controls

| Surface | Threats | Controls |
|---------|---------|----------|
| Dashboard login | credential stuffing, TOTP brute force, enumeration, CSRF, session theft | TOTP authentication (one possession factor); per-IP HTTP rate limit (429); non-blocking auth backoff (`reject` mode); identical failure messages (anti-enumeration); CSRF tokens; HttpOnly/SameSite=Strict cookies; absolute 15-min sessions; session-fixation reset at login; active status and RBAC role rechecked per request |
| Dashboard data layer | SQLi, tampering via web tier | parameterized queries only; engine-enforced read-only connections (`file:...?mode=ro`) |
| Browser | XSS, clickjacking, mixed content | strict CSP (allow-listed CDNs), `frame-ancestors 'none'`, X-Frame-Options DENY, HSTS + HTTPS redirect in production (Talisman) |
| TOTP secrets | DB theft | Fernet (AES-128-CBC + HMAC) encryption at rest; key only in env |
| Recovery codes | DB theft, replay | scrypt (n=16384) with per-code salts; single-use (deleted on consume); constant-time compare |
| Token replay | reuse within TOTP window | atomic UNIQUE(user_id, time_step) consumption of the verified TOTP interval; invalid attempts cannot reserve codes |
| Auth brute force | online guessing | exponential backoff (sleep or reject mode); failed-attempt telemetry; CRITICAL alerts past threshold |
| SMTP alerting | mailbox flooding, credential leakage | STARTTLS with certificate/hostname verification; app passwords; optional duplicate-suppression window |
| Network capture | malicious packets crashing sensor | per-detector exception isolation; no eval/exec of packet data; BPF pre-filter |
| Sensor abuse | unauthorized sniffing | explicit consent env gate + OS privilege check |
| SSE | worker exhaustion | auth required; absolute session expiry and active user rechecked while streaming; bounded lifetime; heartbeats |
| AI layer | data exfiltration | disabled by default; local endpoint only unless operator reconfigures; scheme validation; hard failure isolation |
| Audit log tampering | post-hoc edit/delete of forensic records | optional hash-chain sealing (`python -m logs seal` / `verify-chain`); off-box anchor for tamper-proofing |
| Known-bad infrastructure | traffic to/from flagged IPs or domains | optional local IOC watchlists (`detection/intel.py`); no cloud/API dependency |
| Phishing / smishing links | credential-harvesting URLs | local, explainable URL analyzer (`detection/phishing.py`); fully offline, no AI/API |

## Secret management

* All secrets come from the environment (`.env`, gitignored; `.env.example` is
  the documented template). Nothing secret is committed.
* `MFA_ENCRYPTION_KEY` is the root of trust for TOTP secrets — store a copy
  offline. Rotation requires decrypt/re-encrypt of `users.encrypted_secret`.
* `FLASK_SECRET_KEY` rotation invalidates all sessions (safe, just logs
  everyone out).

## Encryption

* **In transit:** SMTP via STARTTLS; dashboard HTTPS enforced in production
  (terminate TLS at the reverse proxy).
* **At rest:** TOTP secrets encrypted (Fernet); recovery codes irreversibly
  hashed; full-database encryption at rest is delegated to volume encryption
  (LUKS/BitLocker) — see DEPLOYMENT checklist.

## Dependency & supply-chain hygiene (local validation)

CI was intentionally removed by the repository owner; run locally:

```bash
python -m ruff check .          # includes flake8-bandit (S) security rules
python -m pytest
pip install pip-audit && pip-audit -r requirements.txt   # CVE audit
pip install cyclonedx-bom && cyclonedx-py requirements -i requirements.txt -o sbom.json  # SBOM
```

`requirements.txt` is fully pinned (strict versions) to keep builds
reproducible; review diffs when bumping pins.

## Known limitations (accepted, documented)

* Logout clears the browser cookie but cannot revoke a stolen copy individually.
  Absolute 15-minute expiry bounds its lifetime; user revocation disables all of
  that user's cookies on the next protected request (SSE checks each poll).
  Server-side sessions remain the Phase 3 fix for individual logout revocation.
* FIM has a TOCTOU window between hash computations (accepted MVP debt).
* `/metrics` is unauthenticated by default (aggregate counters only, for
  probe/scraper compatibility); set `METRICS_TOKEN` to require a bearer token,
  or restrict it at the reverse proxy if your threat model requires it.
* The in-process login rate limiter is per-process; if you run multiple
  Waitress instances behind a load balancer the effective limit is
  `limit × instances`. A single Waitress process (the default) uses threads, not
  separate processes, so the limiter is global within it. Front with a
  reverse-proxy limit (e.g. nginx `limit_req`) for strict multi-instance guarantees.
* Audit sealing (`logs/integrity.py`) is tamper-*evident*, not tamper-*proof*:
  an attacker with write access to `audit_events`, `audit_retention_hashes`, and `audit_checkpoints`
  can rewrite a consistent chain. Export the latest `chain_hash` anchor off-box
  to close that gap.

## Reporting

This is a homelab/research project. Report issues via the repository issue
tracker; do not file public exploits for unreleased fixes.

Attack-chain correlation establishes a shared host (and recon/auth source IP),
not causation. Validate the linked activity during triage. CLI authentication
does not infer a remote source IP; those events cannot form recon/auth chains
unless their source is supplied explicitly.
