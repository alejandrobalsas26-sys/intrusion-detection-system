# Module: Auth (Layer 7 - Identity)

## Security Model
This module implements TOTP authentication using one possession factor (username is an identifier,
not a second authentication factor):
- **TOTP (RFC 6238):** Time-based One-Time Passwords.
- **Fernet (AES-128-CBC + HMAC):** Symmetric encryption for secrets at rest.
- **Scrypt:** High-cost hashing for recovery codes.

## Intent
To ensure that only authorized analysts can access the IDS orchestrator and forensic logs, preventing unauthorized lateral movement within the detection system.

## Configuration
Configure in `.env`:
```ini
# Generate key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MFA_ENCRYPTION_KEY=your_fernet_key_here
MFA_BACKOFF_ALERT_THRESHOLD=5
# One-time recovery codes issued per enrollment (default 10, clamped to 1..50)
MFA_RECOVERY_CODES_COUNT=10
```

## Usage
The module exposes plain functions (`auth.core`) that handle:
- **Registration:** `enroll_user` — adds new analysts (generates encrypted TOTP secrets and scrypt-hashed recovery codes).
- **Login:** `verify_token` — verifies TOTP codes and handles rate-limiting (backoff).
- **Recovery:** `use_recovery_code` — consumes a backup code when TOTP is unavailable.

## Security Analysis
- **Identity:** Validates the human operator.
- **Confidentiality:** TOTP keys are encrypted at rest; recovery codes are salted and hashed.
- **Integrity:** TOTP replay is prevented by atomically consuming each verified
  `(user_id, time_step)` in `totp_consumptions`. Telemetry fingerprints are
  searchable but never globally unique; numeric codes can repeat later.

## Verification Policy & Rate Limiting (Branch 3B)

The authentication verification flow enforces strict defense-in-depth mechanisms against brute-force, replay, and side-channel attacks.

### Security Guarantees
* **Anti-Enumeration:** Both invalid users and invalid tokens return identical `AUTH_FAILURE` responses. The exact cause is stored safely in the internal `reason_code` context for SOC analysts.
* **Replay Protection:** TOTP accepts the current 30-second interval and its immediate neighbors; each verified interval is consumed once atomically. Invalid attempts do not consume an interval. Recovery codes use atomic deletion with a checked row count; concurrent requests cannot both succeed. Recent successful legacy TOTP fingerprints remain protected for 90 seconds during migration.
* **Constant-Time Comparison:** Recovery codes are hashed using `scrypt` with a per-code unique salt. Comparisons are strictly executed via `hmac.compare_digest` to mitigate timing side-channel attacks.

### Exponential Backoff (Rate Limiting)
Brute-force attempts against an identity (whether via TOTP or Recovery Codes) share the same rate-limiting state.

* **Calculation:** Delay = `BASE_DELAY * (2 ^ failure_count)`, capped at the maximum.
* **Reject mode:** Retry is allowed once the latest failure timestamp plus that
  delay has elapsed; the failure-count window does not become the lockout duration.
  Rejected requests do not extend the cooldown. Sleep mode retains the CLI delay.
* **Configuration variables (12-Factor compliant):**
  * `MFA_BACKOFF_BASE_DELAY_SECONDS` (Default: 1s)
  * `MFA_BACKOFF_MAX_DELAY_SECONDS` (Default: 60s)
  * `MFA_BACKOFF_WINDOW_SECONDS` (Default: 300s)
  * `MFA_BACKOFF_ALERT_THRESHOLD` (Default: 5 attempts)

### Event Dispatching (L0 & L1)
Verification yields an `AuthEvent` which is routed via a central dispatch helper:
* **L0 (Logging):** All events are logged locally via `get_logger("auth_core")`.
* **L1 (Alerting):** `CRITICAL` events (e.g., Replay Attacks, Crypto Errors) or brute-force threshold breaches trigger an immediate email dispatch via `send_security_alert`. The dispatch acts as a safe side-effect and will not halt the authentication transaction if the SMTP server is unreachable.

## Administrative CLI (auth-cli)

### Overview
The `auth-cli` provides administrative controls for managing the TOTP authentication lifecycle of SOC analysts. It operates on a **Root-Trust Model**, assuming that any user capable of executing the CLI on the host machine possesses the necessary administrative privileges.

### Invocation
Execute the CLI module directly via Python:
```bash
python -m auth.cli <command>
```

### Available Subcommands

#### 1. `enroll <username>`
Provisions a new user in the system.
* **Outputs:**
  * A terminal-rendered ASCII QR Code.
  * A standard `otpauth://` provisioning URI.
  * Single-use recovery codes (`MFA_RECOVERY_CODES_COUNT`, default 10).
* **Security Note:** The recovery codes are displayed only once. They must be saved securely by the administrator or the provisioned analyst immediately.

#### 2. `revoke <username>`
Performs a soft-delete on an existing user.
* Sets `is_active = 0` in the database, preserving the user's forensic footprint in the `auth_attempts` log.
* Any future authentication attempts by a revoked user will fail immediately.

#### 3. `list`
Displays a tabulated overview of all users.
* **Columns:** Username, Created At, Role, Status (`Active` / `Revoked`).
* Sorted by most recently created.

#### 4. `set-role <username> <role>`
Assigns an RBAC role to an existing user.
* Valid roles: `analyst` (default at enrollment), `admin`, `viewer`.
* The dashboard rechecks the active user and current database role on each
  protected request, including admin-only endpoints such as `/api/users`.

### Tech Debt & Future Considerations
* **Structured Auditing:** Currently, CLI actions use standard logging (e.g., `logger.info`). In future iterations (Dashboard wiring), these will be refactored to emit standardized `AuthEvent` objects for L1 alerts.

### Implementation Status
- [x] Branch 3A: Cryptographic Primitives & Storage
- [x] Branch 3B: Authentication Core & Defenses
- [x] Branch 3C: Administrative CLI Tooling
