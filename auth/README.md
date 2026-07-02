# Module: Auth (Layer 7 - Identity)

## Security Model
This module implements a hardened Multi-Factor Authentication (MFA) gateway using:
- **TOTP (RFC 6238):** Time-based One-Time Passwords.
- **AES-256 (Fernet):** Symmetric encryption for secrets at rest.
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
- **Registration:** `enroll_user` — adds new analysts (generates TOTP secrets and encrypted recovery codes).
- **Login:** `verify_token` — verifies TOTP codes and handles rate-limiting (backoff).
- **Recovery:** `use_recovery_code` — consumes a backup code when TOTP is unavailable.

## Security Analysis
- **Identity:** Validates the human operator.
- **Confidentiality:** Secrets (TOTP keys, recovery codes) are encrypted at rest.
- **Integrity:** Replay attacks are prevented by a deterministic SHA-256 token
  fingerprint logged in `auth_attempts`, with a 90-second reuse window and a
  `UNIQUE INDEX` as the concurrency backstop (see Replay Protection below).

## Verification Policy & Rate Limiting (Branch 3B)

The authentication verification flow enforces strict defense-in-depth mechanisms against brute-force, replay, and side-channel attacks.

### Security Guarantees
* **Anti-Enumeration:** Both invalid users and invalid tokens return identical `AUTH_FAILURE` responses. The exact cause is stored safely in the internal `reason_code` context for SOC analysts.
* **Replay Protection:** A 90-second deterministic fingerprint window (`_token_fingerprint` and `_recovery_fingerprint`) prevents token reuse. Handled atomically via SQLite `UNIQUE INDEX` to prevent concurrent race conditions.
* **Constant-Time Comparison:** Recovery codes are hashed using `scrypt` with a per-code unique salt. Comparisons are strictly executed via `hmac.compare_digest` to mitigate timing side-channel attacks.

### Exponential Backoff (Rate Limiting)
Brute-force attempts against an identity (whether via TOTP or Recovery Codes) share the same rate-limiting state.

* **Calculation:** Delay = `BASE_DELAY * (2 ^ failure_count)`
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
The `auth-cli` provides administrative controls for managing the Multi-Factor Authentication (MFA) lifecycle of SOC analysts. It operates on a **Root-Trust Model**, assuming that any user capable of executing the CLI on the host machine possesses the necessary administrative privileges.

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
* The dashboard binds the role into the session at login and gates
  admin-only endpoints (e.g. `/api/users`) with it.

### Tech Debt & Future Considerations
* **Structured Auditing:** Currently, CLI actions use standard logging (e.g., `logger.info`). In future iterations (Dashboard wiring), these will be refactored to emit standardized `AuthEvent` objects for L1 alerts.

### Implementation Status
- [x] Branch 3A: Cryptographic Primitives & Storage
- [x] Branch 3B: Authentication Core & Defenses
- [x] Branch 3C: Administrative CLI Tooling
