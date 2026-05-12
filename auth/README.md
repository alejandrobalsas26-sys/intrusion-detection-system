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
MFA_BACKOFF_THRESHOLD=5
MFA_RECOVERY_CODES_COUNT=10
```

## Usage
The module provides an `AuthManager` to handle:
- **Registration:** Adding new analysts (generates TOTP secrets and encrypted recovery codes).
- **Login:** Verifying TOTP codes and handling rate-limiting (backoff).
- **Recovery:** Using backup codes when TOTP is unavailable.

## Security Analysis
- **Identity:** Validates the human operator.
- **Confidentiality:** Secrets (TOTP keys, recovery codes) are encrypted at rest.
- **Integrity:** The `token_blacklist` prevents replay attacks.

