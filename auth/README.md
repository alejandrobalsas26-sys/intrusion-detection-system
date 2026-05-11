# L7: Authentication & MFA Domain Core

## Overview
This module handles the Identity Perimeter of the IDS. It implements a Time-based One-Time Password (TOTP) system according to RFC 6238, providing a Layer 7 security gate for administrative actions and system access.

## Threat Model

| Threat Vector | Status | Mitigation Strategy |
| :--- | :--- | :--- |
| **Credential Stuffing** | ✅ Defended | MFA token requirement invalidates stolen passwords. |
| **Brute Force (MFA)** | ✅ Defended | Exponential backoff policy in `verify_token`. |
| **Replay Attacks** | ✅ Defended | Strict single-use token enforcement (90s window). |
| **SIM Swapping** | ✅ Defended | App-based TOTP eliminates SMS dependency. |
| **Recovery Code Guessing** | ✅ Defended | Hashed storage using `hashlib.scrypt` (GPU-resistant). |
| **Phishing (Real-time)** | ⚠️ Limited | TOTP does not bind to TLS. FIDO2 recommended for v2. |
| **Server Compromise** | ⚠️ Limited | Secrets encrypted with Fernet (KEK). Risk if .env is stolen. |

## Security Implementation Details

### Encryption at Rest (Fernet)
TOTP shared secrets are never stored in plaintext. They are encrypted using **Fernet (AES-128 in CBC mode with HMAC-SHA256)**. 
- **KEK:** Loaded from `MFA_ENCRYPTION_KEY`.
- **Limitation:** KEK rotation is not automated in v1. Compromise requires full re-enrollment.

### Recovery Codes (Scrypt)
Backup codes are stored as one-way hashes.
- **Algorithm:** `hashlib.scrypt`.
- **Performance Note:** Verifying a recovery code is intentionally CPU/Memory intensive to prevent hardware-accelerated cracking. A delay of ~0.5s - 1.0s is expected and constitutes a security feature.

## User Lifecycle
1. **Enrollment:** Generates a new random secret and 10 recovery codes. Returns a provisioning URI for Google Authenticator/Authy.
2. **Verification:** Validates the 6-digit pin against the sliding window.
3. **Recovery:** Allows access via a one-time backup code if the primary device is lost.