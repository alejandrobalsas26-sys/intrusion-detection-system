import sqlite3
import pyotp
import hashlib
import secrets
import string
import time
import os
from typing import List, Tuple
from dataclasses import dataclass, field
from cryptography.fernet import InvalidToken
from .storage import DB_PATH
from .crypto import crypto

@dataclass
class AuthEvent:
    """Dataclass for authentication telemetry (sibling of DetectionEvent)."""
    level: str
    event_name: str
    message: str
    module_source: str = "auth"
    timestamp: float = field(default_factory=time.time)
    context: dict = field(default_factory=dict)

class UserAlreadyExistsError(Exception):
    pass

# Backoff Configuration (12-Factor App Compliance)
BACKOFF_BASE_DELAY = int(os.getenv("MFA_BACKOFF_BASE_DELAY_SECONDS", "1"))
BACKOFF_MAX_DELAY = int(os.getenv("MFA_BACKOFF_MAX_DELAY_SECONDS", "60"))
BACKOFF_WINDOW = int(os.getenv("MFA_BACKOFF_WINDOW_SECONDS", "300"))
BACKOFF_ALERT_THRESHOLD = int(os.getenv("MFA_BACKOFF_ALERT_THRESHOLD", "5"))

def _bootstrap_auth_db():
    """Ensures the database schema exists."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    if not os.path.exists(schema_path):
        return
    with sqlite3.connect(DB_PATH) as conn:
        with open(schema_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())

def _hash_recovery_code(code: str, salt: bytes = None) -> Tuple[str, bytes]:
    """Hashes a recovery code using scrypt with a unique per-code salt."""
    if salt is None:
        salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(code.encode(), salt=salt, n=16384, r=8, p=1)
    return hashed.hex(), salt

def _token_fingerprint(user_id: int, token: str) -> str:
    """Deterministic non-reversible fingerprint for replay detection."""
    return hashlib.sha256(f"{user_id}:{token}".encode()).hexdigest()

def _calculate_backoff_delay(user_id: int) -> Tuple[int, int]:
    """Calculates exponential delay based on recent failed attempts."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM auth_attempts 
            WHERE user_id = ? AND success = 0 
            AND timestamp > datetime('now', '-' || ? || ' seconds')
        """, (user_id, BACKOFF_WINDOW))
        failure_count = cursor.fetchone()[0]

    if failure_count == 0:
        return 0, 0

    delay = BACKOFF_BASE_DELAY * (2 ** failure_count)
    return min(delay, BACKOFF_MAX_DELAY), failure_count

def _build_event_context(reason_code: str, backoff_seconds: int = 0, failure_count: int = 0, extra: dict = None) -> dict:
    """Helper to ensure consistent forensic telemetry across all return paths."""
    ctx = {"reason_code": reason_code}
    if backoff_seconds > 0:
        ctx["backoff_applied_seconds"] = backoff_seconds
    if failure_count >= BACKOFF_ALERT_THRESHOLD:
        ctx["alert_threshold_exceeded"] = True
    if extra:
        ctx.update(extra)
    return ctx

def enroll_user(username: str) -> Tuple[str, List[str]]:
    """Enrolls a new user into the MFA system."""
    _bootstrap_auth_db()
    raw_secret = pyotp.random_base32()
    encrypted_secret = crypto.encrypt(raw_secret)
    
    recovery_codes = []
    for _ in range(10):
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        recovery_codes.append(code)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise UserAlreadyExistsError(f"User '{username}' already exists.")

        try:
            cursor.execute(
                "INSERT INTO users (username, encrypted_secret) VALUES (?, ?)",
                (username, encrypted_secret)
            )
            user_id = cursor.lastrowid
            for code in recovery_codes:
                hashed, salt = _hash_recovery_code(code)
                cursor.execute(
                    "INSERT INTO recovery_codes (user_id, hashed_code, salt) VALUES (?, ?, ?)",
                    (user_id, hashed, salt)
                )
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            raise e

    totp = pyotp.TOTP(raw_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Antigravity-IDS")
    return uri, recovery_codes

def verify_token(username: str, token: str) -> AuthEvent:
    """Verifies a TOTP token with replay protection and anti-enumeration."""
    _bootstrap_auth_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # 1. Fetch User Data
        cursor.execute("SELECT id, encrypted_secret FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return AuthEvent(level="WARNING", event_name="AUTH_FAILURE", 
                             message=f"Authentication failed for user '{username}'.",
                             context=_build_event_context("USER_NOT_FOUND"))
        
        user_id, encrypted_secret = user_row

        # 2. Rate Limiting (Exponential Backoff)
        backoff_seconds, failure_count = _calculate_backoff_delay(user_id)
        if backoff_seconds > 0:
            time.sleep(backoff_seconds)

        # 3. Replay Protection
        fingerprint = _token_fingerprint(user_id, token)
        cursor.execute("""
            SELECT id FROM auth_attempts 
            WHERE user_id = ? AND token_fingerprint = ? 
            AND timestamp > datetime('now', '-90 seconds')
        """, (user_id, fingerprint))
        
        if cursor.fetchone():
            return AuthEvent(level="CRITICAL", event_name="REPLAY_ATTACK", 
                             message=f"Replay attack detected for user '{username}'.",
                             context=_build_event_context("TOKEN_REUSED_WINDOW", backoff_seconds, failure_count))

        # 4. Decrypt and Verify Token
        try:
            raw_secret = crypto.decrypt(encrypted_secret)
            totp = pyotp.TOTP(raw_secret)
            is_valid = totp.verify(token, valid_window=1)
        except InvalidToken:
            return AuthEvent(level="CRITICAL", event_name="CRYPTO_ERROR", 
                             message=f"Secret decryption failed for user '{username}'.",
                             context=_build_event_context("fernet_invalid_token", backoff_seconds, failure_count))
        except Exception as e:
            extra = {"exception_type": type(e).__name__, "exception_repr": repr(e)}
            return AuthEvent(level="ERROR", event_name="SYSTEM_ERROR", 
                             message=f"Internal authentication error for user '{username}'.",
                             context=_build_event_context("unknown_crypto_error", backoff_seconds, failure_count, extra))

        # 5. Record Attempt and catch Race Conditions
        try:
            cursor.execute("""
                INSERT INTO auth_attempts (user_id, success, token_fingerprint)
                VALUES (?, ?, ?)
            """, (user_id, 1 if is_valid else 0, fingerprint))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return AuthEvent(level="CRITICAL", event_name="REPLAY_ATTACK", 
                             message=f"Replay attack detected for user '{username}'.",
                             context=_build_event_context("TOKEN_REUSED_RACE_CONDITION", backoff_seconds, failure_count))

        # 6. Result Dispatch
        if is_valid:
            return AuthEvent(level="INFO", event_name="AUTH_SUCCESS", 
                             message=f"User '{username}' authenticated successfully.",
                             context=_build_event_context("VALID_TOKEN", backoff_seconds, failure_count))
        
        return AuthEvent(level="WARNING", event_name="AUTH_FAILURE", 
                         message=f"Authentication failed for user '{username}'.",
                         context=_build_event_context("INVALID_TOKEN", backoff_seconds, failure_count))

def use_recovery_code(username: str, code: str) -> AuthEvent:
    """Validates and consumes a one-time recovery code (commit #4)."""
    raise NotImplementedError("Implemented in commit #4")
