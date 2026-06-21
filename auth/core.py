import hashlib
import hmac
import os
import secrets
import sqlite3
import string
import time
from dataclasses import dataclass, field
from pathlib import Path

import pyotp
from cryptography.fernet import InvalidToken

from alerts.email_alert import send_security_alert
from logs.logger import get_logger

from .crypto import crypto
from .storage import DB_PATH

# Module-scope logger initialization
logger = get_logger("auth_core")


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


# Backoff Configuration
BACKOFF_BASE_DELAY = int(os.getenv("MFA_BACKOFF_BASE_DELAY_SECONDS", "1"))
BACKOFF_MAX_DELAY = int(os.getenv("MFA_BACKOFF_MAX_DELAY_SECONDS", "60"))
BACKOFF_WINDOW = int(os.getenv("MFA_BACKOFF_WINDOW_SECONDS", "300"))
BACKOFF_ALERT_THRESHOLD = int(os.getenv("MFA_BACKOFF_ALERT_THRESHOLD", "5"))


def _backoff_mode() -> str:
    """Backoff strategy, read at call time so web/CLI contexts can differ.

    'sleep'  (default) — legacy behavior: serialize the caller with time.sleep.
    'reject' — non-blocking: immediately return a RATE_LIMITED AuthEvent.
               Recommended for web workers, where sleeping in the request
               handler enables thread-exhaustion DoS and parallel requests
               bypass the serialized delay anyway.
    """
    return os.getenv("MFA_BACKOFF_MODE", "sleep").strip().lower()


def _enforce_backoff(username: str, user_id: int) -> tuple[int, int, "AuthEvent | None"]:
    """Applies the configured backoff strategy for a user with recent failures.

    Returns (backoff_seconds, failure_count, rejection_event). When
    rejection_event is not None the caller must return it without verifying.
    """
    backoff_seconds, failure_count = _calculate_backoff_delay(user_id)
    if backoff_seconds <= 0:
        return backoff_seconds, failure_count, None

    if _backoff_mode() == "reject":
        return (
            backoff_seconds,
            failure_count,
            _dispatch_event(
                AuthEvent(
                    level="WARNING",
                    event_name="RATE_LIMITED",
                    message=f"Authentication rate limited for user '{username}'.",
                    context=_build_event_context(
                        "RATE_LIMITED", backoff_seconds, failure_count
                    ),
                )
            ),
        )

    time.sleep(backoff_seconds)
    return backoff_seconds, failure_count, None


def _bootstrap_auth_db():
    """Ensures the database schema exists."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        # 1. Load standard schema
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            with open(schema_path, encoding="utf-8") as s:
                conn.executescript(s.read())

        # 2. MIGRATION: Add is_active to existing databases
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='is_active'")
        if cursor.fetchone()[0] == 0:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
            logger.info("Migration applied: added is_active column to users table")
        conn.commit()


def _hash_recovery_code(code: str, salt: bytes = None) -> tuple[str, bytes]:
    """Hashes a recovery code using scrypt with a unique per-code salt."""
    if salt is None:
        salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(code.encode(), salt=salt, n=16384, r=8, p=1)
    return hashed.hex(), salt


def _token_fingerprint(user_id: int, token: str) -> str:
    """Deterministic non-reversible fingerprint for replay detection."""
    return hashlib.sha256(f"{user_id}:{token}".encode()).hexdigest()


def _recovery_fingerprint(user_id: int, code: str) -> str:
    """Deterministic non-reversible fingerprint for recovery code replay detection."""
    return hashlib.sha256(f"recovery:{user_id}:{code}".encode()).hexdigest()


def _calculate_backoff_delay(user_id: int) -> tuple[int, int]:
    """Calculates exponential delay based on recent failed attempts."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) FROM auth_attempts
            WHERE user_id = ? AND success = 0
            AND timestamp > datetime('now', '-' || ? || ' seconds')
        """,
            (user_id, BACKOFF_WINDOW),
        )
        failure_count = cursor.fetchone()[0]

    if failure_count == 0:
        return 0, 0

    delay = BACKOFF_BASE_DELAY * (2**failure_count)
    return min(delay, BACKOFF_MAX_DELAY), failure_count


def _build_event_context(
    reason_code: str, backoff_seconds: int = 0, failure_count: int = 0, extra: dict = None
) -> dict:
    """Helper to ensure consistent forensic telemetry across all return paths."""
    ctx = {"reason_code": reason_code}
    if backoff_seconds > 0:
        ctx["backoff_applied_seconds"] = backoff_seconds
    if failure_count >= BACKOFF_ALERT_THRESHOLD:
        ctx["alert_threshold_exceeded"] = True
    if extra:
        ctx.update(extra)
    return ctx


def _dispatch_event(event: AuthEvent) -> AuthEvent:
    """Routes AuthEvent to L0 (logger) and conditionally to L1 (alerts).
    Returns the event unchanged for caller consumption. Safe and idempotent.
    """
    try:
        # L0: Always log via dynamic level method
        log_method = getattr(logger, event.level.lower(), logger.info)
        log_method(event.message, extra={"context": event.context})

        # L1: Conditionally dispatch to email alerts based on severity/threshold
        if event.level == "CRITICAL" or event.context.get("alert_threshold_exceeded"):
            send_security_alert(
                event_level=event.level,
                module_source=event.module_source,
                alert_message=event.message,
            )
    except Exception as e:
        # Failsafe: dispatch side-effects must never break the auth transaction
        print(f"[FAILSAFE] Auth dispatch failed: {e}")

    return event


def enroll_user(username: str) -> tuple[str, list[str]]:
    """Enrolls a new user into the MFA system."""
    _bootstrap_auth_db()
    raw_secret = pyotp.random_base32()
    encrypted_secret = crypto.encrypt(raw_secret)

    recovery_codes = []
    for _ in range(10):
        code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        recovery_codes.append(code)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise UserAlreadyExistsError(f"User '{username}' already exists.")

        try:
            cursor.execute(
                "INSERT INTO users (username, encrypted_secret) VALUES (?, ?)",
                (username, encrypted_secret),
            )
            user_id = cursor.lastrowid
            for code in recovery_codes:
                hashed, salt = _hash_recovery_code(code)
                cursor.execute(
                    "INSERT INTO recovery_codes (user_id, hashed_code, salt) VALUES (?, ?, ?)",
                    (user_id, hashed, salt),
                )
            conn.commit()
        except sqlite3.IntegrityError as e:
            # The SELECT above is not atomic with the INSERT; a concurrent
            # enrollment of the same username trips the UNIQUE constraint.
            # Surface the domain error rather than a raw DB error so callers
            # handle it identically to the pre-check path.
            conn.rollback()
            raise UserAlreadyExistsError(f"User '{username}' already exists.") from e
        except sqlite3.Error as e:
            conn.rollback()
            raise e

    totp = pyotp.TOTP(raw_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Antigravity-IDS")
    return uri, recovery_codes


def verify_token(username: str, token: str) -> AuthEvent:
    """Verifies a TOTP token with replay protection and anti-enumeration.

    Structured in three phases so that a sleep-mode backoff delay is NEVER
    served while a SQLite connection is held open:
      1. identity resolution (short-lived read connection)
      2. backoff enforcement (opens/closes its own connection, then sleeps)
      3. replay check + verification + attempt record (single write connection)
    """
    _bootstrap_auth_db()

    # Phase 1 — identity resolution.
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, encrypted_secret, is_active FROM users WHERE username = ?", (username,)
        )
        user_row = cursor.fetchone()

    if not user_row:
        return _dispatch_event(
            AuthEvent(
                level="WARNING",
                event_name="AUTH_FAILURE",
                message=f"Authentication failed for user '{username}'.",
                context=_build_event_context("USER_NOT_FOUND"),
            )
        )

    user_id, encrypted_secret, is_active = user_row

    if is_active == 0:
        return _dispatch_event(
            AuthEvent(
                level="WARNING",
                event_name="AUTH_FAILURE",
                message=f"Authentication failed for user '{username}'.",
                context=_build_event_context("USER_REVOKED"),
            )
        )

    # Phase 2 — backoff. No connection is held here, so a sleep-mode delay
    # cannot pin a database handle or block other writers.
    backoff_seconds, failure_count, rejection = _enforce_backoff(username, user_id)
    if rejection is not None:
        return rejection

    # Phase 3 — replay check, cryptographic verification, attempt record.
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        fingerprint = _token_fingerprint(user_id, token)
        cursor.execute(
            """
            SELECT id FROM auth_attempts
            WHERE user_id = ? AND token_fingerprint = ?
            AND timestamp > datetime('now', '-90 seconds')
        """,
            (user_id, fingerprint),
        )

        if cursor.fetchone():
            return _dispatch_event(
                AuthEvent(
                    level="CRITICAL",
                    event_name="REPLAY_ATTACK",
                    message=f"Replay attack detected for user '{username}'.",
                    context=_build_event_context(
                        "TOKEN_REUSED_WINDOW", backoff_seconds, failure_count
                    ),
                )
            )

        try:
            raw_secret = crypto.decrypt(encrypted_secret)
            totp = pyotp.TOTP(raw_secret)
            is_valid = totp.verify(token, valid_window=1)
        except InvalidToken:
            return _dispatch_event(
                AuthEvent(
                    level="CRITICAL",
                    event_name="CRYPTO_ERROR",
                    message=f"Secret decryption failed for user '{username}'.",
                    context=_build_event_context(
                        "fernet_invalid_token", backoff_seconds, failure_count
                    ),
                )
            )
        except Exception as e:
            extra = {"exception_type": type(e).__name__, "exception_repr": repr(e)}
            return _dispatch_event(
                AuthEvent(
                    level="ERROR",
                    event_name="SYSTEM_ERROR",
                    message=f"Internal authentication error for user '{username}'.",
                    context=_build_event_context(
                        "unknown_crypto_error", backoff_seconds, failure_count, extra
                    ),
                )
            )

        try:
            cursor.execute(
                "INSERT INTO auth_attempts (user_id, success, token_fingerprint) VALUES (?, ?, ?)",
                (user_id, 1 if is_valid else 0, fingerprint),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return _dispatch_event(
                AuthEvent(
                    level="CRITICAL",
                    event_name="REPLAY_ATTACK",
                    message=f"Replay attack detected for user '{username}'.",
                    context=_build_event_context(
                        "TOKEN_REUSED_RACE_CONDITION", backoff_seconds, failure_count
                    ),
                )
            )

        if is_valid:
            return _dispatch_event(
                AuthEvent(
                    level="INFO",
                    event_name="AUTH_SUCCESS",
                    message=f"User '{username}' authenticated successfully.",
                    context=_build_event_context("VALID_TOKEN", backoff_seconds, failure_count),
                )
            )

        return _dispatch_event(
            AuthEvent(
                level="WARNING",
                event_name="AUTH_FAILURE",
                message=f"Authentication failed for user '{username}'.",
                context=_build_event_context("INVALID_TOKEN", backoff_seconds, failure_count),
            )
        )


def use_recovery_code(username: str, code: str) -> AuthEvent:
    """Validates and consumes a one-time recovery code from the user's stored set.

    Phased identically to verify_token so the backoff sleep never holds a
    database connection (see verify_token for the rationale).
    """
    _bootstrap_auth_db()

    # Phase 1 — identity resolution.
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, is_active FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()

    if not user_row:
        return _dispatch_event(
            AuthEvent(
                level="WARNING",
                event_name="AUTH_FAILURE",
                message=f"Authentication failed for user '{username}'.",
                context=_build_event_context("USER_NOT_FOUND"),
            )
        )

    user_id, is_active = user_row

    if is_active == 0:
        return _dispatch_event(
            AuthEvent(
                level="WARNING",
                event_name="AUTH_FAILURE",
                message=f"Authentication failed for user '{username}'.",
                context=_build_event_context("USER_REVOKED"),
            )
        )

    # Phase 2 — backoff (no connection held).
    backoff_seconds, failure_count, rejection = _enforce_backoff(username, user_id)
    if rejection is not None:
        return rejection

    # Phase 3 — replay check, code match, single-use consumption.
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        fingerprint = _recovery_fingerprint(user_id, code)
        cursor.execute(
            """
            SELECT id FROM auth_attempts
            WHERE user_id = ? AND token_fingerprint = ?
            AND timestamp > datetime('now', '-90 seconds')
        """,
            (user_id, fingerprint),
        )

        if cursor.fetchone():
            return _dispatch_event(
                AuthEvent(
                    level="CRITICAL",
                    event_name="REPLAY_ATTACK",
                    message=f"Replay attack detected for user '{username}'.",
                    context=_build_event_context(
                        "TOKEN_REUSED_WINDOW", backoff_seconds, failure_count
                    ),
                )
            )

        cursor.execute(
            "SELECT id, hashed_code, salt FROM recovery_codes WHERE user_id = ?", (user_id,)
        )
        recovery_codes = cursor.fetchall()

        matched_code_id = None
        for row_id, stored_hash, salt in recovery_codes:
            computed_hash, _ = _hash_recovery_code(code, salt)
            if hmac.compare_digest(computed_hash, stored_hash):
                matched_code_id = row_id
                break

        try:
            if matched_code_id:
                cursor.execute("DELETE FROM recovery_codes WHERE id = ?", (matched_code_id,))
                cursor.execute(
                    """
                    INSERT INTO auth_attempts (user_id, success, token_fingerprint)
                    VALUES (?, 1, ?)
                """,
                    (user_id, fingerprint),
                )
                conn.commit()
                return _dispatch_event(
                    AuthEvent(
                        level="INFO",
                        event_name="AUTH_SUCCESS",
                        message=f"User '{username}' authenticated successfully.",
                        context=_build_event_context(
                            "VALID_RECOVERY_CODE", backoff_seconds, failure_count
                        ),
                    )
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO auth_attempts (user_id, success, token_fingerprint)
                    VALUES (?, 0, ?)
                """,
                    (user_id, fingerprint),
                )
                conn.commit()
                return _dispatch_event(
                    AuthEvent(
                        level="WARNING",
                        event_name="AUTH_FAILURE",
                        message=f"Authentication failed for user '{username}'.",
                        context=_build_event_context(
                            "INVALID_RECOVERY_CODE", backoff_seconds, failure_count
                        ),
                    )
                )

        except sqlite3.IntegrityError:
            conn.rollback()
            return _dispatch_event(
                AuthEvent(
                    level="CRITICAL",
                    event_name="REPLAY_ATTACK",
                    message=f"Replay attack detected for user '{username}'.",
                    context=_build_event_context(
                        "TOKEN_REUSED_RACE_CONDITION", backoff_seconds, failure_count
                    ),
                )
            )


def revoke_user(username: str) -> tuple[bool, str]:
    """Soft-delete a user. Returns (success, message_code)."""
    _bootstrap_auth_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id, is_active FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()

        if not row:
            return False, "not_found"

        user_id, is_active = row
        if is_active == 0:
            return False, "already_revoked"

        cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        conn.commit()

        _dispatch_event(
            AuthEvent(
                level="WARNING",
                event_name="USER_REVOKED",
                message=f"User '{username}' revoked (soft-deleted).",
                context=_build_event_context("USER_REVOKED", extra={"user_id": user_id}),
            )
        )
        return True, "success"


def get_user_role(username: str) -> str | None:
    """Returns the role of an active user, or None if unknown/revoked.

    RBAC read path over the existing users.role column ('analyst' default,
    'admin' grants administrative views in the dashboard).
    """
    _bootstrap_auth_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT role FROM users WHERE username = ? AND is_active = 1", (username,)
        )
        row = cursor.fetchone()
        return row[0] if row else None


def set_user_role(username: str, role: str) -> bool:
    """Assigns a role to an existing user. Returns False if user not found."""
    valid_roles = {"analyst", "admin", "viewer"}
    if role not in valid_roles:
        raise ValueError(f"Invalid role '{role}'. Valid roles: {sorted(valid_roles)}")

    _bootstrap_auth_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        conn.commit()
        if cursor.rowcount == 0:
            return False

    _dispatch_event(
        AuthEvent(
            level="INFO",
            event_name="ROLE_CHANGED",
            message=f"Role for user '{username}' set to '{role}'.",
            context=_build_event_context("ROLE_CHANGED", extra={"new_role": role}),
        )
    )
    return True


def list_users() -> list[dict]:
    """Returns list of enrolled users with their metadata."""
    _bootstrap_auth_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, created_at, role, is_active
            FROM users
            ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()
        return [
            {"username": r[0], "created_at": r[1], "role": r[2], "is_active": r[3]} for r in rows
        ]
