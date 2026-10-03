import hashlib
import hmac
import math
import os
import secrets
import socket
import sqlite3
import string
import time
from contextlib import closing
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

DEFAULT_RECOVERY_CODES_COUNT = 10


def _recovery_codes_count() -> int:
    """One-time recovery codes issued per enrollment (MFA_RECOVERY_CODES_COUNT).

    Read at call time (like _backoff_mode) rather than at import. A non-numeric
    value falls back to the default; the result is clamped to 1..50 so a typo
    can neither disable recovery entirely nor flood the users' code sets.
    """
    try:
        count = int(os.getenv("MFA_RECOVERY_CODES_COUNT", str(DEFAULT_RECOVERY_CODES_COUNT)))
    except ValueError:
        return DEFAULT_RECOVERY_CODES_COUNT
    return max(1, min(count, 50))


def _backoff_mode() -> str:
    """Backoff strategy, read at call time so web/CLI contexts can differ.

    'sleep'  (default) — legacy behavior: serialize the caller with time.sleep.
    'reject' — non-blocking: immediately return a RATE_LIMITED AuthEvent.
               Recommended for web workers, where sleeping in the request
               handler enables thread-exhaustion DoS and parallel requests
               bypass the serialized delay anyway.
    """
    return os.getenv("MFA_BACKOFF_MODE", "sleep").strip().lower()


def _enforce_backoff(
    username: str, user_id: int, context: dict | None = None
) -> tuple[int, int, "AuthEvent | None"]:
    """Applies the configured backoff strategy for a user with recent failures.

    Returns (backoff_seconds, failure_count, rejection_event). When
    rejection_event is not None the caller must return it without verifying.
    """
    backoff_seconds, failure_count = _calculate_backoff_delay(user_id)
    if backoff_seconds <= 0:
        return backoff_seconds, failure_count, None

    if _backoff_mode() == "reject":
        with closing(sqlite3.connect(DB_PATH)) as conn:
            last_failure = conn.execute(
                "SELECT MAX(CAST(strftime('%s', timestamp) AS REAL)) "
                "FROM auth_attempts WHERE user_id = ? AND success = 0",
                (user_id,),
            ).fetchone()[0]
        remaining = (last_failure or 0) + backoff_seconds - time.time()
        if remaining <= 0:
            return 0, failure_count, None
        backoff_seconds = math.ceil(remaining)
        return (
            backoff_seconds,
            failure_count,
            _dispatch_event(
                AuthEvent(
                    level="WARNING",
                    event_name="RATE_LIMITED",
                    message=f"Authentication rate limited for user '{username}'.",
                    context=_build_event_context(
                        "RATE_LIMITED", backoff_seconds, failure_count, context
                    ),
                )
            ),
        )

    time.sleep(backoff_seconds)
    return backoff_seconds, failure_count, None


def _bootstrap_auth_db():
    """Ensures the database schema exists."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        # 1. Load standard schema
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            with open(schema_path, encoding="utf-8") as s:
                conn.executescript(s.read())

        # 2. MIGRATION: Add is_active to existing databases
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='is_active'")
        if cursor.fetchone()[0] == 0:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
        cursor.execute(
            "SELECT COUNT(*) FROM pragma_table_info('auth_attempts') WHERE name='totp_step'"
        )
        if cursor.fetchone()[0] == 0:
            cursor.execute("ALTER TABLE auth_attempts ADD COLUMN totp_step INTEGER")
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
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
    event.context.setdefault("host_id", socket.gethostname())
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
    for _ in range(_recovery_codes_count()):
        code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        recovery_codes.append(code)

    with closing(sqlite3.connect(DB_PATH)) as conn:
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


def verify_token(username: str, token: str, *, source_ip: str | None = None) -> AuthEvent:
    """Consume a verified TOTP interval atomically; never reserve invalid codes."""
    _bootstrap_auth_db()

    def emit(name, level, reason, backoff=0, failures=0, extra=None):
        context = {"username": username}
        if source_ip:
            context["source_ip"] = source_ip
        context.update(extra or {})
        messages = {
            "AUTH_SUCCESS": f"User '{username}' authenticated successfully.",
            "REPLAY_ATTACK": f"Replay attack detected for user '{username}'.",
            "CRYPTO_ERROR": f"Secret decryption failed for user '{username}'.",
            "SYSTEM_ERROR": f"Internal authentication error for user '{username}'.",
        }
        return _dispatch_event(
            AuthEvent(
                level=level,
                event_name=name,
                message=messages.get(name, f"Authentication failed for user '{username}'."),
                context=_build_event_context(reason, backoff, failures, context),
            )
        )

    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT id, encrypted_secret, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if not row:
        return emit("AUTH_FAILURE", "WARNING", "USER_NOT_FOUND")
    user_id, encrypted_secret, active = row
    if not active:
        return emit("AUTH_FAILURE", "WARNING", "USER_REVOKED")

    backoff, failures, rejection = _enforce_backoff(
        username, user_id, {"username": username, "source_ip": source_ip}
    )
    if rejection is not None:
        return rejection
    now = time.time()
    fingerprint = _token_fingerprint(user_id, token)
    try:
        totp = pyotp.TOTP(crypto.decrypt(encrypted_secret))
        current_step = int(now // totp.interval)
        step = next(
            (
                counter
                for counter in (current_step, current_step - 1, current_step + 1)
                if counter >= 0
                and hmac.compare_digest(str(token), totp.at(counter * totp.interval))
            ),
            None,
        )
    except InvalidToken:
        return emit("CRYPTO_ERROR", "CRITICAL", "fernet_invalid_token", backoff, failures)
    except Exception as exc:
        return emit(
            "SYSTEM_ERROR",
            "ERROR",
            "unknown_crypto_error",
            backoff,
            failures,
            {"exception_type": type(exc).__name__},
        )

    replay = None
    with closing(sqlite3.connect(DB_PATH)) as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute("SELECT is_active FROM users WHERE id = ?", (user_id,)).fetchone()
            if not active or not active[0]:
                conn.rollback()
                return emit("AUTH_FAILURE", "WARNING", "USER_REVOKED", backoff, failures)
            # Compatibility with successful attempts recorded just before migration.
            legacy = (
                conn.execute(
                    "SELECT 1 FROM auth_attempts WHERE user_id = ? AND success = 1 "
                    "AND token_fingerprint = ? AND totp_step IS NULL "
                    "AND timestamp > datetime('now', '-90 seconds') LIMIT 1",
                    (user_id, fingerprint),
                ).fetchone()
                if step is not None
                else None
            )
            consumed = (
                conn.execute(
                    "SELECT 1 FROM totp_consumptions WHERE user_id = ? AND time_step = ?",
                    (user_id, step),
                ).fetchone()
                if step is not None
                else None
            )
            if legacy or consumed:
                replay = "TOKEN_REUSED_WINDOW"
                conn.rollback()
            else:
                if step is not None:
                    conn.execute(
                        "INSERT INTO totp_consumptions (user_id, time_step, consumed_at) "
                        "VALUES (?, ?, ?)",
                        (user_id, step, now),
                    )
                conn.execute(
                    "INSERT INTO auth_attempts (user_id, success, token_fingerprint, totp_step) "
                    "VALUES (?, ?, ?, ?)",
                    (user_id, int(step is not None), fingerprint, step),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            replay = "TOKEN_REUSED_RACE_CONDITION"
    if replay:
        return emit("REPLAY_ATTACK", "CRITICAL", replay, backoff, failures)
    if step is not None:
        return emit("AUTH_SUCCESS", "INFO", "VALID_TOKEN", backoff, failures)
    return emit("AUTH_FAILURE", "WARNING", "INVALID_TOKEN", backoff, failures)


def use_recovery_code(username: str, code: str) -> AuthEvent:
    """Validates and consumes a one-time recovery code from the user's stored set.

    Phased identically to verify_token so the backoff sleep never holds a
    database connection (see verify_token for the rationale).
    """
    _bootstrap_auth_db()

    # Phase 1 — identity resolution.
    with closing(sqlite3.connect(DB_PATH)) as conn:
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
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
                if cursor.rowcount != 1:
                    raise sqlite3.IntegrityError("Recovery code already consumed")
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = ? AND is_active = 1", (username,))
        row = cursor.fetchone()
        return row[0] if row else None


def set_user_role(username: str, role: str) -> bool:
    """Assigns a role to an existing user. Returns False if user not found."""
    valid_roles = {"analyst", "admin", "viewer"}
    if role not in valid_roles:
        raise ValueError(f"Invalid role '{role}'. Valid roles: {sorted(valid_roles)}")

    _bootstrap_auth_db()
    with closing(sqlite3.connect(DB_PATH)) as conn:
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
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
