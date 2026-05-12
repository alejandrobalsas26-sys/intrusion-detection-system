import sqlite3
import pyotp
import hashlib
import secrets
import string
from typing import List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from .storage import DB_PATH
from .crypto import crypto

@dataclass
class AuthEvent:
    """Dataclass para telemetría de autenticación (Sibling de DetectionEvent)"""
    level: str
    event_name: str
    message: str
    module_source: str = "auth"
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    context: dict = field(default_factory=dict)

class UserAlreadyExistsError(Exception):
    pass

def _hash_recovery_code(code: str) -> str:
    """Hashes a recovery code using scrypt (built-in, memory-hard)."""
    salt = b"ids_mfa_salt_fixed" # In production, use unique per-code salts
    # n=16384 (CPU/mem cost), r=8 (block size), p=1 (parallelization)
    hashed = hashlib.scrypt(code.encode(), salt=salt, n=16384, r=8, p=1)
    return hashed.hex()

def enroll_user(username: str) -> Tuple[str, List[str]]:
    """
    Enrolls a new user into the MFA system.
    Returns: (provisioning_uri, plain_recovery_codes)
    Raises: UserAlreadyExistsError if username is taken.
    """
    # 1. Generate TOTP Secret and Encrypt it
    raw_secret = pyotp.random_base32()
    encrypted_secret = crypto.encrypt(raw_secret)
    
    # 2. Generate 10 Plain Recovery Codes
    recovery_codes = []
    for _ in range(10):
        # 8-character random alphanumeric string
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        recovery_codes.append(code)

    # 3. Database Transaction
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Check if user exists (Defensive Guard)
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise UserAlreadyExistsError(f"User '{username}' already exists.")

        try:
            # Insert User
            cursor.execute(
                "INSERT INTO users (username, encrypted_secret) VALUES (?, ?)",
                (username, encrypted_secret)
            )
            user_id = cursor.lastrowid

            # Insert Hashed Recovery Codes
            for code in recovery_codes:
                hashed = _hash_recovery_code(code)
                cursor.execute(
                    "INSERT INTO recovery_codes (user_id, hashed_code) VALUES (?, ?)",
                    (user_id, hashed)
                )
            
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            raise e

    # 4. Generate TOTP URI for Authenticator Apps
    totp = pyotp.TOTP(raw_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="Antigravity-IDS")
    
    return uri, recovery_codes

def verify_token(username: str, token: str) -> AuthEvent:
    """Stub: Verifica la validez de un token TOTP y aplica políticas de seguridad."""
    raise NotImplementedError("Implemented in commit #2")

def use_recovery_code(username: str, code: str) -> AuthEvent:
    """Stub: Valida y consume un código de recuperación de un solo uso."""
    raise NotImplementedError("Implemented in commit #4")
    