import sqlite3
import unittest

import pyotp

from auth.core import _bootstrap_auth_db, enroll_user, revoke_user, use_recovery_code, verify_token
from auth.crypto import crypto
from auth.storage import DB_PATH


class TestRevocationEnforcement(unittest.TestCase):
    def setUp(self):
        """Clean the database before each test to guarantee isolation."""
        _bootstrap_auth_db()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM auth_attempts")
            conn.execute("DELETE FROM recovery_codes")
            conn.execute("DELETE FROM users")
            conn.commit()

    def test_verify_token_revoked_user_fails(self):
        # 1. Enroll user
        _, _ = enroll_user("revoked_user_totp")

        # 2. Extract raw secret to generate a valid token
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT encrypted_secret FROM users WHERE username = 'revoked_user_totp'"
            )
            encrypted_secret = cursor.fetchone()[0]

        raw_secret = crypto.decrypt(encrypted_secret)
        totp = pyotp.TOTP(raw_secret)
        valid_token = totp.now()

        # 3. Revoke user
        revoke_user("revoked_user_totp")

        # 4. Attempt verify - must fail with USER_REVOKED
        event = verify_token("revoked_user_totp", valid_token)

        self.assertEqual(event.event_name, "AUTH_FAILURE")
        self.assertEqual(event.context.get("reason_code"), "USER_REVOKED")

    def test_recovery_code_revoked_user_fails(self):
        # 1. Enroll user
        _, codes = enroll_user("revoked_user_recovery")
        valid_code = codes[0]

        # 2. Revoke user
        revoke_user("revoked_user_recovery")

        # 3. Attempt recovery - must fail with USER_REVOKED
        event = use_recovery_code("revoked_user_recovery", valid_code)

        self.assertEqual(event.event_name, "AUTH_FAILURE")
        self.assertEqual(event.context.get("reason_code"), "USER_REVOKED")
