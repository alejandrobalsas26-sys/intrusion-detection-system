import sqlite3
import unittest
from unittest.mock import patch

from auth.core import UserAlreadyExistsError, enroll_user
from auth.crypto import crypto
from auth.storage import DB_PATH
from tests.auth.fixtures import setup_test_db


class TestAuthEnrollment(unittest.TestCase):
    def setUp(self):
        """Inject guaranteed schema and clean state before each test."""
        with sqlite3.connect(DB_PATH) as conn:
            setup_test_db(conn)

    def test_successful_enrollment(self):
        """Should return a URI and 10 recovery codes, and store data in DB."""
        uri, codes = enroll_user("analyst_1")
        self.assertTrue(uri.startswith("otpauth://totp/Antigravity-IDS:analyst_1"))
        self.assertEqual(len(codes), 10)
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = 'analyst_1'")
            self.assertIsNotNone(cursor.fetchone())

    def test_recovery_codes_count_env_override(self):
        """MFA_RECOVERY_CODES_COUNT controls how many codes are issued."""
        with patch.dict("os.environ", {"MFA_RECOVERY_CODES_COUNT": "5"}):
            _, codes = enroll_user("analyst_env_count")
        self.assertEqual(len(codes), 5)
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM recovery_codes rc JOIN users u ON u.id = rc.user_id"
                " WHERE u.username = 'analyst_env_count'"
            )
            self.assertEqual(cursor.fetchone()[0], 5)

    def test_recovery_codes_count_invalid_falls_back_to_default(self):
        """A non-numeric MFA_RECOVERY_CODES_COUNT must not break enrollment."""
        with patch.dict("os.environ", {"MFA_RECOVERY_CODES_COUNT": "plenty"}):
            _, codes = enroll_user("analyst_bad_count")
        self.assertEqual(len(codes), 10)

    def test_duplicate_user_raises_error(self):
        """Should not allow two users with the same name."""
        enroll_user("analyst_2")
        with self.assertRaises(UserAlreadyExistsError):
            enroll_user("analyst_2")

    def test_encryption_at_rest(self):
        """Verifies that the stored secret can be decrypted to a valid Base32 string."""
        enroll_user("analyst_3")
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_secret FROM users WHERE username = 'analyst_3'")
            encrypted_secret = cursor.fetchone()[0]

        raw_secret = crypto.decrypt(encrypted_secret)
        self.assertEqual(len(raw_secret), 32)
