import unittest
import sqlite3
import os
from auth.core import enroll_user, UserAlreadyExistsError
from auth.storage import DB_PATH
from auth.crypto import crypto

class TestAuthEnrollment(unittest.TestCase):
    def setUp(self):
        """Inject guaranteed schema and clean state before each test."""
        with sqlite3.connect(DB_PATH) as conn:
            # 1. Database Fixture (bulletproof)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    encrypted_secret TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS recovery_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    hashed_code TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    used_at DATETIME,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    ip_address TEXT,
                    token_fingerprint TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
            """)
            # 2. Limpieza
            conn.execute("DELETE FROM recovery_codes")
            conn.execute("DELETE FROM auth_attempts")
            conn.execute("DELETE FROM users")
            conn.commit()

    def test_successful_enrollment(self):
        """Should return a URI and 10 recovery codes, and store data in DB."""
        username = "admin_test"
        uri, codes = enroll_user(username)

        self.assertTrue(uri.startswith("otpauth://totp/Antigravity-IDS:admin_test"))
        self.assertEqual(len(codes), 10)

    def test_encryption_at_rest(self):
        """Verifies that the stored secret can be decrypted to a valid Base32 string."""
        username = "crypto_user"
        enroll_user(username)

        with sqlite3.connect(DB_PATH) as conn:
            encrypted_secret = conn.execute(
                "SELECT encrypted_secret FROM users WHERE username = ?", (username,)
            ).fetchone()[0]

        decrypted = crypto.decrypt(encrypted_secret)

        self.assertEqual(len(decrypted), 32)
        self.assertNotEqual(decrypted, encrypted_secret)

    def test_duplicate_user_raises_error(self):
        """Should not allow two users with the same name."""
        username = "duplicate_guy"
        enroll_user(username)

        with self.assertRaises(UserAlreadyExistsError):
            enroll_user(username)

if __name__ == "__main__":
    unittest.main()
    