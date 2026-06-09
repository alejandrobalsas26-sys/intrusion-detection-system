import sqlite3
import unittest
from unittest.mock import patch

import pyotp

from auth.core import _token_fingerprint, enroll_user, verify_token
from auth.crypto import crypto
from auth.storage import DB_PATH
from tests.auth.fixtures import setup_test_db


class TestVerifyToken(unittest.TestCase):
    def setUp(self):
        # Mocks globales de I/O para evitar side-effects en la suite
        self.logger_patcher = patch("auth.core.logger")
        self.alert_patcher = patch("auth.core.send_security_alert")
        self.mock_logger = self.logger_patcher.start()
        self.mock_alert = self.alert_patcher.start()
        self.addCleanup(patch.stopall)

        with sqlite3.connect(DB_PATH) as conn:
            setup_test_db(conn)
        self.username = "verify_user"
        enroll_user(self.username)
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, encrypted_secret FROM users WHERE username = ?", (self.username,)
            )
            self.user_id, enc_secret = cursor.fetchone()
            self.secret = crypto.decrypt(enc_secret)

    @patch("auth.core.time.sleep")
    def test_verify_success(self, mock_sleep):
        totp = pyotp.TOTP(self.secret)
        event = verify_token(self.username, totp.now())
        self.assertEqual(event.event_name, "AUTH_SUCCESS")
        mock_sleep.assert_not_called()

    @patch("auth.core.time.sleep")
    def test_verify_user_not_found(self, mock_sleep):
        event = verify_token("ghost_user", "123456")
        self.assertEqual(event.event_name, "AUTH_FAILURE")
        self.assertEqual(event.context["reason_code"], "USER_NOT_FOUND")

    @patch("auth.core.time.sleep")
    def test_verify_invalid_token(self, mock_sleep):
        event = verify_token(self.username, "000000")
        self.assertEqual(event.event_name, "AUTH_FAILURE")
        self.assertEqual(event.context["reason_code"], "INVALID_TOKEN")

    @patch("auth.core.time.sleep")
    def test_verify_replay_attack(self, mock_sleep):
        totp = pyotp.TOTP(self.secret)
        token = totp.now()
        verify_token(self.username, token)
        event2 = verify_token(self.username, token)
        self.assertEqual(event2.event_name, "REPLAY_ATTACK")
        self.assertEqual(event2.context["reason_code"], "TOKEN_REUSED_WINDOW")

    @patch("auth.core.time.sleep")
    def test_verify_race_condition(self, mock_sleep):
        totp = pyotp.TOTP(self.secret)
        token = totp.now()
        fingerprint = _token_fingerprint(self.user_id, token)
        # Bypasses 90s window but triggers UNIQUE constraint
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO auth_attempts (user_id, success, token_fingerprint, timestamp) VALUES (?, 1, ?, datetime('now', '-100 seconds'))",
                (self.user_id, fingerprint),
            )
        event = verify_token(self.username, token)
        self.assertEqual(event.event_name, "REPLAY_ATTACK")
        self.assertEqual(event.context["reason_code"], "TOKEN_REUSED_RACE_CONDITION")

    @patch("auth.core.time.sleep")
    def test_verify_crypto_error(self, mock_sleep):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE users SET encrypted_secret = 'corrupted_base64_data' WHERE id = ?",
                (self.user_id,),
            )
        event = verify_token(self.username, "123456")
        self.assertEqual(event.event_name, "CRYPTO_ERROR")
        self.assertEqual(event.context["reason_code"], "fernet_invalid_token")

    def test_failed_auth_logs_to_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM auth_attempts")

        # Use an obviously wrong token
        verify_token(self.username, "000000")

        # Verify entry exists
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT user_id, success, token_fingerprint FROM auth_attempts WHERE user_id = ?",
                (self.user_id,),
            )
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], 0)  # 0 means failed
