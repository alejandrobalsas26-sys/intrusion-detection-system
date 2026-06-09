import sqlite3
import unittest
from unittest.mock import patch

from auth.core import (
    BACKOFF_BASE_DELAY,
    BACKOFF_MAX_DELAY,
    _calculate_backoff_delay,
    enroll_user,
    use_recovery_code,
    verify_token,
)
from auth.storage import DB_PATH
from tests.auth.fixtures import setup_test_db


class TestBackoff(unittest.TestCase):
    def setUp(self):
        # Mocks globales de I/O para evitar side-effects en la suite
        self.logger_patcher = patch("auth.core.logger")
        self.alert_patcher = patch("auth.core.send_security_alert")
        self.mock_logger = self.logger_patcher.start()
        self.mock_alert = self.alert_patcher.start()
        self.addCleanup(patch.stopall)

        with sqlite3.connect(DB_PATH) as conn:
            setup_test_db(conn)
        self.username = "backoff_user"
        _, self.codes = enroll_user(self.username)
        with sqlite3.connect(DB_PATH) as conn:
            self.user_id = conn.execute(
                "SELECT id FROM users WHERE username = ?", (self.username,)
            ).fetchone()[0]

    def _inject_failures(self, count):
        with sqlite3.connect(DB_PATH) as conn:
            for i in range(count):
                conn.execute(
                    "INSERT INTO auth_attempts (user_id, success, token_fingerprint) VALUES (?, 0, ?)",
                    (self.user_id, f"fake_fingerprint_{i}"),
                )

    def test_backoff_mathematical_bounds(self):
        self._inject_failures(3)
        delay, count = _calculate_backoff_delay(self.user_id)
        self.assertEqual(count, 3)
        self.assertEqual(delay, BACKOFF_BASE_DELAY * (2**3))

    def test_backoff_max_cap(self):
        self._inject_failures(10)  # Capped at MAX_DELAY
        delay, count = _calculate_backoff_delay(self.user_id)
        self.assertEqual(delay, BACKOFF_MAX_DELAY)

    @patch("auth.core.time.sleep")
    def test_backoff_applied_on_verify(self, mock_sleep):
        self._inject_failures(2)
        event = verify_token(self.username, "000000")
        expected_delay = BACKOFF_BASE_DELAY * (2**2)
        mock_sleep.assert_called_once_with(expected_delay)
        self.assertEqual(event.context["backoff_applied_seconds"], expected_delay)

    @patch("auth.core.time.sleep")
    def test_shared_backoff_across_vectors(self, mock_sleep):
        self._inject_failures(3)  # 3 TOTP failures
        expected_delay = BACKOFF_BASE_DELAY * (2**3)
        # Use recovery code, should apply the same backoff
        event = use_recovery_code(self.username, "INVALID")
        mock_sleep.assert_called_once_with(expected_delay)
        self.assertEqual(event.context["backoff_applied_seconds"], expected_delay)

    @patch("auth.core.time.sleep")
    def test_backoff_alert_threshold_flag(self, mock_sleep):
        self._inject_failures(5)
        event = verify_token(self.username, "000000")
        self.assertTrue(event.context.get("alert_threshold_exceeded"))
