import sqlite3
import unittest
from unittest.mock import patch

from auth.core import enroll_user, use_recovery_code
from auth.storage import DB_PATH
from tests.auth.fixtures import setup_test_db


class TestRecovery(unittest.TestCase):
    def setUp(self):
        # Mocks globales de I/O para evitar side-effects en la suite
        self.logger_patcher = patch("auth.core.logger")
        self.alert_patcher = patch("auth.core.send_security_alert")
        self.mock_logger = self.logger_patcher.start()
        self.mock_alert = self.alert_patcher.start()
        self.addCleanup(patch.stopall)

        with sqlite3.connect(DB_PATH) as conn:
            setup_test_db(conn)
        self.username = "recovery_user"
        _, self.codes = enroll_user(self.username)

    @patch("auth.core.time.sleep")
    def test_recovery_success(self, mock_sleep):
        event = use_recovery_code(self.username, self.codes[0])
        self.assertEqual(event.event_name, "AUTH_SUCCESS")
        self.assertEqual(event.context["reason_code"], "VALID_RECOVERY_CODE")

    @patch("auth.core.time.sleep")
    def test_recovery_invalid_code(self, mock_sleep):
        event = use_recovery_code(self.username, "INVALID")
        self.assertEqual(event.event_name, "AUTH_FAILURE")
        self.assertEqual(event.context["reason_code"], "INVALID_RECOVERY_CODE")

    @patch("auth.core.time.sleep")
    def test_recovery_single_use_enforcement(self, mock_sleep):
        use_recovery_code(self.username, self.codes[0])
        event = use_recovery_code(self.username, self.codes[0])
        self.assertEqual(event.event_name, "REPLAY_ATTACK")
        self.assertEqual(event.context["reason_code"], "TOKEN_REUSED_WINDOW")

    @patch("auth.core.time.sleep")
    def test_recovery_user_not_found(self, mock_sleep):
        event = use_recovery_code("ghost", "1234")
        self.assertEqual(event.event_name, "AUTH_FAILURE")
        self.assertEqual(event.context["reason_code"], "USER_NOT_FOUND")
