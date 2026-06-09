"""Tests for the opt-in duplicate-alert suppression window."""

import os
import unittest
from unittest.mock import MagicMock, patch

from alerts import email_alert
from detection.dedup import EventDeduplicator

SMTP_ENV = {
    "EMAIL_SENDER": "ids@example.com",
    "EMAIL_PASSWORD": "x",
    "ALERT_RECEIVER": "soc@example.com",
}


class AlertThrottleTestCase(unittest.TestCase):
    def setUp(self):
        # Fresh throttle state per test (module-level singleton otherwise).
        email_alert._alert_throttle = EventDeduplicator(window_seconds=0)

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_throttle_disabled_by_default_sends_every_alert(self, mock_smtp):
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        env = {**SMTP_ENV, "ALERT_DEDUP_WINDOW_SECONDS": "0"}
        with patch.dict(os.environ, env):
            first = email_alert.send_security_alert("CRITICAL", "test", "same message")
            second = email_alert.send_security_alert("CRITICAL", "test", "same message")
        self.assertTrue(first)
        self.assertTrue(second)
        self.assertEqual(mock_smtp.call_count, 2)

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_duplicate_suppressed_inside_window(self, mock_smtp):
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        env = {**SMTP_ENV, "ALERT_DEDUP_WINDOW_SECONDS": "300"}
        with patch.dict(os.environ, env):
            first = email_alert.send_security_alert("CRITICAL", "test", "same message")
            second = email_alert.send_security_alert("CRITICAL", "test", "same message")
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertEqual(mock_smtp.call_count, 1)

    @patch("alerts.email_alert.smtplib.SMTP")
    def test_distinct_alerts_not_suppressed(self, mock_smtp):
        mock_smtp.return_value.__enter__.return_value = MagicMock()
        env = {**SMTP_ENV, "ALERT_DEDUP_WINDOW_SECONDS": "300"}
        with patch.dict(os.environ, env):
            email_alert.send_security_alert("CRITICAL", "test", "message A")
            second = email_alert.send_security_alert("CRITICAL", "test", "message B")
        self.assertTrue(second)
        self.assertEqual(mock_smtp.call_count, 2)


if __name__ == "__main__":
    unittest.main()
