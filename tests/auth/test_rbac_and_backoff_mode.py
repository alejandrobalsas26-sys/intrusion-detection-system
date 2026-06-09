"""Tests for RBAC helpers and the non-blocking (reject) backoff mode."""

import os
import sqlite3
import time
import unittest
from unittest.mock import patch

from auth.core import enroll_user, get_user_role, set_user_role, verify_token
from auth.storage import DB_PATH
from tests.auth.fixtures import setup_test_db


class TestRbacHelpers(unittest.TestCase):
    def setUp(self):
        with sqlite3.connect(DB_PATH) as conn:
            setup_test_db(conn)

    def test_default_role_is_analyst(self):
        enroll_user("rbac_user")
        self.assertEqual(get_user_role("rbac_user"), "analyst")

    def test_set_role_round_trip(self):
        enroll_user("rbac_admin")
        self.assertTrue(set_user_role("rbac_admin", "admin"))
        self.assertEqual(get_user_role("rbac_admin"), "admin")

    def test_set_role_rejects_invalid_role(self):
        enroll_user("rbac_user2")
        with self.assertRaises(ValueError):
            set_user_role("rbac_user2", "superuser")

    def test_set_role_unknown_user_returns_false(self):
        self.assertFalse(set_user_role("ghost", "admin"))

    def test_role_of_unknown_user_is_none(self):
        self.assertIsNone(get_user_role("ghost"))

    def test_revoked_user_has_no_role(self):
        enroll_user("rbac_revoked")
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE username = 'rbac_revoked'")
            conn.commit()
        self.assertIsNone(get_user_role("rbac_revoked"))


class TestRejectBackoffMode(unittest.TestCase):
    """MFA_BACKOFF_MODE=reject must return RATE_LIMITED without sleeping."""

    def setUp(self):
        with sqlite3.connect(DB_PATH) as conn:
            setup_test_db(conn)
        enroll_user("reject_user")
        # Seed enough recent failures to put the user firmly in backoff.
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = 'reject_user'")
            user_id = cursor.fetchone()[0]
            for i in range(4):
                cursor.execute(
                    "INSERT INTO auth_attempts (user_id, success, token_fingerprint) "
                    "VALUES (?, 0, ?)",
                    (user_id, f"seed-fail-{i}"),
                )
            conn.commit()

    def test_reject_mode_returns_rate_limited_quickly(self):
        with patch.dict(os.environ, {"MFA_BACKOFF_MODE": "reject"}):
            start = time.monotonic()
            event = verify_token("reject_user", "000000")
            elapsed = time.monotonic() - start

        self.assertEqual(event.event_name, "RATE_LIMITED")
        self.assertEqual(event.context.get("reason_code"), "RATE_LIMITED")
        self.assertGreater(event.context.get("backoff_applied_seconds", 0), 0)
        # Non-blocking: must not have served the exponential sleep (>= 16s here).
        self.assertLess(elapsed, 5)

    def test_reject_mode_does_not_fire_without_failures(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM auth_attempts")
            conn.commit()
        with patch.dict(os.environ, {"MFA_BACKOFF_MODE": "reject"}):
            event = verify_token("reject_user", "000000")
        # No recent failures -> normal verification path (invalid token).
        self.assertEqual(event.event_name, "AUTH_FAILURE")

    def test_default_mode_still_sleeps(self):
        """Legacy compatibility: without the env var, sleep mode is used."""
        env = {k: v for k, v in os.environ.items() if k != "MFA_BACKOFF_MODE"}
        with patch.dict(os.environ, env, clear=True):
            with patch("auth.core.time.sleep") as mock_sleep:
                event = verify_token("reject_user", "000000")
        mock_sleep.assert_called_once()
        self.assertEqual(event.event_name, "AUTH_FAILURE")


if __name__ == "__main__":
    unittest.main()
