"""End-to-end demo: event generation, real FIM stage, and incident creation."""

import contextlib
import os
import sqlite3
import unittest

from demo.attack_chain import (
    ATTACKER_IP,
    IOC_LIST,
    PROTECTED_LIVE,
    SPRAY_USERS,
    build_records,
    run_demo,
)

EXPECTED_RULES = {
    "brute_force_burst",
    "password_spray",
    "auth_success_after_failures",
    "recon_then_auth",
    "network_then_fim",
    "ioc_match",
}


class BuildRecordsTestCase(unittest.TestCase):
    def test_timeline_shape(self):
        records = build_records()
        # 1 recon + 5 admin failures + 5 spray failures + 1 success
        self.assertEqual(len(records), 12)
        failures = [r for r in records if "failed" in r["message"]]
        self.assertEqual(len(failures), 10)
        users = {r["message"].split("'")[1] for r in failures}
        self.assertEqual(users, {"admin", *SPRAY_USERS})

    def test_offsets_are_monotonic_and_within_correlation_windows(self):
        records = build_records()
        offsets = [r["offset_seconds"] for r in records]
        self.assertEqual(offsets, sorted(offsets))
        # The whole chain must fit the default 3600 s correlation lookback.
        self.assertLess(max(offsets) - min(offsets), 3600)

    def test_no_real_secrets_or_routable_ips(self):
        self.assertTrue(ATTACKER_IP.startswith("203.0.113."))  # RFC 5737


class RunDemoTestCase(unittest.TestCase):
    """Runs against the session-isolated test DB provided by conftest."""

    _ENV_KEYS = ("IOC_IP_LIST_PATH", "EMAIL_SENDER")

    def setUp(self):
        # The demo mutates process env (IOC path, e-mail suppression); restore
        # whatever was there so later tests see an untouched environment.
        self._old_env = {k: os.environ.get(k) for k in self._ENV_KEYS}
        os.environ.pop("IOC_IP_LIST_PATH", None)

    def tearDown(self):
        for key, value in self._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _query(self, sql: str, params: tuple = ()):
        with contextlib.closing(sqlite3.connect(os.environ["DB_PATH"])) as conn:
            return conn.execute(sql, params).fetchall()

    def test_full_demo_creates_expected_incidents(self):
        summary = run_demo(sweep=True)

        self.assertEqual(summary.events_created, 12)
        self.assertGreaterEqual(summary.fim_events_created, 2)  # MODIFIED + CREATED
        self.assertIsNotNone(summary.incidents_created)
        self.assertTrue(EXPECTED_RULES.issubset(set(summary.incident_rules)))

        # The FIM stage must be real: the scratch dir exists and was tampered.
        self.assertTrue((PROTECTED_LIVE / "implant.bat").exists())
        self.assertTrue(IOC_LIST.exists())
        self.assertIn(ATTACKER_IP, IOC_LIST.read_text(encoding="utf-8"))

        fim_types = {
            row[0]
            for row in self._query(
                "SELECT DISTINCT event_type FROM fim_events WHERE filepath LIKE ?",
                (f"%{PROTECTED_LIVE.name}%",),
            )
        }
        self.assertIn("MODIFIED", fim_types)
        self.assertIn("CREATED", fim_types)

    def test_demo_suppresses_email_by_default(self):
        run_demo(sweep=False)
        self.assertEqual(os.environ.get("EMAIL_SENDER"), "")

    def test_sweep_is_idempotent_after_demo(self):
        from detection.correlation import CorrelationEngine

        run_demo(sweep=True)
        # Everything the demo produced was already correlated; nothing new.
        self.assertEqual(CorrelationEngine().sweep(), 0)


if __name__ == "__main__":
    unittest.main()
