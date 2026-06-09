"""Tests for retention purges, integrity checks, and database stats."""

import contextlib
import sqlite3
import time
import unittest
from pathlib import Path

from logs.maintenance import (
    database_stats,
    integrity_check,
    purge_old_events,
    vacuum,
)

REPO_ROOT = Path(__file__).parent.parent.parent


class MaintenanceTestCase(unittest.TestCase):
    def setUp(self):
        self.db_dir = Path("tests/temp_logs")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(self.db_dir / "test_maint.sqlite3")
        db_file = Path(self.db_path)
        if db_file.exists():
            db_file.unlink()
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            for schema in ("logs", "fim", "auth", "detection"):
                with open(REPO_ROOT / schema / "schema.sql", encoding="utf-8") as f:
                    conn.executescript(f.read())

    def tearDown(self):
        for f in self.db_dir.glob("*"):
            try:
                f.unlink()
            except OSError:
                pass

    def _seed(self):
        now = time.time()
        old = now - 200 * 86400
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO audit_events (timestamp, level, module_source, message) "
                "VALUES (?, 'INFO', 'test', 'old event')",
                (old,),
            )
            conn.execute(
                "INSERT INTO audit_events (timestamp, level, module_source, message) "
                "VALUES (?, 'INFO', 'test', 'fresh event')",
                (now,),
            )
            conn.execute(
                "INSERT INTO fim_events (filepath, event_type, severity, timestamp) "
                "VALUES ('/x', 'MODIFIED', 'CRITICAL', datetime('now', '-200 days'))"
            )
            conn.execute(
                "INSERT INTO fim_events (filepath, event_type, severity) "
                "VALUES ('/y', 'MODIFIED', 'CRITICAL')"
            )
            conn.execute(
                "INSERT INTO incidents (created_at, rule_name, title, severity, risk_score, "
                "status, dedupe_key) VALUES (?, 'r', 'old closed', 'INFO', 1, 'closed', 'k1')",
                (old,),
            )
            conn.execute(
                "INSERT INTO incidents (created_at, rule_name, title, severity, risk_score, "
                "status, dedupe_key) VALUES (?, 'r', 'old but open', 'INFO', 1, 'open', 'k2')",
                (old,),
            )
            conn.commit()

    def test_purge_removes_only_expired_rows(self):
        self._seed()
        result = purge_old_events(retention_days=90, db_path=self.db_path)
        self.assertEqual(result.audit_events, 1)
        self.assertEqual(result.fim_events, 1)
        self.assertEqual(result.closed_incidents, 1)

        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            remaining = conn.execute("SELECT message FROM audit_events").fetchall()
            self.assertEqual(remaining, [("fresh event",)])
            # Open incidents survive retention regardless of age.
            statuses = [r[0] for r in conn.execute("SELECT status FROM incidents").fetchall()]
            self.assertEqual(statuses, ["open"])

    def test_purge_rejects_invalid_retention(self):
        with self.assertRaises(ValueError):
            purge_old_events(retention_days=0, db_path=self.db_path)

    def test_integrity_check_ok_on_healthy_db(self):
        ok, findings = integrity_check(db_path=self.db_path)
        self.assertTrue(ok)
        self.assertEqual(findings, ["ok"])

    def test_vacuum_runs_without_error(self):
        self._seed()
        purge_old_events(retention_days=90, db_path=self.db_path)
        vacuum(db_path=self.db_path)  # must not raise

    def test_database_stats_reports_counts(self):
        self._seed()
        stats = database_stats(db_path=self.db_path)
        self.assertEqual(stats["audit_events"], 2)
        self.assertEqual(stats["fim_events"], 2)
        self.assertEqual(stats["incidents"], 2)
        self.assertGreater(stats["size_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
