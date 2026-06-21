"""Resilience tests for the audit logger and test-suite DB isolation."""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from logs.logger import SQLiteAuditHandler


class AuditHandlerBusyTimeoutTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ids_logger_test_")
        self.db = Path(self.tmp, "audit.sqlite3").as_posix()
        self.failsafe = Path(self.tmp, "failsafe.log").as_posix()

    def test_connection_sets_busy_timeout(self):
        handler = SQLiteAuditHandler(self.db, self.failsafe)
        conn = handler._connect()
        try:
            # PRAGMA busy_timeout returns the configured value in milliseconds.
            value = conn.execute("PRAGMA busy_timeout").fetchone()[0]
            self.assertEqual(value, SQLiteAuditHandler._BUSY_TIMEOUT_MS)
        finally:
            conn.close()

    def test_emit_persists_event(self):
        import logging

        handler = SQLiteAuditHandler(self.db, self.failsafe)
        record = logging.LogRecord(
            "test_module", logging.WARNING, __file__, 1, "audit message", None, None
        )
        handler.emit(record)
        with sqlite3.connect(self.db) as conn:
            row = conn.execute(
                "SELECT level, module_source, message FROM audit_events"
            ).fetchone()
        self.assertEqual(row, ("WARNING", "test_module", "audit message"))


class DatabaseIsolationTestCase(unittest.TestCase):
    """conftest.py must redirect the suite away from the production database."""

    def test_db_path_is_not_production(self):
        # The invariant that matters: the suite must never target the operator's
        # real database. (Individual tests may point DB_PATH at their own temp
        # files, but never at the production path.)
        db_path = os.environ.get("DB_PATH", "").replace("\\", "/")
        self.assertTrue(db_path, "DB_PATH must be set during tests")
        self.assertNotIn("logs/ids_database.sqlite3", db_path)


if __name__ == "__main__":
    unittest.main()
