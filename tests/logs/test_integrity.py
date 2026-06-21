"""Tests for tamper-evident audit log sealing and verification."""

import contextlib
import sqlite3
import time
import unittest
from pathlib import Path

from logs.integrity import seal_audit_log, verify_audit_log

REPO_ROOT = Path(__file__).parent.parent.parent
SCHEMA = REPO_ROOT / "logs" / "schema.sql"


class AuditIntegrityTestCase(unittest.TestCase):
    def setUp(self):
        self.db_dir = Path("tests/temp_integrity")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(self.db_dir / "test_chain.sqlite3")
        for leftover in self.db_dir.glob("test_chain.*"):
            with contextlib.suppress(OSError):
                leftover.unlink()
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            with open(SCHEMA, encoding="utf-8") as f:
                conn.executescript(f.read())

    def tearDown(self):
        for f in self.db_dir.glob("*"):
            with contextlib.suppress(OSError):
                f.unlink()

    def _insert(self, n, level="INFO", module="auth_core", message="event"):
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            for i in range(n):
                conn.execute(
                    "INSERT INTO audit_events (timestamp, level, module_source, message, "
                    "context_data) VALUES (?, ?, ?, ?, ?)",
                    (time.time() + i, level, module, f"{message} {i}", None),
                )
            conn.commit()

    def _exec(self, sql, params=()):
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(sql, params)
            conn.commit()

    def test_seal_empty_is_noop(self):
        result = seal_audit_log(db_path=self.db_path)
        self.assertFalse(result.sealed)

    def test_seal_then_verify_ok(self):
        self._insert(5)
        sealed = seal_audit_log(db_path=self.db_path)
        self.assertTrue(sealed.sealed)
        self.assertEqual(sealed.row_count, 5)

        result = verify_audit_log(db_path=self.db_path)
        self.assertTrue(result.ok)
        self.assertEqual(result.verified, 1)
        self.assertEqual(result.unsealed_events, 0)
        self.assertTrue(result.last_chain_hash)

    def test_incremental_sealing(self):
        self._insert(3)
        seal_audit_log(db_path=self.db_path)
        self._insert(3)  # ids 4-6
        second = seal_audit_log(db_path=self.db_path)
        self.assertTrue(second.sealed)
        self.assertEqual(second.from_id, 4)

        result = verify_audit_log(db_path=self.db_path)
        self.assertTrue(result.ok)
        self.assertEqual(result.checkpoints_total, 2)
        self.assertEqual(result.verified, 2)

    def test_unsealed_tail_is_counted(self):
        self._insert(3)
        seal_audit_log(db_path=self.db_path)
        self._insert(2)  # new, unsealed
        result = verify_audit_log(db_path=self.db_path)
        self.assertTrue(result.ok)
        self.assertEqual(result.unsealed_events, 2)

    def test_modified_event_is_detected(self):
        self._insert(5)
        seal_audit_log(db_path=self.db_path)
        # Tamper with a sealed row's message.
        self._exec("UPDATE audit_events SET message = 'TAMPERED' WHERE id = 3")
        result = verify_audit_log(db_path=self.db_path)
        self.assertFalse(result.ok)
        self.assertTrue(any("modified" in f for f in result.failures))

    def test_deleted_event_is_detected(self):
        self._insert(5)
        seal_audit_log(db_path=self.db_path)
        # Delete a row in the middle of a sealed segment.
        self._exec("DELETE FROM audit_events WHERE id = 3")
        result = verify_audit_log(db_path=self.db_path)
        self.assertFalse(result.ok)
        self.assertTrue(any("deleted or inserted" in f for f in result.failures))

    def test_broken_checkpoint_chain_is_detected(self):
        self._insert(3)
        seal_audit_log(db_path=self.db_path)
        self._insert(3)
        seal_audit_log(db_path=self.db_path)
        # Rewrite the first checkpoint's chain_hash without fixing the second's seed.
        self._exec("UPDATE audit_checkpoints SET chain_hash = 'forged' WHERE id = 1")
        result = verify_audit_log(db_path=self.db_path)
        self.assertFalse(result.ok)
        self.assertTrue(any("chain seed broken" in f for f in result.failures))

    def test_retention_aged_out_prefix_is_not_tampering(self):
        self._insert(3)
        seal_audit_log(db_path=self.db_path)  # cp1: ids 1-3
        self._insert(3)
        seal_audit_log(db_path=self.db_path)  # cp2: ids 4-6
        # Simulate a retention purge of the oldest segment's rows.
        self._exec("DELETE FROM audit_events WHERE id <= 3")
        result = verify_audit_log(db_path=self.db_path)
        self.assertTrue(result.ok)
        self.assertEqual(result.aged_out, 1)
        self.assertEqual(result.verified, 1)


if __name__ == "__main__":
    unittest.main()
