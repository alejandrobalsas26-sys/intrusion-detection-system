"""JSONL event replay: parsing, timestamp anchoring, and insertion."""

import contextlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from detection.correlation import CorrelationEngine
from detection.replay import (
    ReplayFormatError,
    insert_audit_records,
    read_jsonl,
    replay_file,
    resolve_timestamps,
)

SAMPLE = Path(__file__).parent.parent.parent / "demo" / "sample_events.jsonl"


class ReadJsonlTestCase(unittest.TestCase):
    def _write(self, content: str) -> str:
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        )
        handle.write(content)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name

    def test_parses_records_and_skips_comments(self):
        path = self._write(
            "# comment\n\n"
            '{"level": "INFO", "module_source": "m", "message": "x", "offset_seconds": 0}\n'
        )
        records = read_jsonl(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["message"], "x")

    def test_rejects_invalid_json(self):
        path = self._write("{not json}\n")
        with self.assertRaises(ReplayFormatError):
            read_jsonl(path)

    def test_rejects_missing_required_fields(self):
        path = self._write('{"level": "INFO", "offset_seconds": 1}\n')
        with self.assertRaises(ReplayFormatError):
            read_jsonl(path)

    def test_rejects_record_without_any_timestamp(self):
        path = self._write('{"level": "INFO", "module_source": "m", "message": "x"}\n')
        with self.assertRaises(ReplayFormatError):
            read_jsonl(path)


class ResolveTimestampsTestCase(unittest.TestCase):
    def test_offsets_anchor_latest_event_at_base_time(self):
        records = [
            {"offset_seconds": 0},
            {"offset_seconds": 30},
            {"offset_seconds": 60},
        ]
        resolved = resolve_timestamps(records, base_time=1000.0)
        self.assertEqual(resolved, [940.0, 970.0, 1000.0])

    def test_absolute_timestamps_pass_through(self):
        records = [{"timestamp": 123.0}, {"offset_seconds": 10}]
        resolved = resolve_timestamps(records, base_time=1000.0)
        self.assertEqual(resolved[0], 123.0)
        self.assertEqual(resolved[1], 1000.0)

    def test_deterministic_given_base_time(self):
        records = [{"offset_seconds": 5}, {"offset_seconds": 15}]
        self.assertEqual(
            resolve_timestamps(records, base_time=500.0),
            resolve_timestamps(records, base_time=500.0),
        )


class InsertionTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ids_replay_test_")
        self.addCleanup(self.tmp.cleanup)
        self.db_path = str(Path(self.tmp.name, "replay.sqlite3"))

    def _rows(self):
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            return conn.execute(
                "SELECT timestamp, level, module_source, message, context_data"
                " FROM audit_events ORDER BY timestamp"
            ).fetchall()

    def test_inserts_rows_with_context(self):
        records = [
            {
                "offset_seconds": 0,
                "level": "warning",
                "module_source": "auth_core",
                "message": "Authentication failed for user 'admin'.",
                "context": {"reason_code": "INVALID_TOTP"},
            }
        ]
        result = insert_audit_records(records, db_path=self.db_path, base_time=2000.0)
        self.assertEqual(result.inserted, 1)
        rows = self._rows()
        self.assertEqual(rows[0][0], 2000.0)
        self.assertEqual(rows[0][1], "WARNING")  # level upper-cased
        self.assertEqual(json.loads(rows[0][4]), {"reason_code": "INVALID_TOTP"})

    def test_replaying_twice_inserts_twice(self):
        # Replay is an insert, not an upsert — documented, and pinned here so a
        # behavior change is a conscious decision.
        records = [
            {"offset_seconds": 0, "level": "INFO", "module_source": "m", "message": "x"}
        ]
        insert_audit_records(records, db_path=self.db_path, base_time=1.0)
        insert_audit_records(records, db_path=self.db_path, base_time=1.0)
        self.assertEqual(len(self._rows()), 2)

    def test_sample_file_replays_and_correlates(self):
        base = 1_750_000_000.0
        result = replay_file(str(SAMPLE), db_path=self.db_path, base_time=base)
        self.assertEqual(result.inserted, 8)

        engine = CorrelationEngine(db_path=self.db_path)
        engine.sweep(since_ts=base - 3600)
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            rules = {
                row[0]
                for row in conn.execute("SELECT rule_name FROM incidents").fetchall()
            }
        self.assertIn("brute_force_burst", rules)
        self.assertIn("auth_success_after_failures", rules)
        self.assertIn("recon_then_auth", rules)
        self.assertIn("network_then_fim", rules)

        # Idempotency: a second sweep over the same window creates nothing new.
        self.assertEqual(engine.sweep(since_ts=base - 3600), 0)


if __name__ == "__main__":
    unittest.main()
