"""Directory-baseline FIM behavior: CREATED detection and one-alert semantics."""

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fim.monitor import check_integrity, initialize_baselines


class TestFimDirectoryBaselines(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="ids_fim_dir_test_"))
        self.watch_dir = self.test_dir / "protected"
        self.watch_dir.mkdir()
        (self.watch_dir / "existing.txt").write_text("original", encoding="utf-8")
        nested = self.watch_dir / "nested"
        nested.mkdir()
        (nested / "deep.txt").write_text("deep", encoding="utf-8")

        self.db_path = self.test_dir / "fim_test.sqlite3"
        self.config_path = self.test_dir / "config.json"
        config = {
            "critical_dirs": [
                {"path": str(self.watch_dir), "recursive": True, "created_severity": "WARNING"}
            ]
        }
        self.config_path.write_text(json.dumps(config), encoding="utf-8")

        self.db_patcher = patch("fim.monitor.DB_PATH", str(self.db_path))
        self.db_patcher.start()
        self.addCleanup(self.db_patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _fim_events(self) -> list[tuple]:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT filepath, event_type, severity FROM fim_events ORDER BY id"
            ).fetchall()

    @patch("fim.monitor.send_security_alert")
    def test_baseline_covers_nested_files(self, _alert):
        initialize_baselines(str(self.config_path))
        with sqlite3.connect(self.db_path) as conn:
            paths = {
                row[0]
                for row in conn.execute(
                    "SELECT filepath FROM file_baselines WHERE is_active = 1"
                )
            }
        self.assertEqual(len(paths), 2)
        self.assertTrue(any("deep.txt" in p for p in paths))

    @patch("fim.monitor.send_security_alert")
    def test_new_file_raises_created_once(self, _alert):
        initialize_baselines(str(self.config_path))
        check_integrity()
        self.assertEqual(self._fim_events(), [])  # clean state: no events

        dropped = self.watch_dir / "backdoor.py"
        dropped.write_text("print('planted')", encoding="utf-8")

        check_integrity()
        events = self._fim_events()
        self.assertEqual(len(events), 1)
        filepath, event_type, severity = events[0]
        self.assertIn("backdoor.py", filepath)
        self.assertEqual(event_type, "CREATED")
        self.assertEqual(severity, "WARNING")

        # Second check: the file was folded into the baseline — no re-alert.
        check_integrity()
        self.assertEqual(len(self._fim_events()), 1)

    @patch("fim.monitor.send_security_alert")
    def test_created_file_later_modified_raises_modified(self, _alert):
        initialize_baselines(str(self.config_path))
        dropped = self.watch_dir / "implant.cfg"
        dropped.write_text("v1", encoding="utf-8")
        check_integrity()  # CREATED + auto-baseline

        dropped.write_text("v2-tampered", encoding="utf-8")
        check_integrity()

        types = [e[1] for e in self._fim_events()]
        self.assertEqual(types, ["CREATED", "MODIFIED"])

    @patch("fim.monitor.send_security_alert")
    def test_non_recursive_ignores_nested_new_files(self, _alert):
        config = {"critical_dirs": [{"path": str(self.watch_dir), "recursive": False}]}
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        initialize_baselines(str(self.config_path))

        (self.watch_dir / "nested" / "sneaky.txt").write_text("x", encoding="utf-8")
        check_integrity()
        self.assertEqual(self._fim_events(), [])

    @patch("fim.monitor.send_security_alert")
    def test_per_file_config_behavior_unchanged(self, mock_alert):
        target = self.watch_dir / "existing.txt"
        config = {"critical_files": [{"path": str(target), "severity": "CRITICAL"}]}
        self.config_path.write_text(json.dumps(config), encoding="utf-8")
        initialize_baselines(str(self.config_path))

        target.write_text("tampered", encoding="utf-8")
        check_integrity()

        types = [e[1] for e in self._fim_events()]
        self.assertEqual(types, ["MODIFIED"])
        self.assertTrue(mock_alert.called)


if __name__ == "__main__":
    unittest.main()
