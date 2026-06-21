import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fim.monitor import calculate_sha256, check_integrity, initialize_baselines


class TestFIM(unittest.TestCase):
    def setUp(self):
        # Each test gets a fully isolated temp directory AND an isolated FIM
        # database. Patching fim.monitor.DB_PATH guarantees baselines never
        # touch the production logs/ids_database.sqlite3, so stale active
        # baselines from one run can never make a later run report spurious
        # DELETED events. This also removes the prior Windows file-lock
        # flakiness, since the whole tree is disposable per test.
        self.test_dir = Path(tempfile.mkdtemp(prefix="ids_fim_test_"))
        self.test_file = self.test_dir / "target.txt"
        self.test_config = self.test_dir / "config.json"
        self.db_path = self.test_dir / "fim_test.sqlite3"

        self.db_patcher = patch("fim.monitor.DB_PATH", str(self.db_path))
        self.db_patcher.start()
        self.addCleanup(self.db_patcher.stop)

        # Create a dummy file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("Initial state")

        # Create config
        config = {"critical_files": [{"path": str(self.test_file), "severity": "CRITICAL"}]}
        with open(self.test_config, "w", encoding="utf-8") as f:
            json.dump(config, f)

    def tearDown(self):
        # rmtree(ignore_errors=True) tolerates transient Windows file locks
        # (AV/indexer holding a just-deleted file) that previously made the
        # plain rmdir() teardown flaky with WinError 5.
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("fim.monitor.send_security_alert")
    def test_integrity_breach_detection(self, mock_alert):
        """Test #1: Detects modification and triggers alert."""
        initialize_baselines(str(self.test_config))

        with open(self.test_file, "a", encoding="utf-8") as f:
            f.write(" + malicious")

        check_integrity()
        self.assertTrue(mock_alert.called)
        _, kwargs = mock_alert.call_args
        self.assertIn("Integrity breach detected", kwargs.get("alert_message", ""))

    @patch("fim.monitor.send_security_alert")
    def test_file_deletion_detection(self, mock_alert):
        """Test #2: Detects when a protected file is missing."""
        initialize_baselines(str(self.test_config))

        self.test_file.unlink()

        check_integrity()
        self.assertTrue(mock_alert.called)
        _, kwargs = mock_alert.call_args
        self.assertIn("has been deleted", kwargs.get("alert_message", ""))

    @patch("fim.monitor.send_security_alert")
    def test_no_change_no_alert(self, mock_alert):
        """Test #3: Verified files with no changes do not trigger alerts."""
        initialize_baselines(str(self.test_config))
        check_integrity()
        self.assertFalse(mock_alert.called)

    def test_sha256_missing_file_returns_none(self):
        """Test #4: calculate_sha256 handles non-existent files gracefully."""
        self.assertIsNone(calculate_sha256("non_existent_file.txt"))

    @patch("fim.monitor.logger")
    def test_initialize_baselines_missing_config(self, mock_logger):
        """Test #5: System logs a warning if config file is missing."""
        initialize_baselines("wrong_path.json")
        self.assertTrue(mock_logger.warning.called)


if __name__ == "__main__":
    unittest.main()
