import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fim.monitor import calculate_sha256, check_integrity, initialize_baselines


class TestFIM(unittest.TestCase):
    def setUp(self):
        # Setup temporary paths
        self.test_dir = Path("tests/temp_fim")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.test_file = self.test_dir / "target.txt"
        self.test_config = self.test_dir / "config.json"

        # Create a dummy file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("Initial state")

        # Create config
        config = {"critical_files": [{"path": str(self.test_file), "severity": "CRITICAL"}]}
        with open(self.test_config, "w", encoding="utf-8") as f:
            json.dump(config, f)

    def tearDown(self):
        # Cleanup all temp files
        if self.test_file.exists():
            self.test_file.unlink()
        if self.test_config.exists():
            self.test_config.unlink()
        if self.test_dir.exists():
            self.test_dir.rmdir()

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
