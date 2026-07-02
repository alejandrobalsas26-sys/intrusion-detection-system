import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scapy.all import ARP

from logs.logger import SQLiteAuditHandler, get_logger
from network.sensor import start_sensor


class TestSmokeArp(unittest.TestCase):
    """Full ARP-spoofing path: sensor thread -> detector -> alert + audit DB.

    The "exactly one CRITICAL row" assertion needs a database nobody else
    writes to. Swapping the process-wide DB_PATH would leak into every other
    test (pytest imports all modules before running any test), so instead the
    sensor logger gets a private SQLiteAuditHandler bound to a test-owned temp
    DB for the duration of this class — order-independent in both directions.
    """

    _ENV = {
        "NETWORK_MONITOR_CONSENT": "true",
        "ARP_SPOOF_MAX_CHANGES": "1",
        "ARP_SPOOF_WINDOW_MINUTES": "5",
    }

    @classmethod
    def setUpClass(cls):
        cls._old_env = {k: os.environ.get(k) for k in cls._ENV}
        os.environ.update(cls._ENV)

        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        tmp.close()
        cls.db_path = tmp.name
        cls._logger = get_logger("network_sensor")
        cls._old_handlers = cls._logger.handlers[:]
        cls._logger.handlers = [
            SQLiteAuditHandler(cls.db_path, cls.db_path + ".failsafe.log")
        ]

    @classmethod
    def tearDownClass(cls):
        cls._logger.handlers = cls._old_handlers
        for key, value in cls._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for path in (cls.db_path, cls.db_path + ".failsafe.log"):
            try:
                os.unlink(path)
            except OSError:
                pass

    @patch("network.sensor.send_security_alert")
    @patch("network.sensor._check_os_privileges", return_value=True)
    @patch("network.sensor.sniff")
    def test_arp_spoofing_integration(self, mock_sniff, mock_privileges, mock_alert):
        # Step 1: Initialize the orchestrator
        thread = start_sensor()
        thread.join(timeout=1.0)

        # Extract the prn callback
        mock_sniff.assert_called_once()
        dispatch_callback = mock_sniff.call_args.kwargs.get("prn")

        # Step 2: Inject Synthetic Packets
        dispatch_callback(ARP(psrc="10.0.0.1", hwsrc="AA:AA:AA:AA:AA:AA"))
        dispatch_callback(ARP(psrc="10.0.0.1", hwsrc="BB:BB:BB:BB:BB:BB"))
        dispatch_callback(ARP(psrc="10.0.0.1", hwsrc="CC:CC:CC:CC:CC:CC"))

        # Step 3: Validate L1 (Alerts) Mock
        mock_alert.assert_called_once()
        args, kwargs = mock_alert.call_args
        self.assertEqual(kwargs["event_level"], "CRITICAL")
        self.assertIn("ARP Spoofing detected", kwargs["alert_message"])

        # Step 4: Validate L0 (SQLite) Real DB Integration
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        rows = cursor.execute(
            "SELECT level, module_source, message FROM audit_events WHERE level = 'CRITICAL'"
        ).fetchall()

        conn.close()

        self.assertEqual(len(rows), 1, "Expected exactly one CRITICAL event in audit DB")
        self.assertIn("ARP Spoofing detected", rows[0][2])


if __name__ == "__main__":
    unittest.main()
