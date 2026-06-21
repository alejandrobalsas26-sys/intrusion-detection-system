import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scapy.all import ARP

# 1. Bootstrapping Temp Environment.
# Snapshot the env keys we mutate so tearDownClass can restore them and this
# module does not leak DB_PATH (etc.) into the rest of the session, keeping the
# suite order-independent.
_ENV_KEYS = ("DB_PATH", "NETWORK_MONITOR_CONSENT", "ARP_SPOOF_MAX_CHANGES", "ARP_SPOOF_WINDOW_MINUTES")
_ORIGINAL_ENV = {k: os.environ.get(k) for k in _ENV_KEYS}

TEMP_DB = tempfile.NamedTemporaryFile(delete=False)
TEMP_DB.close()
os.environ["DB_PATH"] = TEMP_DB.name
os.environ["NETWORK_MONITOR_CONSENT"] = "true"
os.environ["ARP_SPOOF_MAX_CHANGES"] = "1"
os.environ["ARP_SPOOF_WINDOW_MINUTES"] = "5"

from network.sensor import start_sensor  # noqa: E402


class TestSmokeArp(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEMP_DB.name):
            try:
                os.unlink(TEMP_DB.name)
            except Exception:
                pass
        # Restore the original environment so later tests see the session's
        # isolated DB_PATH from conftest, not this module's temp file.
        for key, value in _ORIGINAL_ENV.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

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
        conn = sqlite3.connect(os.environ["DB_PATH"])
        cursor = conn.cursor()

        rows = cursor.execute(
            "SELECT level, module_source, message FROM audit_events WHERE level = 'CRITICAL'"
        ).fetchall()

        conn.close()

        self.assertEqual(len(rows), 1, "Expected exactly one CRITICAL event in audit DB")
        self.assertIn("ARP Spoofing detected", rows[0][2])


if __name__ == "__main__":
    unittest.main()
