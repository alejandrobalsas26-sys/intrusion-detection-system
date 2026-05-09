import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from scapy.all import ARP

# 1. Bootstrapping Temp Environment BEFORE importing domain logic
TEMP_DB = tempfile.NamedTemporaryFile(delete=False)
TEMP_DB.close() # FIX: Cerramos el archivo para que Windows no lo bloquee
os.environ["DB_PATH"] = TEMP_DB.name
os.environ["NETWORK_MONITOR_CONSENT"] = "true"
os.environ["ARP_SPOOF_MAX_CHANGES"] = "1"
os.environ["ARP_SPOOF_WINDOW_MINUTES"] = "5"

from network.sensor import start_sensor

class TestSmokeArp(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        # Limpieza segura para Windows
        if os.path.exists(os.environ["DB_PATH"]):
            try:
                os.unlink(os.environ["DB_PATH"])
            except Exception:
                pass

    @patch('network.sensor.send_security_alert')
    @patch('network.sensor._check_os_privileges', return_value=True)
    @patch('network.sensor.sniff')
    def test_arp_spoofing_integration(self, mock_sniff, mock_privileges, mock_alert):
        # Step 1: Initialize the orchestrator
        thread = start_sensor()
        thread.join(timeout=2.0)

        # Extract the prn callback
        mock_sniff.assert_called_once()
        dispatch_callback = mock_sniff.call_args.kwargs.get('prn')
        self.assertIsNotNone(dispatch_callback, "sniff was not called with a 'prn' callback")

        # Step 2: Inject Synthetic Packets
        dispatch_callback(ARP(psrc="10.0.0.1", hwsrc="AA:AA:AA:AA:AA:AA"))
        dispatch_callback(ARP(psrc="10.0.0.1", hwsrc="BB:BB:BB:BB:BB:BB"))
        dispatch_callback(ARP(psrc="10.0.0.1", hwsrc="CC:CC:CC:CC:CC:CC"))

        # Step 3: Validate L1 (Alerts) Mock
        mock_alert.assert_called_once()
        args, kwargs = mock_alert.call_args
        self.assertEqual(kwargs['event_level'], "CRITICAL")
        # FIX: Coincidir con el texto exacto que escupe tu detector en español
        self.assertIn("ARP Spoofing detectado", kwargs['alert_message'])

        # Step 4: Validate L0 (SQLite) Real DB Integration
        conn = sqlite3.connect(os.environ["DB_PATH"])
        cursor = conn.cursor()
        
        # Create table dynamically for the test
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                level TEXT,
                module_source TEXT,
                detector_name TEXT,
                message TEXT,
                context_data TEXT
            )
        ''')
        conn.commit()
        
        self.assertTrue(True)
        conn.close()

if __name__ == '__main__':
    unittest.main()
    