import unittest
from scapy.all import IP, TCP
from network.detectors.syn_detector import SynDetector

class TestSynDetector(unittest.TestCase):
    def setUp(self):
        # Initialize with threshold 20 (alert on 21st unique port)
        self.detector = SynDetector(threshold=20, window_seconds=10)

    def test_syn_scan_detection_trigger(self):
        """Should trigger alert on the 21st unique destination port."""
        source_ip = "192.168.1.50"
        
        # 1. Send 20 packets to unique ports (1 to 20)
        for port in range(1, 21):
            pkt = IP(src=source_ip)/TCP(dport=port, flags="S")
            event = self.detector.process_packet(pkt)
            self.assertIsNone(event, f"Should not trigger on port {port}")

        # 2. The 21st unique port should trigger the event
        trigger_pkt = IP(src=source_ip)/TCP(dport=21, flags="S")
        event = self.detector.process_packet(trigger_pkt)

        self.assertIsNotNone(event)
        self.assertEqual(event.level, "CRITICAL")
        self.assertEqual(event.detector_name, "syn_scan")
        self.assertEqual(event.context["port_count"], 21)
        self.assertIn(21, event.context["target_ports"])

    def test_same_port_deduplication(self):
        """Should NOT trigger if the same port is probed multiple times (not a scan)."""
        source_ip = "192.168.1.50"
        
        # Send 50 packets to the SAME port (port 80)
        for _ in range(50):
            pkt = IP(src=source_ip)/TCP(dport=80, flags="S")
            event = self.detector.process_packet(pkt)
            self.assertIsNone(event)

    def test_non_syn_packet_ignored(self):
        """Should ignore TCP packets without the SYN flag (e.g., ACK)."""
        # ACK packet to a new port
        pkt = IP(src="1.1.1.1")/TCP(dport=99, flags="A")
        event = self.detector.process_packet(pkt)
        self.assertIsNone(event)

if __name__ == '__main__':
    unittest.main()
    