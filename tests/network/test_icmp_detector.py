import unittest

from scapy.layers.inet import ICMP, IP

from network.detectors.icmp_detector import IcmpSweepDetector


class TestIcmpSweepDetector(unittest.TestCase):
    def setUp(self):
        self.detector = IcmpSweepDetector(threshold=10, window_seconds=30)

    def test_sweep_triggers_past_distinct_host_threshold(self):
        source = "192.168.1.66"
        for i in range(1, 11):
            pkt = IP(src=source, dst=f"10.0.0.{i}") / ICMP(type=8)
            self.assertIsNone(self.detector.process_packet(pkt))

        trigger = IP(src=source, dst="10.0.0.11") / ICMP(type=8)
        event = self.detector.process_packet(trigger)

        self.assertIsNotNone(event)
        self.assertEqual(event.detector_name, "icmp_sweep")
        self.assertEqual(event.level, "WARNING")
        self.assertEqual(event.context["source_ip"], source)
        self.assertEqual(event.context["host_count"], 11)

    def test_repeated_pings_to_same_host_do_not_trigger(self):
        for _ in range(50):
            pkt = IP(src="192.168.1.66", dst="10.0.0.1") / ICMP(type=8)
            self.assertIsNone(self.detector.process_packet(pkt))

    def test_echo_replies_are_ignored(self):
        for i in range(1, 30):
            pkt = IP(src="192.168.1.66", dst=f"10.0.0.{i}") / ICMP(type=0)
            self.assertIsNone(self.detector.process_packet(pkt))

    def test_state_resets_after_alert(self):
        source = "192.168.1.66"
        for i in range(1, 12):
            pkt = IP(src=source, dst=f"10.0.0.{i}") / ICMP(type=8)
            self.detector.process_packet(pkt)
        # After the alert fired, the very next ping starts a fresh window.
        pkt = IP(src=source, dst="10.0.0.99") / ICMP(type=8)
        self.assertIsNone(self.detector.process_packet(pkt))

    def test_non_icmp_packets_ignored(self):
        from scapy.layers.inet import TCP

        pkt = IP(src="1.2.3.4", dst="10.0.0.1") / TCP(dport=80, flags="S")
        self.assertIsNone(self.detector.process_packet(pkt))


if __name__ == "__main__":
    unittest.main()
