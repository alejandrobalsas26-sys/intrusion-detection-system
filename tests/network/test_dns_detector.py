import unittest

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from detection.intel import ThreatIntel
from network.detectors.dns_detector import DnsWatchlistDetector


def _query(domain: str, src: str = "192.168.1.20"):
    return (
        IP(src=src, dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )


class TestDnsWatchlistDetector(unittest.TestCase):
    def setUp(self):
        intel = ThreatIntel(domain_indicators={"evil.example"})
        self.detector = DnsWatchlistDetector(intel=intel)

    def test_watchlisted_domain_query_triggers(self):
        event = self.detector.process_packet(_query("evil.example"))
        self.assertIsNotNone(event)
        self.assertEqual(event.detector_name, "dns_ioc_query")
        self.assertEqual(event.level, "CRITICAL")
        self.assertEqual(event.context["domain"], "evil.example")
        self.assertEqual(event.context["indicator"], "evil.example")
        self.assertEqual(event.context["source_ip"], "192.168.1.20")

    def test_subdomain_matches_listed_parent(self):
        event = self.detector.process_packet(_query("c2.login.evil.example"))
        self.assertIsNotNone(event)
        self.assertEqual(event.context["indicator"], "evil.example")

    def test_benign_domain_is_ignored(self):
        self.assertIsNone(self.detector.process_packet(_query("python.org")))

    def test_duplicate_queries_alert_once(self):
        first = self.detector.process_packet(_query("evil.example"))
        second = self.detector.process_packet(_query("evil.example"))
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_responses_are_ignored(self):
        pkt = (
            IP(src="8.8.8.8", dst="192.168.1.20")
            / UDP(sport=53, dport=5353)
            / DNS(qr=1, qd=DNSQR(qname="evil.example"))
        )
        self.assertIsNone(self.detector.process_packet(pkt))

    def test_empty_watchlist_is_noop(self):
        detector = DnsWatchlistDetector(intel=ThreatIntel())
        self.assertIsNone(detector.process_packet(_query("evil.example")))


if __name__ == "__main__":
    unittest.main()
