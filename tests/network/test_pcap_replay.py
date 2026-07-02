"""Offline PCAP replay through the detector stack (no privileges required)."""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from network.detectors.syn_detector import SynDetector
from network.replay import replay_pcap

REPO_ROOT = Path(__file__).parent.parent.parent
SYN_SAMPLE = REPO_ROOT / "samples" / "syn_scan.pcap"
ICMP_SAMPLE = REPO_ROOT / "samples" / "icmp_sweep.pcap"


def _write_syn_pcap(path: str, ports: int, base_time: float = 1_000_000.0) -> None:
    packets = []
    for i in range(ports):
        pkt = Ether() / IP(src="198.51.100.9", dst="203.0.113.1") / TCP(
            sport=40000, dport=i + 1, flags="S"
        )
        pkt.time = base_time + i * 0.01
        packets.append(pkt)
    wrpcap(path, packets)


class PcapReplayTestCase(unittest.TestCase):
    def test_crafted_scan_triggers_syn_detector(self):
        with tempfile.TemporaryDirectory(prefix="ids_pcap_test_") as tmp:
            pcap = str(Path(tmp, "scan.pcap"))
            _write_syn_pcap(pcap, ports=25)
            stats = replay_pcap(pcap, detectors=[SynDetector(threshold=20, window_seconds=10)])

        self.assertEqual(stats.packets_read, 25)
        self.assertEqual(len(stats.events), 1)
        self.assertEqual(stats.events[0].detector_name, "syn_scan")
        self.assertEqual(stats.events[0].context["source_ip"], "198.51.100.9")

    def test_below_threshold_scan_is_quiet(self):
        with tempfile.TemporaryDirectory(prefix="ids_pcap_test_") as tmp:
            pcap = str(Path(tmp, "small.pcap"))
            _write_syn_pcap(pcap, ports=5)
            stats = replay_pcap(pcap, detectors=[SynDetector(threshold=20, window_seconds=10)])
        self.assertEqual(stats.events, [])

    def test_checked_in_sample_stays_detectable(self):
        # Guards the shipped sample: if thresholds or the capture drift apart,
        # the documented demo command would silently stop demonstrating anything.
        stats = replay_pcap(str(SYN_SAMPLE))
        self.assertTrue(any(e.detector_name == "syn_scan" for e in stats.events))

        stats = replay_pcap(str(ICMP_SAMPLE))
        self.assertTrue(any(e.detector_name == "icmp_sweep" for e in stats.events))

    def test_replay_writes_audit_events(self):
        replay_pcap(str(SYN_SAMPLE))
        with sqlite3.connect(os.environ["DB_PATH"]) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM audit_events"
                " WHERE module_source = 'network_sensor'"
                " AND message LIKE 'DetectionEvent: CRITICAL from syn_scan%'"
            ).fetchone()[0]
        self.assertGreaterEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
