"""ICMP sweep (ping sweep) detector.

Flags a source that sends echo requests to many *distinct* destination hosts
inside a sliding window — the classic live-host enumeration step that precedes
port scanning. Counting distinct destinations (not raw packet volume) keeps
ordinary monitoring pings and retries below the threshold.
"""

import time
from collections import Counter, deque

from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet

from network.detectors import DetectionEvent

ICMP_ECHO_REQUEST = 8


class IcmpSweepDetector:
    """Detects ICMP echo sweeps using the same lazy-eviction pattern as SynDetector."""

    def __init__(self, threshold: int = 16, window_seconds: int = 30):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._dst_deques: dict[str, deque] = {}
        self._dst_counts: dict[str, Counter] = {}

    def process_packet(self, packet: Packet) -> DetectionEvent | None:
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return None
        if packet.getlayer(ICMP).type != ICMP_ECHO_REQUEST:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = packet.time

        dst_deque = self._dst_deques.setdefault(src_ip, deque())
        dst_counts = self._dst_counts.setdefault(src_ip, Counter())

        while dst_deque and (current_time - dst_deque[0][0] > self.window_seconds):
            _, old_dst = dst_deque.popleft()
            dst_counts[old_dst] -= 1
            if dst_counts[old_dst] == 0:
                del dst_counts[old_dst]

        dst_deque.append((current_time, dst_ip))
        dst_counts[dst_ip] += 1

        unique_count = len(dst_counts)
        if unique_count > self.threshold:
            event = DetectionEvent(
                # WARNING (not CRITICAL): a sweep is reconnaissance, lower
                # confidence of compromise than an active SYN scan or spoof.
                level="WARNING",
                module_source="network",
                detector_name="icmp_sweep",
                message=(
                    f"ICMP sweep detected from {src_ip}: "
                    f"{unique_count} distinct hosts pinged in {self.window_seconds}s window."
                ),
                timestamp=time.time(),
                context={
                    "source_ip": src_ip,
                    "host_count": unique_count,
                    "targets": sorted(dst_counts.keys())[:20],
                },
            )
            del self._dst_deques[src_ip]
            del self._dst_counts[src_ip]
            return event

        return None
