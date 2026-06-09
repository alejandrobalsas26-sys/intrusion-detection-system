import time
from collections import Counter, deque

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from network.detectors import DetectionEvent


class SynDetector:
    """Detects SYN scans using a sliding time window.

    Port counting is O(1) amortized per packet: a per-IP deque holds
    (timestamp, port) entries for lazy eviction, and a per-IP Counter
    tracks each port's reference count so the number of distinct active
    ports is read directly via len() rather than rescanning all keys.
    """

    def __init__(self, threshold: int = 20, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._port_deques: dict[str, deque] = {}
        self._port_counts: dict[str, Counter] = {}

    def process_packet(self, packet: Packet) -> DetectionEvent | None:
        if not packet.haslayer(TCP):
            return None

        tcp_layer = packet.getlayer(TCP)
        if tcp_layer.flags != "S":
            return None

        src_ip = packet[IP].src
        dst_port = tcp_layer.dport
        current_time = packet.time

        port_deque = self._port_deques.setdefault(src_ip, deque())
        port_counts = self._port_counts.setdefault(src_ip, Counter())

        # 1. Lazy-evict entries that fall outside the sliding window.
        while port_deque and (current_time - port_deque[0][0] > self.window_seconds):
            _, old_port = port_deque.popleft()
            port_counts[old_port] -= 1
            if port_counts[old_port] == 0:
                del port_counts[old_port]

        # 2-3. Record the new (timestamp, port) and bump its ref count.
        port_deque.append((current_time, dst_port))
        port_counts[dst_port] += 1

        # 4. Number of distinct active ports is O(1).
        unique_count = len(port_counts)

        if unique_count > self.threshold:
            event = DetectionEvent(
                level="CRITICAL",
                module_source="network",
                detector_name="syn_scan",
                message=(
                    f"SYN scan detected from {src_ip}: "
                    f"{unique_count} unique ports in {self.window_seconds}s window."
                ),
                timestamp=time.time(),
                context={
                    "source_ip": src_ip,
                    "port_count": unique_count,
                    "target_ports": sorted(port_counts.keys())[:20],
                },
            )
            # 5. Reset per-IP state after alerting.
            del self._port_deques[src_ip]
            del self._port_counts[src_ip]
            return event

        return None
