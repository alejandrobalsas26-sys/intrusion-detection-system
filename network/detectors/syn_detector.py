import time
from collections import defaultdict, deque
from typing import Optional, Deque, Tuple, Dict
from scapy.all import TCP, IP, Packet

from . import DetectionEvent

class SynDetector:
    """
    Detects TCP SYN scans.
    Technical Debt Note: Unique port counting currently uses len(set(...)) over a deque.
    This is O(N). For MVP with small thresholds (<100) and 10s windows, this is trivial.
    If network noise increases significantly, consider refactoring to a sync'd 'set' sidekick.
    """
    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # State: dict[source_ip, deque[tuple[monotonic_timestamp, destination_port]]]
        self.state: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)

    def process_packet(self, pkt: Packet) -> Optional[DetectionEvent]:
        # Guard clause: Only process packets with IP and TCP layers
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return None
            
        tcp_layer = pkt[TCP]
        # Guard clause: Check if it's strictly a SYN packet (Flag 'S' is 0x02)
        if tcp_layer.flags != 'S':
            return None

        ip_src = pkt[IP].src
        port_dst = tcp_layer.dport
        
        now = time.monotonic()
        history = self.state[ip_src]

        # 1. Lazy Eviction: Remove entries outside the sliding window
        while history and history[0][0] < (now - self.window_seconds):
            history.popleft()

        # 2. Append current packet's destination port
        history.append((now, port_dst))

        # 3. Anomaly Detection: Count unique destination ports
        # Note: See docstring regarding O(N) complexity deferred debt.
        unique_ports = list(set(port for _, port in history))
        changes = len(unique_ports)

        if changes > self.threshold:
            # Calculate scan burst speed for forensic analysis
            scan_duration_seconds = history[-1][0] - history[0][0]
            
            event = DetectionEvent(
                level="CRITICAL",
                module_source="network",
                detector_name="syn_scan",
                message=f"TCP SYN Scan detected from IP {ip_src}. Probed {changes} unique ports within window.",
                timestamp=time.time(),
                context={
                    "detector_name": "syn_scan",
                    "source_ip": ip_src,
                    "target_ports": unique_ports,
                    "port_count": changes,
                    "window_seconds": self.window_seconds,
                    "threshold_allowed": self.threshold,
                    "scan_duration_seconds": round(scan_duration_seconds, 3)
                }
            )
            
            # Clear state to prevent alert flooding within the same window
            self.state[ip_src].clear()
            
            return event

        return None
        