import os
from dataclasses import dataclass, field
from typing import Any, Dict  # noqa: F401, UP035


@dataclass
class DetectionEvent:
    level: str
    module_source: str
    detector_name: str
    message: str
    timestamp: float
    context: dict[str, Any] = field(default_factory=dict)


def build_default_detectors() -> list:
    """Instantiates every packet detector with its environment-driven config.

    Shared by the live sensor and the offline PCAP replay so both paths run an
    identical detection stack. Imports are deferred so importing this package
    for the DetectionEvent dataclass alone does not pull in scapy layers.
    """
    from network.detectors.arp_detector import ArpDetector
    from network.detectors.dns_detector import DnsWatchlistDetector
    from network.detectors.icmp_detector import IcmpSweepDetector
    from network.detectors.syn_detector import SynDetector

    arp_threshold = int(os.getenv("ARP_SPOOF_MAX_CHANGES", "1"))
    arp_window = int(os.getenv("ARP_SPOOF_WINDOW_MINUTES", "5")) * 60
    syn_threshold = int(os.getenv("SYN_SCAN_THRESHOLD", "20"))
    syn_window = int(os.getenv("SYN_SCAN_WINDOW_SECONDS", "10"))
    icmp_threshold = int(os.getenv("ICMP_SWEEP_THRESHOLD", "16"))
    icmp_window = int(os.getenv("ICMP_SWEEP_WINDOW_SECONDS", "30"))

    return [
        ArpDetector(max_changes=arp_threshold, window_seconds=arp_window),
        SynDetector(threshold=syn_threshold, window_seconds=syn_window),
        IcmpSweepDetector(threshold=icmp_threshold, window_seconds=icmp_window),
        # No-op unless IOC_DOMAIN_LIST_PATH points at a watchlist.
        DnsWatchlistDetector(),
    ]
