"""DNS watchlist detector: queries for operator-listed malicious domains.

Deliberately narrow to stay high-confidence: it only fires when a DNS query
name matches the local IOC domain watchlist (``IOC_DOMAIN_LIST_PATH``, see
``detection.intel``). Without a configured watchlist it is a guaranteed no-op.
Entropy/DGA heuristics were considered and rejected as too false-positive
prone for an honest default.
"""

import time

from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet

from detection.intel import ThreatIntel
from network.detectors import DetectionEvent


class DnsWatchlistDetector:
    """Flags DNS queries whose qname matches a local threat-intel domain list."""

    def __init__(self, intel: ThreatIntel | None = None):
        self.intel = intel if intel is not None else ThreatIntel.from_env()
        # One alert per (source, domain) per process run; a compromised host
        # re-resolving its C2 every few seconds must not flood the alert channel.
        self._reported: set[tuple[str, str]] = set()

    def process_packet(self, packet: Packet) -> DetectionEvent | None:
        if not self.intel.has_indicators():
            return None
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None
        if packet.getlayer(DNS).qr != 0:  # queries only, not responses
            return None

        qname = packet.getlayer(DNSQR).qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="replace")
        domain = qname.rstrip(".").lower()
        if not domain:
            return None

        indicator = self.intel.match_domain(domain)
        if not indicator:
            return None

        src_ip = "unknown"
        # DNS can arrive over IPv4 or IPv6; import both lazily to keep the
        # hot path free of layer lookups when there is no match.
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src

        key = (src_ip, domain)
        if key in self._reported:
            return None
        self._reported.add(key)

        return DetectionEvent(
            level="CRITICAL",
            module_source="network",
            detector_name="dns_ioc_query",
            message=(
                f"DNS query for watchlisted domain from {src_ip}: "
                f"'{domain}' matches indicator '{indicator}'."
            ),
            timestamp=time.time(),
            context={
                "source_ip": src_ip,
                "domain": domain,
                "indicator": indicator,
            },
        )
