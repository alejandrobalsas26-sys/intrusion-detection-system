"""Regenerates the sample capture files used by the PCAP replay demo/tests.

Run from the repository root:
    python samples/make_sample_pcaps.py

The captures are synthetic (crafted with scapy, never sniffed) and use
documentation address space (RFC 5737 TEST-NET) so they can't be mistaken
for real traffic.
"""

from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

SAMPLES_DIR = Path(__file__).parent
ATTACKER = "198.51.100.77"  # TEST-NET-2
TARGET = "203.0.113.10"  # TEST-NET-3
BASE_TIME = 1_750_000_000.0  # fixed epoch: replays are deterministic


def build_syn_scan(ports: int = 60) -> list:
    """One source SYN-probing many ports on one host within a few seconds."""
    packets = []
    for i in range(ports):
        pkt = (
            Ether()
            / IP(src=ATTACKER, dst=TARGET)
            / TCP(sport=54321, dport=i + 1, flags="S")
        )
        pkt.time = BASE_TIME + i * 0.05
        packets.append(pkt)
    return packets


def build_icmp_sweep(hosts: int = 25) -> list:
    """One source pinging many distinct hosts within a few seconds."""
    packets = []
    for i in range(hosts):
        pkt = Ether() / IP(src=ATTACKER, dst=f"203.0.113.{i + 1}") / ICMP(type=8)
        pkt.time = BASE_TIME + i * 0.2
        packets.append(pkt)
    return packets


def main() -> None:
    syn_path = SAMPLES_DIR / "syn_scan.pcap"
    wrpcap(str(syn_path), build_syn_scan())
    print(f"[+] Wrote {syn_path}")

    icmp_path = SAMPLES_DIR / "icmp_sweep.pcap"
    wrpcap(str(icmp_path), build_icmp_sweep())
    print(f"[+] Wrote {icmp_path}")


if __name__ == "__main__":
    main()
