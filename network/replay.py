"""Offline PCAP replay through the live detector stack.

Reads packets from a capture file with ``scapy.rdpcap`` (pure file I/O — no
raw sockets, no privileges, no live interface) and runs them through the same
detectors the sensor uses. Detected events are written to the audit store in
the sensor's exact log format, so normalization, correlation, scoring, and the
dashboard treat them identically to live detections.

Windowing note: SYN/ICMP detectors evaluate sliding windows against the
packet capture timestamps (``pkt.time``), so a scan recorded years ago still
correlates within itself. The ARP detector windows on wall-clock time; replayed
ARP bursts are evaluated as if they arrived now (fine for spoofing bursts,
which fit any window).

Alerting: e-mail dispatch is OFF by default during replay — offline forensics
should not page anyone. Pass ``--alert`` to exercise the full alert path.

CLI:
    python -m network.replay samples/syn_scan.pcap [--alert] [--sweep]
"""

import argparse
from dataclasses import dataclass, field

from network.detectors import DetectionEvent, build_default_detectors


@dataclass
class ReplayStats:
    packets_read: int = 0
    events: list[DetectionEvent] = field(default_factory=list)
    detector_errors: int = 0


def replay_pcap(
    path: str,
    detectors: list | None = None,
    alert: bool = False,
) -> ReplayStats:
    """Runs every packet in a capture file through the detector stack.

    Events are logged through the standard audit pipeline (same message format
    as the live sensor). Returns the stats so callers/tests can inspect what
    fired without querying the database.
    """
    # Deferred imports: scapy's rdpcap and the logger only load when a replay
    # actually runs, keeping module import cheap for tests and tooling.
    from scapy.utils import rdpcap

    from logs.logger import get_logger

    logger = get_logger("network_sensor")
    stack = detectors if detectors is not None else build_default_detectors()
    stats = ReplayStats()

    packets = rdpcap(path)
    for pkt in packets:
        stats.packets_read += 1
        for detector in stack:
            try:
                event = detector.process_packet(pkt)
            except Exception as exc:
                stats.detector_errors += 1
                logger.error(
                    f"Replay error in detector {detector.__class__.__name__}: {exc}"
                )
                continue
            if not event:
                continue
            stats.events.append(event)
            if alert:
                from alerts.email_alert import send_security_alert

                send_security_alert(
                    event_level=event.level,
                    module_source=event.module_source,
                    alert_message=event.message,
                )
            log_func = getattr(logger, event.level.lower(), logger.info)
            # Same envelope as the live sensor so downstream parsing is identical;
            # context rides along so normalization gets structured fields too.
            log_func(
                f"DetectionEvent: {event.level} from {event.detector_name} - {event.message}",
                extra={"context": dict(event.context)},
            )
    return stats


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        prog="network.replay",
        description="Replay a PCAP file through the IDS detectors (offline, unprivileged).",
    )
    parser.add_argument("pcap", help="Path to a capture file (.pcap/.pcapng)")
    parser.add_argument(
        "--alert",
        action="store_true",
        help="Also dispatch e-mail alerts for detections (off by default)",
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="Run one correlation sweep after the replay",
    )
    args = parser.parse_args(argv)

    try:
        stats = replay_pcap(args.pcap, alert=args.alert)
    except FileNotFoundError:
        print(f"[x] Capture file not found: {args.pcap}")
        return 1
    except Exception as exc:  # scapy raises various errors on malformed captures
        print(f"[x] Could not read capture: {exc}")
        return 1

    print(f"[+] Replayed {stats.packets_read} packet(s) from {args.pcap}")
    if stats.events:
        print(f"[!] {len(stats.events)} detection event(s):")
        for event in stats.events:
            print(f"    - [{event.level}] {event.detector_name}: {event.message}")
    else:
        print("[+] No detections fired.")
    if stats.detector_errors:
        print(f"[!] {stats.detector_errors} packet(s) caused detector errors (see audit log).")

    if args.sweep:
        from detection.correlation import CorrelationEngine

        created = CorrelationEngine().sweep()
        print(f"[+] Correlation sweep: {created} new incident(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
