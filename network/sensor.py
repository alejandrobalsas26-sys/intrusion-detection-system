import os
import threading

from scapy.all import sniff
from scapy.packet import Packet

from alerts.email_alert import send_security_alert
from detection.dedup import EventDeduplicator
from logs.logger import get_logger

from .detectors import build_default_detectors

logger = get_logger("network_sensor")


def _check_os_privileges() -> bool:
    """Checks if the process has enough privileges to open raw sockets."""
    try:
        # On Linux/Unix, checking effective UID
        return os.getuid() == 0
    except AttributeError:
        # os.getuid() is unavailable on Windows; perform a real elevation check
        # so a non-admin process fails fast with the clear "Insufficient
        # privileges" message instead of a raw socket error later.
        import ctypes

        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def start_sensor() -> threading.Thread | None:
    """Orchestrates network detectors and dispatches events to L0 and L1."""
    if os.getenv("NETWORK_MONITOR_CONSENT") != "true":
        logger.warning("Network monitoring consent not found. Aborting sensor.")
        return None

    if not _check_os_privileges():
        logger.warning("Insufficient privileges to start network sensor.")
        return None

    # 1. Initialize Detectors with Env Config (shared factory with PCAP replay)
    detectors = build_default_detectors()

    # Optional duplicate suppression across detector re-triggers. Disabled by
    # default (window=0) to preserve legacy alert-per-event behavior.
    dedup_window = int(os.getenv("EVENT_DEDUP_WINDOW_SECONDS", "0"))
    deduplicator = EventDeduplicator(window_seconds=dedup_window) if dedup_window > 0 else None

    def _dispatch_packet(pkt: Packet) -> None:
        """Internal callback for scapy sniff."""
        for detector in detectors:
            try:
                event = detector.process_packet(pkt)

                # GUARDIA: Solo procesamos si el detector encontró algo
                if event:
                    if deduplicator is not None:
                        entity = event.context.get("source_ip") or event.context.get(
                            "ip_address"
                        )
                        fp = EventDeduplicator.fingerprint(
                            event.detector_name, entity, event.level
                        )
                        if deduplicator.is_duplicate(fp):
                            logger.info(
                                f"Suppressed duplicate {event.detector_name} event "
                                f"for {entity} (dedup window {dedup_window}s)."
                            )
                            continue

                    # A. Dispatch to L1 (Alerts)
                    send_security_alert(
                        event_level=event.level,
                        module_source=event.module_source,
                        alert_message=event.message,
                    )

                    # B. Dispatch to L0 (Logs/Persistence)
                    # Mapeo dinámico de nivel (critical, warning, info)
                    log_func = getattr(logger, event.level.lower(), logger.info)
                    log_func(
                        f"DetectionEvent: {event.level} from {event.detector_name} - {event.message}"  # noqa: E501
                    )
            except Exception as e:
                # Evitamos que un error en un detector mate al sniffer
                logger.error(f"Error in detector {detector.__class__.__name__}: {e}")

    # 2. Start Sniffer in a daemon thread. The filter admits exactly what the
    # detector stack consumes: ARP (spoofing), bare SYNs (scans), ICMP echo
    # (sweeps), and DNS queries (watchlist matches).
    bpf_filter = (
        "arp or icmp or udp port 53 or "
        "(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
    )

    sniffer_thread = threading.Thread(
        target=sniff,
        kwargs={"prn": _dispatch_packet, "filter": bpf_filter, "store": 0},
        daemon=True,
    )

    sniffer_thread.start()
    return sniffer_thread
