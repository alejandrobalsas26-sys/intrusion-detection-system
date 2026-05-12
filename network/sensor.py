import os
import threading
from scapy.all import sniff
from alerts.email_alert import send_security_alert
from logs.logger import get_logger

from .detectors.arp_detector import ArpDetector
from .detectors.syn_detector import SynDetector

def _check_os_privileges():
    """Checks if the process has enough privileges to open raw sockets."""
    try:
        # On Linux/Unix, checking effective UID
        return os.getuid() == 0
    except AttributeError:
        # On Windows, this is a simplified check
        return True

def start_sensor():
    """Orchestrates network detectors and dispatches events to L0 and L1."""
    if os.getenv("NETWORK_MONITOR_CONSENT") != "true":
        print("[!] Network monitoring consent not found. Aborting sensor.")
        return None

    if not _check_os_privileges():
        print("[!] Insufficient privileges to start network sensor.")
        return None

    # 1. Initialize Detectors with Env Config
    arp_threshold = int(os.getenv("ARP_SPOOF_MAX_CHANGES", 1))
    arp_window = int(os.getenv("ARP_SPOOF_WINDOW_MINUTES", 5)) * 60
    
    syn_threshold = int(os.getenv("SYN_SCAN_THRESHOLD", 20))
    syn_window = int(os.getenv("SYN_SCAN_WINDOW_SECONDS", 10))

    # Plug-in Architecture: List of active detectors
    detectors = [
        ArpDetector(max_changes=arp_threshold, window_seconds=arp_window),
        SynDetector(threshold=syn_threshold, window_seconds=syn_window)
    ]

    def _dispatch_packet(pkt):
        """Internal callback for scapy sniff."""
        for detector in detectors:
            try:
                event = detector.process_packet(pkt)
                
                # GUARDIA: Solo procesamos si el detector encontró algo
                if event:
                    # A. Dispatch to L1 (Alerts)
                    send_security_alert(
                        event_level=event.level,
                        alert_message=event.message
                    )

                    # B. Dispatch to L0 (Logs/Persistence)
                    logger = get_logger("network_sensor")
                    
                    # Mapeo dinámico de nivel (critical, warning, info)
                    log_func = getattr(logger, event.level.lower(), logger.info)
                    log_func(
                        f"DetectionEvent: {event.level} from {event.detector_name} - {event.message}"
                    )
            except Exception as e:
                # Evitamos que un error en un detector mate al sniffer
                print(f"[-] Error in detector {detector.__class__.__name__}: {e}")

    # 2. Start Sniffer in a daemon thread
    bpf_filter = "arp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
    
    sniffer_thread = threading.Thread(
        target=sniff,
        kwargs={
            "prn": _dispatch_packet,
            "filter": bpf_filter,
            "store": 0
        },
        daemon=True
    )
    
    sniffer_thread.start()
    return sniffer_thread
    