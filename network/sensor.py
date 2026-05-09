import os
import threading
from scapy.all import sniff, Packet

# Adapters (L0, L1)
from logs.logger import get_logger
from alerts.email_alert import send_security_alert

# Domain Core (L2)
from network.detectors.arp_detector import ArpDetector

logger = get_logger("network_sensor")

def start_sensor() -> threading.Thread:
    """
    Initializes and starts the network sensor in a background daemon thread.
    Note: Caller is responsible for pre-loading the environment variables (e.g., via load_dotenv).
    """
    logger.info("Initializing L2 Network Sensor...")
    
    # Initialize domain logic with env thresholds (Lifecycle bounded to start_sensor)
    arp_max_changes = int(os.getenv("ARP_SPOOF_MAX_CHANGES", "1"))
    arp_window = int(os.getenv("ARP_SPOOF_WINDOW_MINUTES", "5")) * 60
    
    arp_detector = ArpDetector(max_changes=arp_max_changes, window_seconds=arp_window)

    def _dispatch_packet(pkt: Packet):
        """Adapter logic: Feeds packets to the domain core and handles L0/L1 side-effects."""
        event = arp_detector.process_packet(pkt)
        
        if event:
            # 1. Log locally for forensic audit (L0) - Dynamic level + SQLite context mapping
            log_method = getattr(logger, event.level.lower(), logger.info)
            log_method("%s", event.message, extra={"context": event.context})
            
            # 2. Dispatch alert to SOC (L1)
            try:
                formatted_message = f"{event.message}\n\nForensic Context:\n{event.context}"
                send_security_alert(
                    event_level=event.level,
                    module_source=event.module_source,
                    alert_message=formatted_message,
                    subject=f"[{event.level}] IDS Alert: {event.detector_name}"
                )
            except Exception as e:
                logger.error("Failed to dispatch L1 alert: %s", str(e))

    def _sniff_worker():
        """Background worker for Scapy continuous packet capture."""
        logger.info("L2 Passive Sensor thread started. BPF Filter: 'arp'")
        # TODO(branch-2): expand BPF to include SYN handshake initiation ('tcp')
        sniff(filter="arp", prn=_dispatch_packet, store=False)

    sniffer_thread = threading.Thread(
        target=_sniff_worker, 
        daemon=True, 
        name="NetworkSensorThread"
    )
    sniffer_thread.start()
    
    return sniffer_thread
    