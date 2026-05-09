import os
import threading
from scapy.all import sniff, Packet
from dotenv import load_dotenv

# Adapters (L0, L1)
from logs.logger import get_logger
from alerts.email_alert import send_security_alert

# Domain Core (L2)
from network.detectors.arp_detector import ArpDetector

load_dotenv()
logger = get_logger("network_sensor")

# Inicializar lógica con umbrales del .env
arp_max_changes = int(os.getenv("ARP_SPOOF_MAX_CHANGES", 1))
arp_window = int(os.getenv("ARP_SPOOF_WINDOW_MINUTES", 5)) * 60

arp_detector = ArpDetector(max_changes=arp_max_changes, window_seconds=arp_window)

def _dispatch_packet(pkt: Packet):
    """Lógica del adaptador: Envía paquetes al núcleo y maneja efectos secundarios."""
    event = arp_detector.process_packet(pkt)
    
    if event:
        # 1. Log local (L0)
        logger.critical(event.message)
        
        # 2. Enviar alerta (L1)
        try:
            # Simplificado para evitar conflictos de argumentos con email_alert.py
            alert_subject = f"[{event.level}] IDS Alert: {event.detector_name}"
            alert_body = f"{event.message} | Contexto: {event.context}"
            send_security_alert(alert_subject, alert_body)
        except Exception as e:
            logger.error(f"Error enviando alerta L1: {str(e)}")

def _sniff_worker():
    """Hilo de fondo para captura continua con Scapy."""
    logger.info("Hilo del sensor L2 iniciado. Filtro BPF: 'arp'")
    sniff(filter="arp", prn=_dispatch_packet, store=False)

def start_sensor() -> threading.Thread:
    """
    Inicializa y arranca el sensor en un hilo separado (daemon).
    """
    logger.info("Iniciando Network Sensor L2...")
    
    sniffer_thread = threading.Thread(
        target=_sniff_worker, 
        daemon=True, 
        name="NetworkSensorThread"
    )
    sniffer_thread.start()
    
    return sniffer_thread
    