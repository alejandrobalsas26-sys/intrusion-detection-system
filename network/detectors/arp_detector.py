import time
from collections import defaultdict, deque
from typing import Optional, Deque, Tuple, Dict
from scapy.all import ARP, Packet

from . import DetectionEvent

class ArpDetector:
    def __init__(self, max_changes: int, window_seconds: int):
        self.max_changes = max_changes
        self.window_seconds = window_seconds
        # State: dict[IP, deque[tuple[monotonic_timestamp, mac_address]]]
        self.state: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)

    def process_packet(self, pkt: Packet) -> Optional[DetectionEvent]:
        # Solo procesar paquetes que contengan una capa ARP
        if not pkt.haslayer(ARP):
            return None
        
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        
        now = time.monotonic()
        history = self.state[ip_src]

        # 1. Lazy Eviction: Quitar entradas fuera de la ventana de tiempo
        while history and history[0][0] < (now - self.window_seconds):
            history.popleft()

        # 2. Deduplicación: Solo añadir si la MAC es distinta a la última vista
        if not history or history[-1][1] != mac_src:
            history.append((now, mac_src))

        # 3. Detección de anomalías: El número de cambios es len(history) - 1
        changes = len(history) - 1

        if changes > self.max_changes:
            mac_history = [mac for _, mac in history]
            
            event = DetectionEvent(
                level="CRITICAL",
                module_source="network",
                detector_name="arp_spoofing",
                message=f"ARP Spoofing detectado para IP {ip_src}. MAC cambio {changes} veces en la ventana.",
                timestamp=time.time(),
                context={
                    "ip_address": ip_src,
                    "mac_history": mac_history,
                    "window_seconds": self.window_seconds,
                    "max_changes_allowed": self.max_changes
                }
            )
            
            # Limpiar estado para evitar spam de alertas
            self.state[ip_src].clear()
            
            return event

        return None