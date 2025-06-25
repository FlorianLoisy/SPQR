from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass
from typing import List
import random
import time
import json
from pathlib import Path

@dataclass
class ICMPConfig:
    src_ip: str
    dst_ip: str
    icmp_type: int = 8  # Echo Request
    icmp_code: int = 0
    payload: str = "SPQR-ICMP-TEST"
    count: int = 4
    id: int = None
    src_mac: str = None
    dst_mac: str = None
    time_interval: int = 1000  # Intervalle de temps entre les paquets en millisecondes

class ICMPGenerator(ProtocolGenerator):
    def __init__(self, config: dict):
        # Charger la configuration par défaut
        config_path = Path("config/protocols/icmp_config.json")
        with config_path.open() as f:
            config = json.load(f)
            defaults = config["default"]
            
        # Appliquer les valeurs par défaut
        for key, value in defaults.items():
            if not hasattr(self, key) or getattr(self, key) is None:
                setattr(self, key, value)
#        super().__init__(config=config)
#        self.icmp_config = config
#        self.id = self.icmp_config.id or random.randint(1000, 65535)
        # Convertir la config plate en ICMPConfig
        self.icmp_config = ICMPConfig(
            src_ip=self.source_ip,
            dst_ip=self.dest_ip,
            source_port=self.source_port,  # Même si non utilisé pour ICMP
            dest_port=self.dest_port       # Même si non utilisé pour ICMP
        )

    def generate(self) -> List[Packet]:
        packets = []
        
        for i in range(self.packet_count):
            # Créer la requête ICMP (ping)
            request = IP(src=self.icmp_config.src_ip, dst=self.icmp_config.dst_ip) / \
                     ICMP(type=self.icmp_config.icmp_type,
                          code=self.icmp_config.icmp_code,
                          id=self.id,
                          seq=i+1) / \
                     Raw(load=self.icmp_config.payload)
            
            # Créer la réponse ICMP (pong)
            response = IP(src=self.icmp_config.dst_ip, dst=self.icmp_config.src_ip) / \
                      ICMP(type=0, code=0, id=self.id, seq=i+1) / \
                      Raw(load=self.icmp_config.payload)
            
            packets.extend([request, response])
            
            if self.time_interval > 0 and i < self.packet_count - 1:
                time.sleep(self.time_interval / 1000)
        
        return packets
    
    def generate_icmp_from_schedule(json_path: str, output_pcap: str):
        
        json_path = Path("config/config.json")
        with json_path.open() as f:
           data = json.load(f)

        icmp_specifique = data["traffic_patterns"]["icmp_specifique"]
        dst_ip = icmp_specifique["parameters"]["dst_ip"]
        schedule = icmp_specifique["parameters"]["schedule"]

        ping_events = []

        for entry in schedule:
            src_ip = entry["src_ip"]
            for ts in entry["timestamps"]:
                timestamp = datetime.fromisoformat(ts)
                ping_events.append((timestamp, src_ip))

        # Trier les événements dans l'ordre chronologique
        ping_events.sort()

        print(f"Nombre total de pings planifiés : {len(ping_events)}")

        packets = []

        # Boucle principale d'attente et d'exécution
        for ts, src_ip in ping_events:
            pkt = IP(src=src_ip, dst=dst_ip) / ICMP() / b"ping-test"
            pkt.time = time.mktime(ts.timetuple())  # Assigner le timestamp au paquet
            packets.append(pkt)

            # Écrire les paquets dans le fichier pcap
        wrpcap(output_pcap, packets)

        print(f"{len(packets)} paquets ICMP ont été écrits dans '{output_pcap}'")