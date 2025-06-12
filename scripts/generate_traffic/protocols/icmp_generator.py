from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass
from typing import List
import random
import time

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
    def __init__(self, config: ICMPConfig):
        super().__init__()
        self.config = config
        self.id = self.config.id or random.randint(1000, 65535)

    def generate(self) -> List[Packet]:
        packets = []
        
        for i in range(self.packet_count):
            # Créer la requête ICMP (ping)
            request = IP(src=self.config.src_ip, dst=self.config.dst_ip) / \
                     ICMP(type=self.config.icmp_type,
                          code=self.config.icmp_code,
                          id=self.id,
                          seq=i+1) / \
                     Raw(load=self.config.payload)
            
            # Créer la réponse ICMP (pong)
            response = IP(src=self.config.dst_ip, dst=self.config.src_ip) / \
                      ICMP(type=0, code=0, id=self.id, seq=i+1) / \
                      Raw(load=self.config.payload)
            
            packets.extend([request, response])
            
            if self.time_interval > 0 and i < self.packet_count - 1:
                time.sleep(self.time_interval / 1000)
        
        return packets