from dataclasses import dataclass
from typing import List, Optional
from scapy.all import *

@dataclass
class ICMPConfig:
    src_ip: str
    dst_ip: str
    src_mac: str = "02:42:ac:11:00:02"
    dst_mac: str = "02:42:ac:11:00:03"
    icmp_type: int = 8  # Echo Request
    icmp_code: int = 0
    payload: str = "SPQR-ICMP-TEST"
    count: int = 4
    id: int = 12345

class ICMPGenerator:
    def __init__(self, config: ICMPConfig):
        self.config = config

    def generate(self) -> List[Packet]:
        """Génère une séquence de paquets ICMP"""
        packets = []
        
        for seq in range(self.config.count):
            # ICMP Request
            icmp_request = (
                Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
                IP(src=self.config.src_ip, dst=self.config.dst_ip) /
                ICMP(
                    type=self.config.icmp_type,
                    code=self.config.icmp_code,
                    id=self.config.id,
                    seq=seq
                ) /
                Raw(load=self.config.payload)
            )
            
            # ICMP Reply
            icmp_reply = (
                Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
                IP(src=self.config.dst_ip, dst=self.config.src_ip) /
                ICMP(
                    type=0,  # Echo Reply
                    code=0,
                    id=self.config.id,
                    seq=seq
                ) /
                Raw(load=self.config.payload)
            )
            
            packets.extend([icmp_request, icmp_reply])
        
        return packets