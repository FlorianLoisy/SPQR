from scapy.all import *
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class ICMPConfig:
    src_ip: str
    dst_ip: str
    src_mac: str = "02:42:ac:11:00:02"
    dst_mac: str = "02:42:ac:11:00:03"
    nbre_ping: int = 4
    icmp_data: str = "SPQR-ICMP-TEST"
    icmp_id: int = 12345

class ICMPGenerator:
    def __init__(self, config: ICMPConfig):
        self.config = config
        
    def generate_ping(self) -> List[Packet]:
        """Génère une séquence de pings ICMP"""
        packets = []
        
        if isinstance(self.config.icmp_data, str):
            icmp_data = self.config.icmp_data.encode()
        else:
            icmp_data = self.config.icmp_data

        for seq in range(1, self.config.nbre_ping + 1):
            # Request
            icmp_request = (
                Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
                IP(src=self.config.src_ip, dst=self.config.dst_ip) /
                ICMP(type="echo-request", id=self.config.icmp_id, seq=seq) /
                Raw(load=icmp_data)
            )
            
            # Reply
            icmp_reply = (
                Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
                IP(src=self.config.dst_ip, dst=self.config.src_ip) /
                ICMP(type="echo-reply", id=self.config.icmp_id, seq=seq) /
                Raw(load=icmp_data)
            )
            
            packets.extend([icmp_request, icmp_reply])
            
        return packets

    def generate_port_scan(self, target_ports: List[int]) -> List[Packet]:
        """Génère des paquets ICMP port unreachable pour simulation de scan"""
        packets = []
        
        for port in target_ports:
            packet = (
                Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
                IP(src=self.config.src_ip, dst=self.config.dst_ip) /
                ICMP(type=3, code=3) /  # Port unreachable
                IP(src=self.config.src_ip, dst=self.config.dst_ip) /
                TCP(dport=port)
            )
            packets.append(packet)
            
        return packets