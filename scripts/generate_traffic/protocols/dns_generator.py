from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class DNSConfig:
    src_ip: str
    dst_ip: str
    src_port: int = 53000
    dst_port: int = 53
    query_domain: str = "example.com"
    record_type: str = "A"
    src_mac: str = "02:42:ac:11:00:02"
    dst_mac: str = "02:42:ac:11:00:03"
    custom_payload: Optional[bytes] = None

class DNSGenerator(ProtocolGenerator):
    def __init__(self, config: DNSConfig):
        self.config = config

    def generate(self) -> List[Packet]:
        """Génère une séquence de paquets DNS"""
        packets = []
        
        # DNS Query
        dns_query = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            UDP(sport=self.config.src_port, dport=self.config.dst_port) /
            DNS(
                rd=1,  # Recursion Desired
                qd=DNSQR(qname=self.config.query_domain, qtype=self.config.record_type)
            )
        )
        
        # DNS Response
        dns_response = (
            Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
            IP(src=self.config.dst_ip, dst=self.config.src_ip) /
            UDP(sport=self.config.dst_port, dport=self.config.src_port) /
            DNS(
                qr=1,  # Response
                aa=1,  # Authoritative Answer
                rd=1,  # Recursion Desired
                ra=1,  # Recursion Available
                qd=DNSQR(qname=self.config.query_domain, qtype=self.config.record_type),
                an=DNSRR(
                    rrname=self.config.query_domain,
                    type=self.config.record_type,
                    ttl=3600,
                    rdata="192.0.2.1"
                )
            )
        )
        
        packets.extend([dns_query, dns_response])
        return packets