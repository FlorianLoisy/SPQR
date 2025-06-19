from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
from pathlib import Path

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

    def __post_init__(self):
        # Charger la configuration par défaut
        config_path = Path("config/protocols/dns_config.json")
        with config_path.open() as f:
            config = json.load(f)
            defaults = config["default"]
            
        # Appliquer les valeurs par défaut
        for key, value in defaults.items():
            if not hasattr(self, key) or getattr(self, key) is None:
                setattr(self, key, value)

class DNSGenerator(ProtocolGenerator):
    def __init__(self, config: dict):
        super().__init__(config=config)
        
        # Convertir la config plate en DNSConfig
        self.dns_config = DNSConfig(
            src_ip=self.source_ip,
            dst_ip=self.dest_ip,
            src_port=self.source_port,
            dst_port=self.dest_port
        )

    def generate(self) -> List[Packet]:
        """Génère une séquence de paquets DNS"""
        packets = []
        
        # DNS Query
        dns_query = (
            Ether(src=self.dns_config.src_mac, dst=self.dns_config.dst_mac) /
            IP(src=self.dns_config.src_ip, dst=self.dns_config.dst_ip) /
            UDP(sport=self.dns_config.src_port, dport=self.dns_config.dst_port) /
            DNS(
                rd=1,  # Recursion Desired
                qd=DNSQR(qname=self.dns_config.query_domain, qtype=self.dns_config.record_type)
            )
        )
        
        # DNS Response
        dns_response = (
            Ether(src=self.dns_config.dst_mac, dst=self.dns_config.src_mac) /
            IP(src=self.dns_config.dst_ip, dst=self.dns_config.src_ip) /
            UDP(sport=self.dns_config.dst_port, dport=self.dns_config.src_port) /
            DNS(
                qr=1,  # Response
                aa=1,  # Authoritative Answer
                rd=1,  # Recursion Desired
                ra=1,  # Recursion Available
                qd=DNSQR(qname=self.dns_config.query_domain, qtype=self.dns_config.record_type),
                an=DNSRR(
                    rrname=self.dns_config.query_domain,
                    type=self.dns_config.record_type,
                    ttl=3600,
                    rdata="192.0.2.1"
                )
            )
        )
        
        packets.extend([dns_query, dns_response])
        return packets