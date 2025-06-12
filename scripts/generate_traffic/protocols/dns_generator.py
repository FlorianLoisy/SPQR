from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass
from typing import Optional

@dataclass
class DNSConfig:
    client_ip: str
    dns_server_ip: str
    query_domain: str
    src_port: int = 53000
    custom_payload: Optional[bytes] = None

class DNSGenerator(ProtocolGenerator):
    def __init__(self, config: DNSConfig):
        self.config = config
        
    def generate(self) -> List[Packet]:
        # Déplacer la logique de generate_dns_communication ici
        # ...existing DNS generation code...