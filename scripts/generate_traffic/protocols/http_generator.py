from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class HTTPConfig:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    method: str = "GET"
    path: str = "/"
    version: str = "1.1"
    host: str = "example.com"
    user_agent: str = "SPQR-Test-Agent"
    custom_headers: Dict = None
    body: str = ""

class HTTPGenerator(ProtocolGenerator):
    def __init__(self, config: HTTPConfig):
        self.config = config
        
    def generate(self) -> List[Packet]:
        # Déplacer la logique de generate_http_communication ici
        # ...existing HTTP generation code...