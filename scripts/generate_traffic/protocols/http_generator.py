from .base_generator import ProtocolGenerator
from scapy.all import *
from scapy.packet import Packet
from dataclasses import dataclass
from typing import List, Dict, Optional
import json
from pathlib import Path
import random
import time

@dataclass
class HTTPConfig:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int = 80
    method: str = "GET"
    path: str = "/"
    version: str = "1.1"
    host: str = "example.com"
    user_agent: str = "SPQR-Test-Agent"
    custom_headers: Dict = None
    body: str = ""

    def __post_init__(self):
        # Charger la configuration par défaut
        config_path = Path("config/protocols/http_config.json")
        with config_path.open() as f:
            config = json.load(f)
            defaults = config["default"]
            
        # Appliquer les valeurs par défaut
        for key, value in defaults.items():
            if not hasattr(self, key) or getattr(self, key) is None:
                setattr(self, key, value)
                
    @classmethod
    def load_attack_config(cls, attack_type: str, src_ip: str, dst_ip: str, src_port: int) -> 'HTTPConfig':
        """Charge une configuration d'attaque spécifique"""
        config_path = Path("config/protocols/http_config.json")
        with config_path.open() as f:
            config = json.load(f)
            
        # Créer la configuration de base
        instance = cls(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port)
        
        # Appliquer la configuration d'attaque si elle existe
        if attack_type in config.get("attacks", {}):
            attack_config = config["attacks"][attack_type]
            for key, value in attack_config.items():
                setattr(instance, key, value)
                
        return instance

class HTTPGenerator(ProtocolGenerator):
    def __init__(self, config: dict):
        super().__init__(config=config)

        # Convertir la config plate en HTTPConfig
        self.http_config = HTTPConfig(
            src_ip=self.source_ip,      # depuis ProtocolGenerator
            dst_ip=self.dest_ip,        # depuis ProtocolGenerator
            src_port=self.source_port,  # depuis ProtocolGenerator
            dst_port=self.dest_port     # depuis ProtocolGenerator
        )

        self.seq = random.randint(1000, 9999)
        self.ack = 0

    def generate(self) -> List[Packet]:
        all_packets = []
        
        for _ in range(self.packet_count):
            # Generate single HTTP transaction
            packets = []
            
            # TCP Handshake
            packets.extend(self._generate_handshake())
            
            # HTTP Request/Response
            request_payload = self._build_http_request()
            packets.extend(self._generate_http_request(request_payload))
            
            response_payload = self._build_http_response()
            packets.extend(self._generate_http_response(response_payload))
            
            # TCP Teardown
            packets.extend(self._generate_teardown())
            
            all_packets.extend(packets)
            
            # Reset sequence numbers for next transaction
            self.seq = random.randint(1000, 9999)
            self.ack = 0
            
            # Add delay if specified
            if self.time_interval > 0 and _ < self.packet_count - 1:
                time.sleep(self.time_interval / 1000)  # Convert ms to seconds
        
        return all_packets
    
    def _generate_handshake(self) -> List[Packet]:
        # SYN
        syn = IP(src=self.http_config.src_ip, dst=self.http_config.dst_ip) / \
              TCP(sport=self.http_config.src_port, dport=self.http_config.dst_port,
                  seq=self.seq, flags='S')
        
        # SYN-ACK
        self.ack = self.seq + 1
        syn_ack = IP(src=self.http_config.dst_ip, dst=self.http_config.src_ip) / \
                  TCP(sport=self.http_config.dst_port, dport=self.http_config.src_port,
                      seq=self.ack, ack=self.ack, flags='SA')
        
        # ACK
        self.seq = self.ack
        ack = IP(src=self.http_config.src_ip, dst=self.http_config.dst_ip) / \
              TCP(sport=self.http_config.src_port, dport=self.http_config.dst_port,
                  seq=self.seq, ack=self.ack + 1, flags='A')
        
        return [syn, syn_ack, ack]
    
    def _generate_http_request(self, payload: bytes) -> List[Packet]:
        # PSH-ACK with HTTP request
        self.seq += 1
        request = IP(src=self.http_config.src_ip, dst=self.http_config.dst_ip) / \
                 TCP(sport=self.http_config.src_port, dport=self.http_config.dst_port,
                     seq=self.seq, ack=self.ack + 1, flags='PA') / \
                 Raw(load=payload)
        
        # Server ACK
        server_ack = IP(src=self.http_config.dst_ip, dst=self.http_config.src_ip) / \
                    TCP(sport=self.http_config.dst_port, dport=self.http_config.src_port,
                        seq=self.ack + 1, ack=self.seq + len(payload), flags='A')
        
        self.seq += len(payload)
        self.ack += 1
        
        return [request, server_ack]
    
    def _generate_http_response(self, payload: bytes) -> List[Packet]:
        # PSH-ACK with HTTP response
        response = IP(src=self.http_config.dst_ip, dst=self.http_config.src_ip) / \
                  TCP(sport=self.http_config.dst_port, dport=self.http_config.src_port,
                      seq=self.ack, ack=self.seq, flags='PA') / \
                  Raw(load=payload)
        
        # Client ACK
        client_ack = IP(src=self.http_config.src_ip, dst=self.http_config.dst_ip) / \
                    TCP(sport=self.http_config.src_port, dport=self.http_config.dst_port,
                        seq=self.seq, ack=self.ack + len(payload), flags='A')
        
        self.ack += len(payload)
        
        return [response, client_ack]
    
    def _generate_teardown(self) -> List[Packet]:
        # FIN from client
        fin = IP(src=self.http_config.src_ip, dst=self.http_config.dst_ip) / \
              TCP(sport=self.http_config.src_port, dport=self.http_config.dst_port,
                  seq=self.seq, ack=self.ack, flags='FA')
        
        # FIN-ACK from server
        fin_ack = IP(src=self.http_config.dst_ip, dst=self.http_config.src_ip) / \
                  TCP(sport=self.http_config.dst_port, dport=self.http_config.src_port,
                      seq=self.ack, ack=self.seq + 1, flags='FA')
        
        # Final ACK from client
        last_ack = IP(src=self.http_config.src_ip, dst=self.http_config.dst_ip) / \
                   TCP(sport=self.http_config.src_port, dport=self.http_config.dst_port,
                       seq=self.seq + 1, ack=self.ack + 1, flags='A')
        
        return [fin, fin_ack, last_ack]
    
    def _build_http_request(self) -> bytes:
        """Construit la requête HTTP avec les paramètres configurés"""
        # Construire les en-têtes HTTP
        headers = {
            "Host": self.http_config.host,
            "User-Agent": self.http_config.user_agent,
            "Connection": "close"
        }
        
        # Ajouter les en-têtes personnalisés
        if self.http_config.custom_headers:
            headers.update(self.http_config.custom_headers)
        
        # Construire la requête
        request_lines = [
            f"{self.http_config.method} {self.http_config.path} HTTP/{self.http_config.version}",
            *[f"{k}: {v}" for k, v in headers.items()],
            "",  # Ligne vide pour séparer les en-têtes du corps
            self.http_config.body
        ]
        
        return "\r\n".join(request_lines).encode()
    
    def _build_http_response(self) -> bytes:
        """Construit une réponse HTTP basique"""
        response_lines = [
            "HTTP/1.1 200 OK",
            "Server: SPQR-Test-Server",
            "Content-Type: text/plain",
            "Connection: close",
            "",  # Ligne vide pour séparer les en-têtes du corps
            "Hello from SPQR!"
        ]
        
        return "\r\n".join(response_lines).encode()