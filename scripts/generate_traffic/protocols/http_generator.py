from .base_generator import ProtocolGenerator
from scapy.all import *
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json
from pathlib import Path

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
    custom_headers: Dict = field(default_factory=dict)
    body: str = ""
    src_mac: str = "02:42:ac:11:00:02"
    dst_mac: str = "02:42:ac:11:00:03"

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
    def __init__(self, config: HTTPConfig):
        self.config = config
        
    def generate(self) -> List[Packet]:
        """Génère une séquence complète de paquets HTTP"""
        packets = []
        
        # 1. TCP Handshake
        packets.extend(self._generate_tcp_handshake())
        
        # 2. HTTP Request
        packets.extend(self._generate_http_request())
        
        # 3. HTTP Response
        packets.extend(self._generate_http_response())
        
        # 4. TCP Teardown
        packets.extend(self._generate_tcp_teardown())
        
        return packets

    def _generate_tcp_handshake(self) -> List[Packet]:
        """Génère la séquence de handshake TCP"""
        # SYN
        syn = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            TCP(sport=self.config.src_port, dport=self.config.dst_port, flags="S")
        )
        
        # SYN-ACK
        syn_ack = (
            Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
            IP(src=self.config.dst_ip, dst=self.config.src_ip) /
            TCP(sport=self.config.dst_port, dport=self.config.src_port, flags="SA")
        )
        
        # ACK
        ack = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            TCP(sport=self.config.src_port, dport=self.config.dst_port, flags="A")
        )
        
        return [syn, syn_ack, ack]

    def _generate_http_request(self) -> List[Packet]:
        """Génère la requête HTTP"""
        # Construire l'en-tête HTTP
        headers = {
            "Host": self.config.host,
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            "Connection": "close"
        }
        headers.update(self.config.custom_headers)
        
        # Construire la requête HTTP complète
        http_request = (
            f"{self.config.method} {self.config.path} HTTP/{self.config.version}\r\n" +
            "\r\n".join(f"{k}: {v}" for k, v in headers.items()) +
            "\r\n\r\n" +
            self.config.body
        )
        
        # Paquet TCP avec la requête HTTP
        request_packet = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            TCP(sport=self.config.src_port, dport=self.config.dst_port, flags="PA") /
            Raw(load=http_request)
        )
        
        return [request_packet]

    def _generate_http_response(self) -> List[Packet]:
        """Génère la réponse HTTP"""
        # Réponse HTTP basique
        http_response = (
            "HTTP/1.1 200 OK\r\n"
            "Server: SPQR-Test-Server\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "Connection: close\r\n"
            "\r\n"
            "Hello, World!"
        )
        
        response_packet = (
            Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
            IP(src=self.config.dst_ip, dst=self.config.src_ip) /
            TCP(sport=self.config.dst_port, dport=self.config.src_port, flags="PA") /
            Raw(load=http_response)
        )
        
        return [response_packet]

    def _generate_tcp_teardown(self) -> List[Packet]:
        """Génère la séquence de fin de connexion TCP"""
        # FIN from client
        fin1 = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            TCP(sport=self.config.src_port, dport=self.config.dst_port, flags="FA")
        )
        
        # FIN-ACK from server
        fin_ack = (
            Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
            IP(src=self.config.dst_ip, dst=self.config.src_ip) /
            TCP(sport=self.config.dst_port, dport=self.config.src_port, flags="FA")
        )
        
        # Final ACK from client
        last_ack = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            TCP(sport=self.config.src_port, dport=self.config.dst_port, flags="A")
        )
        
        return [fin1, fin_ack, last_ack]