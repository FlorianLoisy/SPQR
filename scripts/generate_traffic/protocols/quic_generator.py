from dataclasses import dataclass
from typing import List, Optional
from scapy.all import *
import os
import random
from .base_generator import ProtocolGenerator
from pathlib import Path
import json

@dataclass
class QUICConfig:
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: int = 443
    version: str = "1"
    src_mac: str = "02:42:ac:11:00:02"
    dst_mac: str = "02:42:ac:11:00:03"
    dcid_len: int = 8
    scid_len: int = 8
    
    def __post_init__(self):
        # Charger la configuration par défaut
        config_path = Path("config/protocols/quic_config.json")
        with config_path.open() as f:
            config = json.load(f)
            defaults = config["default"]
            
        # Appliquer les valeurs par défaut
        for key, value in defaults.items():
            if not hasattr(self, key) or getattr(self, key) is None:
                setattr(self, key, value)

class QUICGenerator(ProtocolGenerator):
    def __init__(self, config: dict):
        super().__init__(config=config)
        self.quic_config = QUICConfig(
            source_ip=self.source_ip,
            dest_ip=self.dest_ip,
            source_port=self.source_port,
            dest_port=self.dest_port
        )
        if self.quic_config.source_port is None:
            self.quic_config.source_port = random.randint(49152, 65535)

    def generate(self) -> List[Packet]:
        """Génère une séquence de paquets QUIC"""
        packets = []
        for _ in range(self.packet_count):
            # Initial Packet
            initial = (
                Ether(src=self.quic_config.src_mac, dst=self.quic_config.dst_mac) /
                IP(src=self.quic_config.source_ip, dst=self.quic_config.dest_ip) /
                UDP(sport=self.quic_config.source_port, dport=self.quic_config.dest_port) /
                Raw(load=bytes([
                    0xc3,  # Long header with Initial type
                    0x00, 0x00, 0x00, int(self.quic_config.version),  # Version
                    self.quic_config.dcid_len  # DCID Length
                ]) + os.urandom(self.quic_config.dcid_len))  # Random DCID
            )
            packets.append(initial)
            
            if self.time_interval > 0:
                time.sleep(self.time_interval / 1000)  # Convert ms to seconds
                
        return packets
        
        packets.extend([initial, handshake])
        return packets