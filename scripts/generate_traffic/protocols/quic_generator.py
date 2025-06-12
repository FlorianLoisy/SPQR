from dataclasses import dataclass
from typing import List, Optional
from scapy.all import *
import os
import random

@dataclass
class QUICConfig:
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: int = 443
    version: str = "1"
    src_mac: str = "02:42:ac:11:00:02"
    dst_mac: str = "02:42:ac:11:00:03"
    dcid_len: int = 8
    scid_len: int = 8

class QUICGenerator:
    def __init__(self, config: QUICConfig):
        self.config = config
        if self.config.src_port is None:
            self.config.src_port = random.randint(49152, 65535)

    def generate(self) -> List[Packet]:
        """Génère une séquence de paquets QUIC"""
        packets = []
        
        # Initial Packet
        initial = (
            Ether(src=self.config.src_mac, dst=self.config.dst_mac) /
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            UDP(sport=self.config.src_port, dport=self.config.dst_port) /
            Raw(load=bytes([
                0xc3,  # Long header with Initial type
                0x00, 0x00, 0x00, int(self.config.version),  # Version
                self.config.dcid_len  # DCID Length
            ]) + os.urandom(self.config.dcid_len))  # Random DCID
        )
        
        # Handshake Packet
        handshake = (
            Ether(src=self.config.dst_mac, dst=self.config.src_mac) /
            IP(src=self.config.dst_ip, dst=self.config.src_ip) /
            UDP(sport=self.config.dst_port, dport=self.config.src_port) /
            Raw(load=bytes([0xe0]) + os.urandom(16))  # Handshake type + random data
        )
        
        packets.extend([initial, handshake])
        return packets