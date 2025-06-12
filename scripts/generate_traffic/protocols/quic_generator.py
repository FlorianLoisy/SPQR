from scapy.all import *
from dataclasses import dataclass
from typing import List, Optional
import random

@dataclass
class QUICConfig:
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: int = 443
    version: str = "1"
    dcid_len: int = 8
    scid_len: int = 8

class QUICGenerator:
    def __init__(self, config: QUICConfig):
        self.config = config
        if self.config.src_port is None:
            self.config.src_port = random.randint(49152, 65535)

    def _generate_connection_id(self, length: int) -> bytes:
        """Génère un ID de connexion aléatoire"""
        return bytes([random.randint(0, 255) for _ in range(length)])

    def generate(self) -> List[Packet]:
        """Génère une séquence de paquets QUIC"""
        packets = []

        # Initial Packet
        dcid = self._generate_connection_id(self.config.dcid_len)
        scid = self._generate_connection_id(self.config.scid_len)
        
        initial_packet = (
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            UDP(sport=self.config.src_port, dport=self.config.dst_port) /
            Raw(load=bytes([
                0xc3,  # Long header with packet type Initial
                0x00, 0x00, 0x00, int(self.config.version),  # Version
                len(dcid),  # DCID Length
            ]) + dcid + bytes([
                len(scid)  # SCID Length
            ]) + scid)
        )
        packets.append(initial_packet)

        # Handshake Packet
        handshake_packet = (
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            UDP(sport=self.config.src_port, dport=self.config.dst_port) /
            Raw(load=bytes([0xe0]) + dcid + scid)  # Handshake type + CIDs
        )
        packets.append(handshake_packet)

        # Short Header (1-RTT) Packet
        data_packet = (
            IP(src=self.config.src_ip, dst=self.config.dst_ip) /
            UDP(sport=self.config.src_port, dport=self.config.dst_port) /
            Raw(load=bytes([0x40]) + dcid + b"SPQR-QUIC-PAYLOAD")
        )
        packets.append(data_packet)

        return packets