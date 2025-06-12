import pytest
from scapy.all import *
from scripts.generate_traffic.protocols.quic_generator import QUICGenerator, QUICConfig

def test_quic_config():
    config = QUICConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20"
    )
    assert config.src_ip == "192.168.1.10"
    assert config.dst_port == 443  # default value

def test_quic_packet_generation():
    config = QUICConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345
    )
    generator = QUICGenerator(config)
    packets = generator.generate()
    
    assert len(packets) == 3  # Initial + Handshake + Data
    assert all(UDP in p for p in packets)
    assert all(p[UDP].dport == 443 for p in packets)
    assert all(Raw in p for p in packets)