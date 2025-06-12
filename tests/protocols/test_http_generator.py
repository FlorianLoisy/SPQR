import pytest
from scapy.all import *
from scripts.generate_traffic.protocols.http_generator import HTTPGenerator, HTTPConfig

def test_http_config():
    config = HTTPConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345
    )
    assert config.src_ip == "192.168.1.10"
    assert config.dst_port == 80  # default value

def test_http_generator_basic():
    config = HTTPConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=12345
    )
    generator = HTTPGenerator(config)
    packets = generator.generate()
    
    assert len(packets) >= 7  # handshake + request + response + teardown
    assert all(isinstance(p, Packet) for p in packets)
    assert all(TCP in p for p in packets)