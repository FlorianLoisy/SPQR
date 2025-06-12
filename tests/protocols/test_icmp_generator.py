import pytest
from scapy.all import *
from scripts.generate_traffic.protocols.icmp_generator import ICMPGenerator, ICMPConfig

def test_icmp_config():
    config = ICMPConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20"
    )
    assert config.src_ip == "192.168.1.10"
    assert config.count == 4  # default value

def test_ping_generation():
    config = ICMPConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20"
    )
    generator = ICMPGenerator(config)
    packets = generator.generate()
    
    assert len(packets) == 8  # 4 pings * 2 (request + reply)
    assert all(ICMP in p for p in packets)
    assert any(p[ICMP].type == 8 for p in packets)  # echo request
    assert any(p[ICMP].type == 0 for p in packets)  # echo reply