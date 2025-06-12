import pytest
from scapy.all import *
from scripts.generate_traffic.protocols.dns_generator import DNSGenerator, DNSConfig

def test_dns_config():
    config = DNSConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20"
    )
    assert config.src_ip == "192.168.1.10"
    assert config.dst_port == 53  # default value

def test_dns_query_generation():
    config = DNSConfig(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        query_domain="example.com"
    )
    generator = DNSGenerator(config)
    packets = generator.generate()
    
    assert len(packets) == 2  # query + response
    assert DNS in packets[0]
    assert packets[0][DNS].qr == 0  # query
    assert packets[1][DNS].qr == 1  # response