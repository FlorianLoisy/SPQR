from typing import Dict, Type
from .protocols.base_generator import ProtocolGenerator
from .protocols.http_generator import HTTPGenerator, HTTPConfig
from .protocols.dns_generator import DNSGenerator, DNSConfig
from .protocols.icmp_generator import ICMPGenerator, ICMPConfig
from .protocols.quic_generator import QUICGenerator, QUICConfig

class ProtocolGeneratorFactory:
    _generators = {
        "http": (HTTPGenerator, HTTPConfig),
        "dns": (DNSGenerator, DNSConfig),
        "icmp": (ICMPGenerator, ICMPConfig),
        "quic": (QUICGenerator, QUICConfig)
    }

    @classmethod
    def create_generator(cls, protocol_type: str, config: Dict) -> ProtocolGenerator:
        if protocol_type not in cls._generators:
            raise ValueError(f"Protocol {protocol_type} not supported")
            
        generator_class, config_class = cls._generators[protocol_type]
        config_instance = config_class(**config)
        return generator_class(config_instance)