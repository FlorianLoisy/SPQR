from typing import Dict, Any, Optional
from .protocols.base_generator import ProtocolGenerator
from .protocols.http_generator import HTTPGenerator
from .protocols.dns_generator import DNSGenerator
from .protocols.icmp_generator import ICMPGenerator
from .protocols.quic_generator import QUICGenerator

class ProtocolGeneratorFactory:
    
    GENERATORS = {
        "http": HTTPGenerator,
        "dns": DNSGenerator,
        "icmp": ICMPGenerator,
        "quic": QUICGenerator
    }

    @classmethod
    def create_generator(cls, protocol_type: str, config: Dict[str, Any], custom_params: Optional[Dict[str, Any]] = None) -> ProtocolGenerator:
        generator_class = cls.GENERATORS.get(protocol_type.lower())
        if not generator_class:
            raise ValueError(f"Unsupported protocol type: {protocol_type}")
        if protocol_type.lower() == "http":
            return generator_class(config=config, http_params=custom_params)
        if custom_params:
            return generator_class(config=config, **custom_params)
        return generator_class(config=config)