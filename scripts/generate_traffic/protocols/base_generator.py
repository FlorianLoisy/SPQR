from abc import ABC, abstractmethod
from typing import List
from scapy.packet import Packet

class ProtocolGenerator(ABC):
    """Classe de base abstraite pour tous les générateurs de protocoles"""
    
    def __init__(self, config: dict):
        """Initialize protocol generator with configuration"""
        # Vérification et extraction des paramètres requis
        required_keys = ['source_ip', 'dest_ip', 'source_port', 'dest_port']
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required configuration parameter: {key}")
    
        self.source_ip = config.get('source_ip')
        self.dest_ip = config.get('dest_ip')
        self.source_port = config.get('source_port')
        self.dest_port = config.get('dest_port')
        self.config = config  # Store full config for additional parameters
        self.packet_count = 1
        self.time_interval = 0
    
    def set_options(self, options: dict):
        """Configure les options de génération"""
        self.packet_count = options.get('packet_count', 1)
        self.time_interval = options.get('time_interval', 0)
    
    @abstractmethod
    def generate(self) -> List[Packet]:
        """Génère une liste de paquets"""
        pass