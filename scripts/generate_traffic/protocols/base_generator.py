from abc import ABC, abstractmethod
from typing import List
from scapy.packet import Packet

class ProtocolGenerator(ABC):
    """Classe de base abstraite pour tous les générateurs de protocoles"""
    
    def __init__(self):
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