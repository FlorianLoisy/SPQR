from abc import ABC, abstractmethod
from typing import List
from scapy.packet import Packet

class ProtocolGenerator(ABC):
    """Classe de base abstraite pour tous les générateurs de protocoles"""
    
    @abstractmethod
    def generate(self) -> List[Packet]:
        """Génère les paquets pour ce protocole"""
        pass