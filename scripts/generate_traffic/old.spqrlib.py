import json
from scapy.all import *
import random
import struct
from typing import List, Optional

from .protocols.http_generator import HTTPGenerator, HTTPConfig
from .protocols.dns_generator import DNSGenerator, DNSConfig
from .protocols.icmp_generator import ICMPGenerator, ICMPConfig
from .protocols.quic_generator import QUICGenerator, QUICConfig

class FlowGenerator:
    """
    Classe pour générer différents types de flux réseau.

    Attributes:
     - packets (list): Liste des paquets générés.
    """

    def __init__(self, config: dict):
        """
        Initialise une instance de FlowGenerator.

        Parameters:

        """
        self.config = config
        self.packets = []

    def generate_tcp_handshake(self, src_ip, dst_ip, src_port, dst_port):
        tcp_config = config_data["tcp"]
        src_ip = tcp_config["DEFAULT_SRC_IP"]
        dst_ip = tcp_config["DEFAULT_DST_IP"]
        src_mac = "02:42:ac:11:00:02"
        dst_mac = "02:42:ac:11:00:03"

        paquet_syn = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="S")
        )
        paquet_syn_ack = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(
                sport=dst_port, dport=src_port, flags="SA", ack=paquet_syn[TCP].seq + 1
            )
        )
        paquet_ack = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags="A",
                seq=paquet_syn_ack[TCP].ack,
                ack=paquet_syn_ack[TCP].ack,
            )
        )

        handshake = paquet_syn, paquet_syn_ack, paquet_ack
        self.packets.append(handshake)

    def generate_http_communication(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        http_method,
        http_path,
        http_version,
        http_host,
        user_agent,
        custom_headers,
        http_body,
    ):
        """
        Génère une communication HTTP et l'ajoute à la liste des paquets.
        """
        tcp_config = config_data["tcp"]
        http_config = config_data["http"]
        src_ip = tcp_config["DEFAULT_SRC_IP"]
        dst_ip = tcp_config["DEFAULT_DST_IP"]
        src_port = http_config["DEFAULT_SRC_PORT"]
        dst_port = http_config["DEFAULT_DST_PORT"]
        http_method = http_config["DEFAULT_HTTP_METHOD"]
        http_path = http_config["DEFAULT_HTTP_PATH"]
        http_version = http_config["DEFAULT_HTTP_VERSION"]
        http_host = http_config["DEFAULT_HTTP_HOST"]
        user_agent = http_config["DEFAULT_USER_AGENT"]
        custom_headers = http_config["DEFAULT_CUSTOM_HEADERS"]
        http_body = http_config["DEFAULT_HTTP_BODY"]
        response_payload = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Rendez-vous prévu à 17h derrière la cours de l'école.</h1></body></html>"
        sequence_number = 1
        src_mac = "02:42:ac:11:00:02"
        dst_mac = "02:42:ac:11:00:03"
        
        if custom_headers is None:
            custom_headers = {}

        http_request_line = f"{http_method} {http_path} HTTP/{http_version}\r\n"
        http_headers = f"Host: {http_host}\r\nUser-Agent: {user_agent}\r\n" + "\r\n".join(
            [f"{key}: {value}" for key, value in custom_headers.items()]
        ) + "\r\n\r\n"
        http_body_encoded = http_body.encode() if http_body else b""

        http_request = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags="PA",
                seq=sequence_number,
                ack=sequence_number,
            )
            / Raw(load=http_request_line.encode() + http_headers.encode() + http_body_encoded)
        )

        http_response = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(
                sport=dst_port,
                dport=src_port,
                flags="PA",
                seq=http_request[TCP].ack,
                ack=len(http_request[Raw]) + 1,
            )
            / response_payload
        )

        http_client_ack = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags="A",
                seq=http_response[TCP].ack,
                ack=len(http_response[Raw]) + 1,
            )
        )

        http_serveur_ask_close = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(
                sport=dst_port,
                dport=src_port,
                flags="FA",
                seq=http_client_ack[TCP].ack,
                ack=http_client_ack[TCP].seq,
            )
        )

        http_client_ack_close = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags="A",
                seq=http_serveur_ask_close[TCP].ack,
                ack=http_serveur_ask_close[TCP].seq + 1,
            )
        )

        http_client_fin_ack_close = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags="FA",
                seq=http_serveur_ask_close[TCP].ack,
                ack=http_serveur_ask_close[TCP].seq + 1,
            )
        )

        http_serveur_close = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=dst_ip, dst=src_ip)
            / TCP(
                sport=dst_port,
                dport=src_port,
                flags="A",
                seq=http_client_fin_ack_close[TCP].ack,
                ack=http_client_fin_ack_close[TCP].seq + 1,
            )
        )

        http_communication = (
            http_request,
            http_response,
            http_client_ack,
            http_serveur_ask_close,
            http_client_ack_close,
            http_client_fin_ack_close,
            http_serveur_close,
        )
        self.packets.append(http_communication)

    def generate_dns_communication(
        self, client_ip, src_port, dns_server_ip, query_domain, custom_payload
    ):
        """
        Génère une communication DNS et l'ajoute à la liste des paquets.
        """
        dns_config = config_data["dns"]
        src_port = dns_config["DEFAULT_SRC_PORT"]
        client_ip = dns_config["DEFAULT_CLIENT_IP"]
        dns_server_ip = dns_config["DEFAULT_DNS_SERVER_IP"]
        query_domain = dns_config["DEFAULT_QUERY_DOMAIN"]
        custom_payload = dns_config["DEFAULT_CUSTOM_PAYLOAD"]
        src_mac = "02:42:ac:11:00:02"
        dst_mac = "02:42:ac:11:00:03"
        
        if custom_payload is not None and not isinstance(custom_payload, bytes):
            raise ValueError("Custom DNS payload must be a bytes-like object")

        dns_query = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(dst=dns_server_ip)
            / UDP(dport=53, sport=src_port)
            / DNS(qr=0, qd=DNSQR(qname=query_domain))  # Query
        )

        if custom_payload is not None:
            dns_query[DNS].payload = custom_payload

        dns_response = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=dns_server_ip, dst=client_ip)
            / UDP(dport=src_port, sport=53)
            / DNS(
                qr=1,  # Response
                qd=DNSQR(qname=query_domain),
                an=DNSRR(rrname=query_domain, ttl=3600, rdata="192.168.1.1"),
            )
        )

        dns_flux = (dns_query, dns_response)

        self.packets.append(dns_flux)
        print(self.packets)

    def generate_icmp_communication(self, src_ip, dst_ip, icmp_data):
        """
        Génère une communication ICMP et l'ajoute à la liste des paquets.
        """
        config = ICMPConfig(
            src_ip=src_ip or self.config["icmp"]["DEFAULT_SRC_IP"],
            dst_ip=dst_ip or self.config["icmp"]["DEFAULT_DST_IP"],
            icmp_data=icmp_data or self.config["icmp"]["DEFAULT_ICMP_DATA"],
            nbre_ping=int(self.config["icmp"]["DEFAULT_NBRE_PING"])
        )
        generator = ICMPGenerator(config)
        self.packets.extend(generator.generate_ping())

    def generate_quic_traffic(src_ip: str, dst_ip: str, src_port: Optional[int] = None, dst_port: int = 443) -> List[Packet]:
        """
        Génère du trafic QUIC simulé
        """
        if src_port is None:
            src_port = random.randint(49152, 65535)

        packets = []

        # Initial Packet
        initial_packet = (
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=src_port, dport=dst_port) /
            Raw(load=bytes([
                0xc3,  # Long header with packet type Initial
                0x00, 0x00, 0x00, 0x01,  # Version 1
                0x08  # DCID Length
            ]) + os.urandom(8))  # Random Connection ID
        )
        packets.append(initial_packet)

        # Handshake Packet
        handshake_packet = (
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=src_port, dport=dst_port) /
            Raw(load=bytes([0xe0]) + os.urandom(16))  # Handshake type + random data
        )
        packets.append(handshake_packet)

        # Short Header (1-RTT) Packet
        data_packet = (
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=src_port, dport=dst_port) /
            Raw(load=bytes([0x40]) + os.urandom(31))  # 1-RTT type + random payload
        )
        packets.append(data_packet)

        return packets

def create_quic_pcap(output_file: str, src_ip: str, dst_ip: str) -> str:
    """
    Crée un fichier PCAP contenant du trafic QUIC simulé
    """
    packets = generate_quic_traffic(src_ip, dst_ip)
    wrpcap(output_file, packets)
    return output_file

class PcapGenerator:
    """
    Classe pour sauvegarder différents flux dans un fichier pcap.

    Attributes:
    - output_file (str): Le nom du fichier pcap de sortie.
    """

    def __init__(self):
        """
         Initialise une instance de FlowGenerator.

         Parameters:
         - output_file (str): Le nom du fichier pcap de sortie.
        self.output_file = "output_file.pcap"
         self.packets =[]
        """

    def save_to_pcap(self, absolute_pcap, packets):
        """
        Sauvegarde les paquets générés dans un fichier pcap.
        """
        wrpcap(absolute_pcap, packets)
        print(
            f"le pcap a été généré et est disponible dans le dossier suivant {absolute_pcap}."
        )

    def create_packets(
        http_checkbox,
        dns_checkbox,
        icmp_checkbox,
        pcap_path,
        current_datetime,
    ):
        packets = PcapGenerator.generate_packets(
            http_checkbox, dns_checkbox, icmp_checkbox
        )
        pcap_gen = PcapGenerator()
        output_pcap = "output_" + current_datetime + ".pcap"
        absolute_pcap = pcap_path + "/" + output_pcap
        pcap_gen.save_to_pcap(absolute_pcap, packets)

    # Créez une fonction pour générer les paquets en fonction des cases cochées
    def generate_packets(http, dns, icmp):
        flow_gen = FlowGenerator()
        flow_gen.packets = []  # Réinitialisez la liste des paquets

        # Générez les paquets en fonction des cases cochées
        if http:
            flow_gen.generate_tcp_handshake(
                src_ip=config_data["tcp"]["DEFAULT_SRC_IP"],
                dst_ip=config_data["tcp"]["DEFAULT_DST_IP"],
                src_port=config_data["http"]["DEFAULT_SRC_PORT"],
                dst_port=config_data["http"]["DEFAULT_DST_PORT"],
            )
            flow_gen.generate_http_communication(
                src_ip=config_data["tcp"]["DEFAULT_SRC_IP"],
                dst_ip=config_data["tcp"]["DEFAULT_DST_IP"],
                src_port=config_data["http"]["DEFAULT_SRC_PORT"],
                dst_port=config_data["http"]["DEFAULT_DST_PORT"],
                http_method=config_data["http"]["DEFAULT_HTTP_METHOD"],
                http_path=config_data["http"]["DEFAULT_HTTP_PATH"],
                http_version=config_data["http"]["DEFAULT_HTTP_VERSION"],
                http_host=config_data["http"]["DEFAULT_HTTP_HOST"],
                user_agent=config_data["http"]["DEFAULT_USER_AGENT"],
                custom_headers=config_data["http"]["DEFAULT_CUSTOM_HEADERS"],
                http_body=config_data["http"]["DEFAULT_HTTP_BODY"],
            )

        if dns:
            flow_gen.generate_dns_communication(
                client_ip=config_data["dns"]["DEFAULT_CLIENT_IP"],
                src_port=config_data["dns"]["DEFAULT_SRC_PORT"], 
                dns_server_ip=config_data["dns"]["DEFAULT_DNS_SERVER_IP"],
                query_domain=config_data["dns"]["DEFAULT_QUERY_DOMAIN"],
                custom_payload=config_data["dns"]["DEFAULT_CUSTOM_PAYLOAD"],
            )

        if icmp:
            flow_gen.generate_icmp_communication(
                src_ip=config_data["icmp"]["DEFAULT_SRC_IP"],
                dst_ip=config_data["icmp"]["DEFAULT_DST_IP"],
                icmp_data=config_data["icmp"]["DEFAULT_ICMP_DATA"],
            )

        return flow_gen.packets

    def generate_pcap(attack_type: str, output_file: str, config: dict) -> None:
        """
        Fonction d'entrée pour SPQR CLI – Génère un PCAP basé sur un type d'attaque.
        """
        flow_gen = FlowGenerator()
        flow_gen.packets = []

        if attack_type == "web_attack":
            flow_gen.generate_tcp_handshake(
                src_ip=config["network"]["source_ip"],
                dst_ip=config["network"]["dest_ip"],
                src_port=config["network"]["source_port"],
                dst_port=config["network"]["dest_port"]
            )
            flow_gen.generate_http_communication(
                src_ip=config["network"]["source_ip"],
                dst_ip=config["network"]["dest_ip"],
                src_port=config["network"]["source_port"],
                dst_port=config["network"]["dest_port"],
                http_method=None,
                http_path=None,
                http_version=None,
                http_host=None,
                user_agent=None,
                custom_headers=None,
                http_body=None
            )

        elif attack_type == "data_exfiltration":
            flow_gen.generate_dns_communication(
                client_ip=None,
                src_port=None,
                dns_server_ip=None,
                query_domain=None,
                custom_payload=None
            )

        elif attack_type == "malware_c2":
            flow_gen.generate_tcp_handshake(
                src_ip=config["network"]["source_ip"],
                dst_ip=config["network"]["dest_ip"],
                src_port=config["network"]["source_port"],
                dst_port=443
            )
            flow_gen.generate_http_communication(
                src_ip=config["network"]["source_ip"],
                dst_ip=config["network"]["dest_ip"],
                src_port=config["network"]["source_port"],
                dst_port=443,
                http_method=None,
                http_path=None,
                http_version=None,
                http_host=None,
                user_agent=None,
                custom_headers=None,
                http_body="GET /malware_command HTTP/1.1"
            )

        elif attack_type == "dns_tunneling":
            flow_gen.generate_dns_communication(
                client_ip=None,
                src_port=None,
                dns_server_ip=None,
                query_domain="secret.data.exfil.example.com",
                custom_payload=b"hidden_data"
            )

        elif attack_type == "brute_force" or attack_type == "port_scan":
            # Pour l'instant, placeholder : ICMP ou ping pour reconnaissance
            flow_gen.generate_icmp_communication(
                src_ip=None,
                dst_ip=None,
                icmp_data=None
            )

        else:
            raise ValueError(f"Type d'attaque non supporté: {attack_type}")

        pkt_flat = [pkt for group in flow_gen.packets for pkt in group]  # aplatir
        PcapGenerator().save_to_pcap(output_file, pkt_flat)

generate_pcap = PcapGenerator.generate_pcap

# Ce fichier peut être supprimé une fois que tous les générateurs
# ont été migrés vers leurs propres fichiers