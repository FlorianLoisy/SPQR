import streamlit as st
import os
import zipfile
import json
import logging
from pathlib import Path
from scripts.process.process import SPQRSimple
from datetime import datetime
from typing import Dict, List

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class SPQRWeb:
    def __init__(self):
        self.spqr = SPQRSimple()
        self.load_config()
        
    def load_config(self):
        config_path = "config/config.json"
        logger.debug(f"Loading config from: {os.path.abspath(config_path)}")
        with open(config_path) as f:
            self.config = json.load(f)
            
        # Charger les configurations des protocoles
        self.protocol_configs = {}
        for protocol in ["http", "dns", "icmp", "quic"]:
            try:
                with open(f"config/protocols/{protocol}_config.json") as f:
                    self.protocol_configs[protocol] = json.load(f)
            except FileNotFoundError:
                logger.warning(f"No config found for {protocol}")

    def get_available_engines(self) -> List[Dict]:
        """Get list of configured IDS engines"""
        return self.config.get("engines", [
            {"type": "suricata", "version": "6.0.15"},
            {"type": "suricata", "version": "7.0.2"},
            {"type": "snort", "version": "2.9"},
            {"type": "snort", "version": "3"}
        ])

def show_pcap_generation():
    st.header("🔰 Générateur de PCAP")
    
    # Layout principal
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Sélection du type d'attaque
        attack_type = st.selectbox(
            "Type de trafic à générer",
            spqr_web.spqr.list_attack_types(),
            help="Sélectionnez le type de trafic que vous souhaitez générer"
        )
        
        # Description du type sélectionné
        if attack_type in spqr_web.config["traffic_patterns"]:
            st.info(spqr_web.config["traffic_patterns"][attack_type]["description"])
            
        # Configuration du protocole
        st.subheader("Configuration du Protocole")
        protocol_type = spqr_web.config["traffic_patterns"][attack_type].get("payload_type", "http")
        
        # Chargement de la configuration du protocole
        config_path = f"config/protocols/{protocol_type}_config.json"
        try:
            with open(config_path) as f:
                protocol_config = json.load(f)
                
            # Interface de configuration du protocole
            with st.expander(f"Configuration {protocol_type.upper()}", expanded=True):
                edited_config = {}
                
                # Paramètres de base
                st.markdown("#### Paramètres de base")
                cols = st.columns(2)
                with cols[0]:
                    for key, value in protocol_config["default"].items():
                        if isinstance(value, bool):
                            edited_config[key] = st.checkbox(
                                f"{key}", value,
                                help=f"Configuration de {key}"
                            )
                        elif isinstance(value, int):
                            edited_config[key] = st.number_input(
                                f"{key}", value=value,
                                help=f"Configuration de {key}"
                            )
                        elif isinstance(value, dict):
                            st.json(value)
                        else:
                            edited_config[key] = st.text_input(
                                f"{key}", value,
                                help=f"Configuration de {key}"
                            )
                
                # Paramètres avancés
                if "attacks" in protocol_config and attack_type in protocol_config["attacks"]:
                    st.markdown("#### Paramètres spécifiques à l'attaque")
                    attack_params = protocol_config["attacks"][attack_type]
                    for key, value in attack_params.items():
                        edited_config[key] = st.text_input(
                            f"{key} (spécifique)", 
                            value,
                            help=f"Paramètre spécifique pour {attack_type}"
                        )
                
        except FileNotFoundError:
            st.warning(f"Pas de configuration trouvée pour {protocol_type}")
            edited_config = {}
    
    with col2:
        # Paramètres réseau
        st.subheader("Paramètres réseau")
        network_config = {
            "src_ip": st.text_input(
                "IP Source",
                value=spqr_web.config["network"]["source_ip"]
            ),
            "dst_ip": st.text_input(
                "IP Destination",
                value=spqr_web.config["network"]["dest_ip"]
            ),
            "src_port": st.number_input(
                "Port Source",
                value=int(spqr_web.config["network"].get("source_port", 1234))
            ),
            "dst_port": st.number_input(
                "Port Destination",
                value=int(spqr_web.config["network"].get("dest_port", 80))
            )
        }
        
        # Options de génération
        st.subheader("Options")
        options = {
            "packet_count": st.number_input("Nombre de paquets", 1, 1000, 10),
            "time_interval": st.slider("Intervalle (ms)", 0, 1000, 100)
        }
    
    # Bouton de génération
    if st.button("🚀 Générer PCAP"):
        with st.spinner("Génération du fichier PCAP en cours..."):
            try:
                # Combiner toutes les configurations
                generation_config = {
                    "network": network_config,
                    "protocol": edited_config,
                    "options": options
                }
                
                # Générer le PCAP avec la configuration complète
                result = spqr_web.spqr.generate_pcap(
                    attack_type,
                    config=generation_config
                )
                
                if isinstance(result, dict) and 'pcap_file' in result:
                    pcap_path = Path(result['pcap_file'])
                    st.success(f"✅ PCAP généré avec succès!")
                    
                    # Afficher les détails du fichier
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Taille", f"{pcap_path.stat().st_size / 1024:.2f} KB")
                    with col2:
                        st.metric("Paquets", options["packet_count"])
                    with col3:
                        st.download_button(
                            "📥 Télécharger PCAP",
                            data=pcap_path.read_bytes(),
                            file_name=pcap_path.name,
                            mime="application/vnd.tcpdump.pcap"
                        )
                    
                    # Aperçu du PCAP
                    with st.expander("Aperçu du PCAP"):
                        st.code(f"tcpdump -r {pcap_path} -n")
                        
                else:
                    st.error("❌ Erreur lors de la génération du PCAP")
            except Exception as e:
                st.error(f"❌ Erreur: {str(e)}")

def show_protocol_config():
    st.header("⚙️ Configuration des Protocoles")
    
    # Sélection du protocole
    protocol = st.selectbox(
        "Protocole à configurer",
        ["HTTP", "DNS", "ICMP", "QUIC"]
    )
    
    # Charger la configuration actuelle
    config_path = f"config/protocols/{protocol.lower()}_config.json"
    with open(config_path) as f:
        config = json.load(f)
    
    # Interface d'édition
    st.subheader("Configuration par défaut")
    edited_config = {"default": {}}
    
    # Édition des valeurs par défaut
    with st.expander("Valeurs par défaut", expanded=True):
        for key, value in config["default"].items():
            if isinstance(value, bool):
                edited_config["default"][key] = st.checkbox(key, value)
            elif isinstance(value, int):
                edited_config["default"][key] = st.number_input(key, value=value)
            elif isinstance(value, dict):
                st.json(value)  # Pour l'instant, afficher uniquement
            else:
                edited_config["default"][key] = st.text_input(key, value)
    
    # Édition des configurations d'attaque
    st.subheader("Configurations d'attaque")
    edited_config["attacks"] = {}
    
    for attack_name, attack_config in config.get("attacks", {}).items():
        with st.expander(f"Attaque: {attack_name}"):
            edited_config["attacks"][attack_name] = {}
            for key, value in attack_config.items():
                edited_config["attacks"][attack_name][key] = st.text_input(
                    f"{attack_name} - {key}", 
                    value
                )
    
    # Bouton de sauvegarde
    if st.button("💾 Sauvegarder la configuration"):
        with open(config_path, "w") as f:
            json.dump(edited_config, f, indent=2)
        st.success("Configuration sauvegardée!")

def main():
    st.set_page_config(
        page_title="SPQR - Security Package for Quick Response",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize SPQR
    global spqr_web
    spqr_web = SPQRWeb()

    # Sidebar Navigation
    with st.sidebar:
        st.title("SPQR Navigation")
        page = st.radio(
            "Navigation",
            ["Génération PCAP", "Test Rapide", "Configuration Protocoles"]
        )

    # Main Content based on selection
    if page == "Génération PCAP":
        show_pcap_generation()
    elif page == "Test Rapide":
        st.header("Test Rapide de Règles")
        
        col1, col2 = st.columns([2, 1])
        with col1:
            # Attack Type Selection
            attack_type = st.selectbox(
                "Type d'attaque",
                spqr_web.spqr.list_attack_types()
            )
        with col2:
            # Engine Selection
            selected_engines = st.multiselect(
                "Sélectionner les IDS",
                options=[f"{e['type']}-{e['version']}" for e in spqr_web.get_available_engines()],
                default=[f"{e['type']}-{e['version']}" for e in spqr_web.get_available_engines()]
            )
        
        if st.button("🚀 Lancer le Test Rapide"):
            with st.spinner("Génération et analyse en cours..."):
                try:
                    # Generate PCAP first
                    pcap_result = spqr_web.spqr.generate_pcap(attack_type)
                    if not pcap_result or 'error' in pcap_result:
                        st.error(f"Erreur lors de la génération du PCAP: {pcap_result.get('error', 'Unknown error')}")
                        return

                    # Show PCAP info
                    pcap_file = pcap_result['pcap_file']
                    st.success(f"PCAP généré: {Path(pcap_file).name}")

                    # Test with each selected engine
                    results = {}
                    for engine_id in selected_engines:
                        engine_type, version = engine_id.split('-')
                        with st.spinner(f"Test avec {engine_type} {version}..."):
                            result = spqr_web.spqr.test_with_engine(
                                pcap_file, 
                                engine_type=engine_type, 
                                version=version
                            )
                            results[engine_id] = result

                    # Display results in tabs
                    if results:
                        tabs = st.tabs(list(results.keys()))
                        for tab, (engine_id, result) in zip(tabs, results.items()):
                            with tab:
                                if 'error' in result:
                                    st.error(f"Erreur: {result['error']}")
                                else:
                                    if result.get('log_file') and os.path.exists(result['log_file']):
                                        with open(result['log_file']) as f:
                                            st.code(f.read())
                                    if result.get('alert_count'):
                                        st.metric("Alertes détectées", result['alert_count'])

                    st.session_state['last_results'] = results

                except Exception as e:
                    st.error(f"Erreur: {str(e)}")
                    logger.exception("Erreur lors du test rapide")

    elif page == "Test Manuel":
        st.header("Test Manuel avec Fichiers")
        pcap_file = st.file_uploader("Sélectionner un fichier PCAP", type=['pcap', 'pcapng'])
        rules_file = st.file_uploader("Sélectionner un fichier de règles (optionnel)", type=['rules'])
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Tester les Règles"):
                if pcap_file:
                    # Implement manual test logic
                    st.info("Test manuel en cours...")
        with col2:
            if st.button("Générer Rapport"):
                st.info("Génération du rapport...")

    elif page == "Configuration Protocoles":
        show_protocol_config()

    else:  # Logs
        st.header("Logs d'Exécution")
        
        # Display logs
        if 'logs' not in st.session_state:
            st.session_state.logs = []
        
        log_viewer = st.empty()
        log_viewer.code('\n'.join(st.session_state.logs))
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Effacer Logs"):
                st.session_state.logs = []
                log_viewer.code('')
        with col2:
            if st.button("Sauvegarder Logs"):
                # Save logs logic
                st.download_button(
                    "📥 Télécharger les logs",
                    '\n'.join(st.session_state.logs),
                    "spqr_logs.txt",
                    "text/plain"
                )

if __name__ == "__main__":
    main()

