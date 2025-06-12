import streamlit as st
import os
import zipfile
import json
import logging
from pathlib import Path
from scripts.process.process import SPQRSimple
from datetime import datetime
from typing import Dict, List, Any
from scripts.utils.file_watcher import FileWatcher  # Changed from relative to absolute import

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class SPQRWeb:
    def __init__(self):
        self.spqr = SPQRSimple()
        self.file_watcher = FileWatcher()
        self.load_config()
        
    def load_config(self):
        """Load main config and protocol configs"""
        try:
            # Add main config to file watcher
            config_path = "config/config.json"
            self.file_watcher.add_watch(config_path)
            
            with open(config_path) as f:
                self.config = json.load(f)
            
            # Load and watch protocol configs
            self.protocol_configs = {}
            for protocol in ["http", "dns", "icmp", "quic"]:
                config_path = f"config/protocols/{protocol}_config.json"
                self.file_watcher.add_watch(config_path)
                try:
                    with open(config_path) as f:
                        self.protocol_configs[protocol] = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    logger.warning(f"Config issue for {protocol}: {str(e)}")
                    self.protocol_configs[protocol] = {"default": {}, "attacks": {}}
                    
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            raise

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
        protocol_type = spqr_web.config["traffic_patterns"][attack_type].get("payload_type", "http")
        protocol_config = spqr_web.protocol_configs[protocol_type]
        
        # Interface de configuration du protocole
        with st.expander(f"Configuration {protocol_type.upper()}", expanded=True):
            edited_config = {}
            
            try:
                # Configuration par défaut si attaque personnalisée
                if attack_type == "custom":
                    st.markdown("#### Configuration de base")
                    for key, value in protocol_config["default"].items():
                        edited_config[key] = _display_config_input(key, value)
                else:
                    # Afficher uniquement les paramètres spécifiques à l'attaque
                    attack_params = protocol_config["attacks"].get(attack_type, {}).get("parameters", {})
                    if attack_params:
                        st.markdown("#### Paramètres spécifiques")
                        for key, value in attack_params.items():
                            # Ne pas afficher les paramètres qui sont déjà dans la config par défaut
                            if key not in protocol_config["default"]:
                                edited_config[key] = _display_config_input(key, value)
                    
                    # Ajouter les paramètres par défaut nécessaires
                    for key, value in protocol_config["default"].items():
                        if key not in edited_config:
                            edited_config[key] = value
                            
            except Exception as e:
                logger.error(f"Error in protocol configuration: {str(e)}")
                st.error(f"Erreur de configuration: {str(e)}")
                return

    with col2:
        # Paramètres réseau
        st.subheader("Paramètres réseau")
        try:
            network_config = {
                "src_ip": st.text_input(
                    "IP Source",
                    value=spqr_web.config["network"].get("source_ip", "192.168.1.10")
                ),
                "dst_ip": st.text_input(
                    "IP Destination",
                    value=spqr_web.config["network"].get("dest_ip", "192.168.1.20")
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
        except Exception as e:
            logger.error(f"Error in network configuration: {str(e)}")
            st.error(f"Erreur de configuration réseau: {str(e)}")
            return

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
                # Log des configurations
                logger.debug(f"Attack type: {attack_type}")
                logger.debug(f"Protocol config: {edited_config}")
                logger.debug(f"Network config: {network_config}")
                logger.debug(f"Options: {options}")
                
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
                
                logger.debug(f"Generation result: {result}")  # Add this line
                
                if isinstance(result, dict):
                    if 'error' in result:
                        st.error(f"❌ Erreur: {result['error']}")
                        logger.error(f"PCAP generation error: {result['error']}")
                        return
                        
                    if 'pcap_file' in result:
                        pcap_path = Path(result['pcap_file'])
                        if not pcap_path.exists():
                            st.error("❌ Le fichier PCAP n'a pas été créé")
                            logger.error(f"PCAP file not found: {pcap_path}")
                            return
                            
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
                else:
                    st.error("❌ Format de résultat invalide")
                    logger.error(f"Invalid result format: {result}")
                    
            except Exception as e:
                logger.exception("Error during PCAP generation")
                st.error(f"❌ Erreur: {str(e)}")

def _display_config_input(key: str, value: Any) -> Any:
    """Affiche le widget approprié selon le type de valeur"""
    if isinstance(value, bool):
        return st.checkbox(key, value)
    elif isinstance(value, int):
        return st.number_input(key, value=value)
    elif isinstance(value, dict):
        return st.json(value)
    else:
        return st.text_input(key, str(value))

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

