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

    def get_available_engines(self) -> List[Dict]:
        """Get list of configured IDS engines"""
        return self.config.get("engines", [
            {"type": "suricata", "version": "6.0.15"},
            {"type": "suricata", "version": "7.0.2"},
            {"type": "snort", "version": "2.9"},
            {"type": "snort", "version": "3"}
        ])

def main():
    st.set_page_config(
        page_title="SPQR - Security Package for Quick Response",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize SPQR
    spqr_web = SPQRWeb()

    # Sidebar Navigation
    with st.sidebar:
        st.title("SPQR Navigation")
        page = st.radio(
            "Select Page",
            ["Test Rapide", "Test Manuel", "Configuration", "Logs"]
        )

    # Main Content based on selection
    if page == "Test Rapide":
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

    elif page == "Configuration":
        st.header("Configuration SPQR")
        
        # Network Configuration
        st.subheader("Configuration Réseau")
        col1, col2 = st.columns(2)
        with col1:
            source_ip = st.text_input("IP Source", value="192.168.1.10")
            source_port = st.text_input("Port Source", value="1234")
        with col2:
            dest_ip = st.text_input("IP Destination", value="192.168.1.20")
            dest_port = st.text_input("Port Destination", value="80")
            
        # Output Directory
        st.subheader("Répertoire de Sortie")
        output_dir = st.text_input("Répertoire de sortie", value="output")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Sauvegarder Configuration"):
                # Save config logic
                st.success("Configuration sauvegardée!")
        with col2:
            if st.button("Charger Configuration"):
                # Load config logic
                st.info("Configuration chargée!")
        with col3:
            if st.button("Réinitialiser"):
                # Reset config logic
                st.info("Configuration réinitialisée!")

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

