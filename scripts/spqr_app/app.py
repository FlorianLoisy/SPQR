import streamlit as st
import os
import zipfile
import json
import logging
from pathlib import Path
from scripts.process.process import SPQRSimple
from datetime import datetime

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
        # Attack Type Selection
        attack_type = st.selectbox(
            "Type d'attaque",
            spqr_web.spqr.list_attack_types()
        )
        
        if st.button("🚀 Lancer le Test Rapide"):
            with st.spinner("Génération et analyse en cours..."):
                try:
                    result = spqr_web.spqr.quick_test(attack_type)
                    if isinstance(result, dict) and 'pcap_file' in result:
                        st.success(f"Test terminé! PCAP généré: {Path(result['pcap_file']).name}")
                        st.session_state['last_result'] = result
                except Exception as e:
                    st.error(f"Erreur: {str(e)}")

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

