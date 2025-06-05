#!/bin/bash

# SPQR - Script d'Installation et Configuration
# Ce script automatise l'installation et la configuration de SPQR

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fonction pour vérifier si une commande existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Cloner le projet s'il n'existe pas encore
if [ ! -d "SPQR" ]; then
    echo "[INFO] Clonage du dépôt SPQR..."
    git clone https://github.com/FlorianLoisy/SPQR.git SPQR
    cd SPQR
else
    echo "[INFO] Le dossier SPQR existe déjà. Passage dans ce dossier..."
    cd SPQR
fi

# Fonction pour installer les dépendances Python
install_python_deps() {
    print_info "Installation des dépendances Python..."

    # Créer le fichier requirements.txt
    cat > requirements.txt << EOF
scapy>=2.4.5
python-json-logger>=2.0.0
tkinter-tooltip>=1.0.0
requests>=2.25.0
pandas>=1.3.0
matplotlib>=3.5.0
argparse>=1.4.0
pathlib>=1.0.0
EOF

    # Installer les dépendances
    if command_exists pip3; then
        pip3 install -r requirements.txt
    elif command_exists pip; then
        pip install -r requirements.txt
    else
        print_error "pip non trouvé. Veuillez installer pip."
        exit 1
    fi

    print_success "Dépendances Python installées"

    # Installer tkinter selon la distribution
    print_info "Vérification de tkinter (GUI)..."
    if command_exists apt-get; then
        sudo apt-get install -y python3-tk
    elif command_exists dnf; then
        sudo dnf install -y python3-tkinter
    elif command_exists pacman; then
        sudo pacman -S --noconfirm tk
    else
        print_warning "Gestionnaire de paquets inconnu : veuillez installer tkinter manuellement si besoin."
    fi
}

# Fonction pour construire les images Docker IDS
install_ids_engines() {
    print_info "Construction des images Docker IDS (Suricata & Snort)..."

    if [ -f "images_docker/install_docker.sh" ]; then
        bash images_docker/install_docker.sh
        print_success "Images Docker IDS construites avec succès"
    else
        print_warning "Script install_docker.sh introuvable. Construction manuelle nécessaire."
    fi
}

# Fonction pour créer la structure de répertoires
create_directory_structure() {
    print_info "Création de la structure de répertoires..."
    
    # Créer les répertoires nécessaires
    mkdir -p {config,input,output/{pcap,logs,reports},notebooks,scripts/{generate_path,generate_traffic,select_process},ressources}
    
    print_success "Structure de répertoires créée"
}

# Fonction pour créer les scripts d'aide
create_helper_scripts() {
    print_info "Création des scripts d'aide..."
    
    # Script de lancement rapide
    cat > spqr_launch.sh << 'EOF'
#!/bin/bash
# Script de lancement rapide SPQR

echo "=== SPQR - Network Rules Testing Tool ==="
echo "1. Interface graphique (GUI)"
echo "2. Interface en ligne de commande (CLI)"
echo "3. Test rapide"
echo "4. Aide"
echo ""
read -p "Sélectionnez une option [1-4]: " choice

case $choice in
    1)
        echo "Lancement de l'interface graphique..."
        python3 spqr_gui.py
        ;;
    2)
        echo "Interface en ligne de commande disponible avec: python3 spqr_cli.py"
        echo "Tapez 'python3 spqr_cli.py --help' pour voir les options"
        ;;
    3)
        echo "Types d'attaques disponibles:"
        python3 spqr_cli.py list
        echo ""
        read -p "Entrez le type d'attaque à tester: " attack_type
        python3 spqr_cli.py quick "$attack_type"
        ;;
    4)
        echo "=== AIDE SPQR ==="
        echo "SPQR est un outil de test de règles de détection réseau."
        echo ""
        echo "Utilisation en ligne de commande:"
        echo "  python3 spqr_cli.py quick <type_attaque>  # Test rapide"
        echo "  python3 spqr_cli.py generate <type>       # Génère du trafic"
        echo "  python3 spqr_cli.py test <fichier.pcap>   # Test avec PCAP"
        echo "  python3 spqr_cli.py list                  # Liste les types"
        echo ""
        echo "Interface graphique:"
        echo "  python3 spqr_gui.py"
        ;;
    *)
        echo "Option invalide"
        ;;
esac
EOF
    
    chmod +x spqr_launch.sh
    
    # Script de mise à jour des règles
    cat > scripts/update_rules.sh << 'EOF'
#!/bin/bash
# Script de mise à jour des règles Suricata

echo "Mise à jour des règles Suricata..."

# Télécharger les règles depuis Emerging Threats (exemple)
if command -v wget >/dev/null 2>&1; then
    wget -O /tmp/emerging.rules.tar.gz "https://rules.emergingthreats.net/open/suricata/rules/emerging.rules.tar.gz"
    tar -xzf /tmp/emerging.rules.tar.gz -C /tmp/
    
    # Copier les règles importantes
    cp /tmp/rules/emerging-*.rules config/ 2>/dev/null || true
    
    echo "Règles mises à jour"
else
    echo "wget non trouvé. Mise à jour manuelle nécessaire."
fi
EOF
    
    chmod +x scripts/update_rules.sh
    
    print_success "Scripts d'aide créés"
}

# Fonction pour créer un exemple de test
create_test_example() {
    print_info "Création d'un exemple de test..."
    
    cat > example_test.py << 'EOF'
#!/usr/bin/env python3
"""
Exemple d'utilisation de SPQR
Ce script montre comment utiliser SPQR programmatiquement
"""

from spqr_cli import SPQRSimple
import json

def main():
    print("=== Exemple d'utilisation SPQR ===")
    
    # Initialiser SPQR
    spqr = SPQRSimple()
    
    # Lister les types d'attaques disponibles
    print("\nTypes d'attaques disponibles:")
    for attack_type in spqr.list_attack_types():
        print(f"  - {attack_type}")
    
    # Effectuer un test rapide
    print("\nTest rapide avec 'web_attack':")
    results = spqr.quick_test("web_attack")
    
    if "error" in results:
        print(f"Erreur: {results['error']}")
    else:
        print("Test réussi!")
        print(f"PCAP: {results.get('pcap_file', 'N/A')}")
        print(f"Logs: {results.get('log_file', 'N/A')}")
        print(f"Rapport: {results.get('report_file', 'N/A')}")

if __name__ == "__main__":
    main()
EOF
    
    chmod +x example_test.py
    
    print_success "Exemple de test créé"
}

# Fonction pour afficher les informations finales
show_final_info() {
    echo ""
    echo "============================================"
    print_success "Installation SPQR terminée avec succès!"
    echo "============================================"
    echo ""
    echo "Pour commencer à utiliser SPQR:"
    echo ""
    echo "1. Lancement rapide:"
    echo "   ./spqr_launch.sh"
    echo ""
    echo "2. Interface graphique:"
    echo "   python3 spqr_gui.py"
    echo ""
    echo "3. Ligne de commande:"
    echo "   python3 spqr_cli.py --help"
    echo ""
    echo "4. Test rapide:"
    echo "   python3 spqr_cli.py quick web_attack"
    echo ""
    echo "5. Exemple programmatique:"
    echo "   python3 example_test.py"
    echo ""
    echo "Fichiers importants:"
    echo "  - config/config.json      : Configuration principale"
    echo "  - config/suricata.rules   : Règles de détection"
    echo "  - output/                 : Résultats des tests"
    echo ""
    echo "Documentation: Consultez le README.md pour plus d'informations"
    echo ""
}

# Fonction principale
main() {
    echo "============================================"
    echo "    SPQR - Installation et Configuration"
    echo "============================================"
    echo ""

    # Vérifier Python
    if ! command_exists python3; then
        print_error "Python 3 n'est pas installé. Veuillez l'installer avant de continuer."
        exit 1
    fi

    print_info "Python 3 détecté: $(python3 --version)"

    # Étapes d'installation
    install_python_deps
    install_ids_engines             # <== Ajouté ici
    create_directory_structure
    create_config_files
    create_helper_scripts
    create_test_example

    show_final_info
}

# Vérifier si le script est exécuté directement
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi