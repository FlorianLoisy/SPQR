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


# Ajout des droit en execution des fichiers .sh .py
    
chmod +x spqr_launch.sh
chmod +x scripts/update_rules.sh
chmod +x example_test.py


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