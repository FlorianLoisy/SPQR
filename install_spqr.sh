#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Fonction de log
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Vérification des prérequis
check_prerequisites() {
    log "Vérification des prérequis..."
    
    # Vérifier Docker
    if ! command -v docker &> /dev/null; then
        error "Docker n'est pas installé. Installation..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        warn "Veuillez vous déconnecter et vous reconnecter pour utiliser Docker sans sudo"
    fi

    # Vérifier Docker Compose
    if ! command -v docker compose &> /dev/null; then
        error "Docker Compose n'est pas installé"
        sudo apt-get update && sudo apt-get install -y docker-compose-plugin
    fi

    # Vérifier Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 n'est pas installé"
        sudo apt-get update && sudo apt-get install -y python3 python3-pip
    fi
}

# Préparation de l'environnement
setup_environment() {
    log "Préparation de l'environnement..."
    
    # Création des dossiers nécessaires
    mkdir -p config/suricata_6.0.15
    mkdir -p config/snort_2.9
    mkdir -p config/snort_3
    mkdir -p output/{logs,pcap,reports}

    # Permissions
    chmod -R 755 output
}

# Construction des images Docker
build_images() {
    log "Construction des images Docker..."
    
    # Construction de toutes les images
    docker compose build || error "Erreur lors de la construction des images"
    
    # Vérification des images
    expected_images=("spqr_streamlit" "spqr_suricata:6.0.15" "spqr_suricata:7.0.2" "spqr_snort:2.9" "spqr_snort:3")
    for img in "${expected_images[@]}"; do
        docker image inspect $img >/dev/null 2>&1 || error "Image $img non trouvée"
    done
}

# Test de fonctionnement
test_installation() {
    log "Test de l'installation..."
    
    # Démarrage des services
    docker compose up -d
    
    # Attente du démarrage de Streamlit
    sleep 10
    
    # Test de l'interface web
    if curl -s http://localhost:8501 > /dev/null; then
        log "Interface web accessible sur http://localhost:8501"
    else
        error "Interface web non accessible"
    fi
    
    # Test rapide avec Suricata
    docker compose exec -T suricata6015 suricata -V || error "Suricata test failed"
}

# Nettoyage
cleanup() {
    log "Nettoyage..."
    docker compose down
    docker system prune -f
}

# Menu principal
main() {
    log "Installation de SPQR..."
    
    check_prerequisites
    setup_environment
    build_images
    test_installation
    
    log "Installation terminée avec succès!"
    log "Accédez à l'interface via: http://localhost:8501"
}

# Gestion des erreurs
set -e
trap 'error "Une erreur est survenue. Nettoyage..."' ERR

# Exécution
main "$@"