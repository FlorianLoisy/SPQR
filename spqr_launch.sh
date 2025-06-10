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
<<<<<<< HEAD
esac
=======
esac
>>>>>>> 33226148057da68856b71e95a7dfb22beb934863
