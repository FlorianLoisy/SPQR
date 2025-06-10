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
