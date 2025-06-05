# SPQR - Network Rules Testing Tool 🛡️

**SPQR** est un outil simplifié pour tester et valider les règles de détection réseau avec Suricata, Snort 2 et Snort 3, incluant un support natif des conteneurs Docker. Fini les notebooks complexes - utilisez SPQR avec une interface claire, des scripts automatisés, et un mode multi-IDS !

## 🚀 Installation Rapide

### Méthode 1 : Installation Automatique (Recommandée)
```bash
# Télécharger et exécuter le script d'installation
wget https://raw.githubusercontent.com/FlorianLoisy/SPQR/main/install_spqr.sh
chmod +x install_spqr.sh
./install_spqr.sh
```

### Méthode 2 : Installation Manuelle
```bash
# Cloner le projet
git clone https://github.com/FlorianLoisy/SPQR.git
cd SPQR

# Installer les dépendances
pip3 install -r requirements.txt

# Installer Suricata (Ubuntu/Debian)
sudo apt-get install suricata

# Lancer SPQR
python3 spqr_cli.py --help
```

## 📋 Utilisation

### 💻 Interface Graphique (Pour les Débutants)
```bash
python3 spqr_gui.py
```
- Interface simple avec onglets
- Test rapide en un clic
- Configuration visuelle
- Visualisation des résultats

### ⚡ Lancement Rapide
```bash
./spqr_launch.sh
```
Menu interactif pour choisir votre mode d'utilisation.

### 💻 Ligne de Commande (Pour les Experts)

#### Test Rapide Complet
```bash
# Test d'attaque web
python3 spqr_cli.py quick web_attack

# Test de malware C2
python3 spqr_cli.py quick malware_c2

# Test d'exfiltration de données
python3 spqr_cli.py quick data_exfiltration
```

#### Tests avec Plusieurs IDS
```bash
# Tester un PCAP contre tous les moteurs définis dans config.json
python3 spqr_cli.py test-all output/pcap/example.pcap
```

#### Opérations Individuelles
```bash
# Lister les types d'attaques disponibles
python3 spqr_cli.py list

# Générer seulement du trafic
python3 spqr_cli.py generate web_attack

# Tester avec un fichier PCAP existant
python3 spqr_cli.py test input/malware_sample.pcap

# Générer un rapport depuis les logs
python3 spqr_cli.py report output/logs/eve.json
```

#### Options Avancées
```bash
# Utiliser une configuration personnalisée
python3 spqr_cli.py quick web_attack --config custom_config.json

# Spécifier un fichier de sortie
python3 spqr_cli.py generate malware_c2 --output custom_malware.pcap

# Utiliser des règles personnalisées
python3 spqr_cli.py test malware.pcap --rules custom_rules.rules

# Mode verbeux
python3 spqr_cli.py quick web_attack --verbose
```

## 📁 Structure du Projet
```
SPQR/
├── spqr_cli.py          # Interface ligne de commande
├── spqr_gui.py          # Interface graphique
├── spqr_launch.sh       # Script de lancement rapide
├── example_test.py      # Exemple d'utilisation
│
├── config/
│   ├── config.json      # Configuration principale
│   ├── suricata.yaml    # Configuration Suricata
│   └── suricata.rules   # Règles de détection
│
├── input/               # Fichiers PCAP d'entrée
├── output/
│   ├── pcap/            # Trafic généré
│   ├── logs/            # Logs Suricata/Snort
│   └── reports/         # Rapports générés
│
├── images_docker/       # Conteneurs Docker IDS (Suricata/Snort)
└── scripts/
    ├── generate_traffic/
    └── update_rules.sh  # Mise à jour des règles
```

## 🌟 Fonctionnalités Spéciales

- ✅ **Support Multi-IDS** : Suricata 6, Suricata 7, Snort 2.9, Snort 3 via Docker
- ✅ **Mode test-all** : compare les résultats de plusieurs IDS en un seul appel
- ✅ **Structure modulaire** : facile à étendre pour d'autres moteurs ou scénarios

## 🔧 Configuration

### Configuration Multi-IDS (`config/config.json`)
```json
{
  "network": {
    "source_ip": "192.168.1.10",
    "dest_ip": "192.168.1.20",
    "source_port": 1234,
    "dest_port": 80
  },
  "suricata": {
    "config_file": "config/suricata.yaml",
    "rules_file": "config/suricata.rules",
    "log_dir": "output/logs"
  },
  "output": {
    "pcap_dir": "output/pcap",
    "reports_dir": "output/reports"
  },
  "engines": [
    {"type": "suricata", "version": "6.0.15", "mode": "docker"},
    {"type": "suricata", "version": "7.0.2", "mode": "docker"},
    {"type": "snort", "version": "2.9", "mode": "docker"},
    {"type": "snort", "version": "3", "mode": "docker"}
  ]
}
```

### Ajout de Règles
```bash
# Ajouter une règle manuellement
echo 'alert tcp any any -> any 8080 (msg:"Custom Rule"; sid:2000001;)' >> config/suricata.rules

# Mise à jour automatique
./scripts/update_rules.sh
```

## 📊 Exemples Multi-IDS

### Comparaison Suricata vs Snort
```bash
python3 spqr_cli.py test-all output/pcap/web_attack_test.pcap

# Résultat
=== RÉSULTATS MULTI-IDS ===
--- suricata_6.0.15 ---
Log : output/logs/suricata_6.0.15/eve.json
Rapport : output/reports/suricata_6.0.15/report_*.txt

--- snort_3 ---
Log : output/logs/snort_3/alert.fast
Rapport : output/reports/snort_3/report_*.txt
```

## 🔎 Dépannage & Astuces

- **Erreur Docker : permission denied**
  ```bash
  sudo usermod -aG docker $USER
  newgrp docker
  ```

- **Erreur sur Suricata non trouvé**
  ```bash
  sudo apt-get install suricata
  ```

- **Installer les dépendances Python**
  ```bash
  pip3 install -r requirements.txt
  ```

- **Afficher les logs**
  ```bash
  tail -f output/logs/suricata.log
  ```

## 🏆 Contribuer

- Forkez le projet
- Ajoutez vos règles ou moteurs IDS
- Proposez des Pull Requests

---

Développé avec ❤️ par [FlorianLoisy](https://github.com/FlorianLoisy)
