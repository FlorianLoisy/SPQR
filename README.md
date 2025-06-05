# SPQR - Network Rules Testing Tool 🛡️

**SPQR** est un outil simplifié pour tester et valider les règles de détection réseau avec Suricata. Fini les notebooks complexes - utilisez SPQR avec une interface simple !

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

### 🖥️ Interface Graphique (Pour les Débutants)
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
│   ├── pcap/           # Trafic généré
│   ├── logs/           # Logs Suricata
│   └── reports/        # Rapports générés
│
└── scripts/
    ├── generate_traffic/
    └── update_rules.sh  # Mise à jour des règles
```

## 🎯 Types d'Attaques Disponibles

| Type | Description | Port Cible |
|------|-------------|------------|
| `web_attack` | Attaques web (XSS, SQLi) | 80/443 |
| `malware_c2` | Communication C&C | 443 |
| `data_exfiltration` | Exfiltration DNS | 53 |
| `port_scan` | Scan de ports | Multiple |
| `brute_force` | Attaque par force brute | 22/3389 |
| `dns_tunneling` | Tunnel DNS | 53 |

## ⚙️ Configuration

### Configuration Rapide
Le fichier `config/config.json` contient tous les paramètres :

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
    "rules_file": "config/suricata.rules"
  }
}
```

### Ajout de Nouvelles Règles
```bash
# Ajouter des règles dans le fichier
echo 'alert tcp any any -> any 8080 (msg:"Custom Rule"; sid:2000001;)' >> config/suricata.rules

# Ou utiliser le script de mise à jour
./scripts/update_rules.sh
```

## 📊 Exemples d'Utilisation

### Scénario 1 : Test Rapide d'Attaque Web
```bash
# Lancer le test complet
python3 spqr_cli.py quick web_attack

# Résultats attendus
✅ TEST TERMINÉ AVEC SUCCÈS!
📁 PCAP généré: output/pcap/web_attack_20250605_143022.pcap
📄 Logs: output/logs/suricata_20250605_143022.json
📊 Rapport: output/reports/report_20250605_143022.txt
```

### Scénario 2 : Analyse de Malware
```bash
# Placer le fichier PCAP dans input/
cp malware_sample.pcap input/

# Tester avec vos règles
python3 spqr_cli.py test input/malware_sample.pcap

# Générer le rapport
python3 spqr_cli.py report output/logs/eve.json
```

### Scénario 3 : Développement de Règles
```bash
# 1. Générer du trafic spécifique
python3 spqr_cli.py generate malware_c2 --output test_c2.pcap

# 2. Tester avec vos nouvelles règles
python3 spqr_cli.py test test_c2.pcap --rules my_rules.rules

# 3. Analyser les résultats
python3 spqr_cli.py report output/logs/eve.json
```

## 🔧 Dépannage

### Problèmes Courants

**Suricata non trouvé**
```bash
# Installer Suricata
sudo apt-get install suricata  # Ubuntu/Debian
brew install suricata         # macOS
```

**Erreur de permissions**
```bash
# Donner les permissions d'exécution
chmod +x spqr_launch.sh
chmod +x scripts/update_rules.sh
```

**Module Python manquant**
```bash
# Installer les dépendances
pip3 install -r requirements.txt
```

### Logs de Débogage
```bash
# Mode verbeux pour plus d'informations
python3 spqr_cli.py quick web_attack --verbose

# Consulter les logs Suricata
tail -f output/logs/suricata.log
```

## 🆚 Avantages par rapport au Notebook

| Aspect | Notebook | SPQR Simplifié |
|--------|----------|----------------|
| **Facilité d'usage** | ⚠️ Complexe | ✅ Simple |
| **Installation** | ⚠️ Jupyter requis | ✅ Prêt à l'emploi |
| **Automatisation** | ❌ Difficile | ✅ Scripts inclus |
| **Interface** | ⚠️ Web uniquement | ✅ CLI + GUI |
| **Déploiement** | ❌ Serveur requis | ✅ Local |
| **Maintenance** | ⚠️ Cellules à gérer | ✅ Auto-maintenance |

## 🚀 Fonctionnalités Avancées

### Intégration CI/CD
```bash
# Dans votre pipeline
python3 spqr_cli.py quick web_attack
if [ $? -eq 0 ]; then
    echo "Tests de règles réussis"
else
    echo "Échec des tests de règles"
    exit 1
fi
```

### Utilisation Programmatique
```python
from spqr_cli import SPQRSimple

# Initialiser SPQR
spqr = SPQRSimple()

# Lancer des tests
results = spqr.quick_test("web_attack")
if "error" not in results:
    print(f"Test réussi: {results['report_file']}")
```

### Personnalisation
```bash
# Créer vos propres types d'attaques
# Modifier config/config.json pour ajouter :
{
  "traffic_patterns": {
    "my_custom_attack": {
      "description": "Mon attaque personn