# SPQR - Network Rules Testing Tool

SPQR est une solution d'analyse de trafic réseau utilisant plusieurs IDS (Suricata et Snort) dans des conteneurs Docker avec une interface web Streamlit.

## Prérequis

- Linux (testé sur Ubuntu 22.04)
- Docker
- Docker Compose
- Python 3.11+
- Curl

## Installation rapide

```bash
# Cloner le dépôt
git clone https://github.com/votre-repo/SPQR.git
cd SPQR

# Lancer l'installation automatique
chmod +x install_spqr.sh
./install_spqr.sh
```

L'interface web sera accessible sur : http://localhost:8501

## Structure du projet

```
SPQR/
├── config/                     # Configurations
│   ├── suricata_6.0.15/       # Config Suricata 6.0.15
│   ├── suricata_7.0.2/        # Config Suricata 7.0.2
│   ├── snort_2.9/             # Config Snort 2.9
│   └── snort_3/               # Config Snort 3
├── images_docker/             # Dockerfiles
│   ├── Docker_Streamlit/      # Image Streamlit
│   ├── Docker_Suricata-6.0.15/
│   ├── Docker_Suricata-7.0.2/
│   ├── Docker_Snort-2.9/
│   └── Docker_Snort-3/
├── output/                    # Sorties
│   ├── logs/                  # Logs des IDS
│   ├── pcap/                 # Fichiers PCAP générés
│   └── reports/              # Rapports d'analyse
├── spqr_app/                 # Application Streamlit
│   ├── app.py                # Interface web
│   └── requirements.txt      # Dépendances Python
├── docker-compose.yml        # Configuration des services
└── install_spqr.sh          # Script d'installation
```

## Utilisation manuelle

Si vous préférez gérer les services manuellement :

```bash
# Construire les images
docker compose build

# Démarrer tous les services
docker compose up -d

# Démarrer uniquement l'interface web
docker compose up -d streamlit

# Arrêter les services
docker compose down
```

## Services disponibles

- **Streamlit** : Interface web (port 8501)
- **Suricata 6.0.15** : IDS principal
- **Suricata 7.0.2** : IDS secondaire
- **Snort 2.9** : IDS complémentaire
- **Snort 3** : IDS expérimental

## Développement

Pour contribuer au projet :

1. Fork le dépôt
2. Créez une branche pour votre fonctionnalité
3. Committez vos changements
4. Poussez vers la branche
5. Ouvrez une Pull Request

## Troubleshooting

En cas de problème :

1. Vérifiez les logs :
```bash
docker compose logs -f
```

2. Redémarrez les services :
```bash
docker compose restart
```

3. Reconstruction complète :
```bash
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

---

Développé avec ❤️ par [FlorianLoisy](https://github.com/FlorianLoisy)
