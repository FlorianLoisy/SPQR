from pathlib import Path
from typing import Union
import logging
import json
import yaml
import requests

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# MAJ rules Suricata


def abs_path(path: Union[str, Path]) -> Path:
    """Returns a resolved absolute path."""
    return Path(path).expanduser().resolve()

def load_json_or_yaml(config_path: Path) -> dict:
    """Loads either JSON or YAML based on file extension."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    if config_path.suffix in ('.yaml', '.yml'):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return json.loads(config_path.read_text())

def download_et_rules(engine: str) -> bool:
    logger.debug(f"Downloading Emerging Threats rules for {engine}...")
    try:
        if engine == "suricata":
            ET_URL = "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
            DEST_DIR = Path("config")
            DEST_RULES_FILE = DEST_DIR / "suricata_ET.rules"

            print(f"Téléchargement depuis {ET_URL}...")
            response = requests.get(ET_URL, stream=True)
            response.raise_for_status()

            # Sauvegarde temporaire
            temp_tar = DEST_DIR / "emerging.rules.tar.gz"
            with open(temp_tar, "wb") as f:
                f.write(response.content)

            import tarfile
            with tarfile.open(temp_tar, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("emerging-all.rules"):
                        member.name = "suricata_ET.rules"
                        tar.extract(member, path=DEST_DIR)
                        break

            # Nettoyage
            temp_tar.unlink(missing_ok=True)

            print(f"✅ Règles mises à jour dans {DEST_DIR / 'suricata_ET.rules'}")
            return True

        elif engine == "snort":
            print(f"Téléchargement depuis {ET_URL}...")
            response = requests.get(ET_URL, stream=True)
            response.raise_for_status()

            # Sauvegarde temporaire
            temp_tar = DEST_DIR / "emerging.rules.tar.gz"
            with open(temp_tar, "wb") as f:
                f.write(response.content)

            import tarfile
            with tarfile.open(temp_tar, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("emerging-all.rules"):
                        member.name = "suricata_ET.rules"
                        tar.extract(member, path=DEST_DIR)
                        break

            # Nettoyage
            temp_tar.unlink(missing_ok=True)

            print(f"✅ Règles mises à jour dans {DEST_DIR / 'suricata_ET.rules'}")
            return True
        
    except Exception as e:
        print(f"❌ Échec de la mise à jour : {e}")
        return False