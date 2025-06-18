from pathlib import Path
from typing import Union
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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