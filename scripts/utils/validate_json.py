import json
import sys
from pathlib import Path

def validate_json_file(file_path: str) -> bool:
    """Validate a JSON file and print any errors found"""
    try:
        with open(file_path) as f:
            json.load(f)
        print(f"✅ {file_path} is valid JSON")
        return True
    except json.JSONDecodeError as e:
        print(f"❌ Error in {file_path}:")
        print(f"   Line {e.lineno}, Column {e.colno}: {e.msg}")
        return False

def main():
    # Validate all JSON files in config directory
    config_dir = Path(__file__).parents[2] / "config"
    json_files = list(config_dir.rglob("*.json"))
    
    all_valid = True
    for file in json_files:
        if not validate_json_file(str(file)):
            all_valid = False
    
    sys.exit(0 if all_valid else 1)

if __name__ == "__main__":
    main()