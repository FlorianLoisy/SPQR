import logging
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)

class FileWatcher:
    """Manage file watching for the application"""
    
    def __init__(self):
        self._watched_paths: Set[Path] = set()
        
    def add_watch(self, path: str) -> None:
        """Add a path to watch"""
        self._watched_paths.add(Path(path))
        logger.debug(f"Added watch for: {path}")
        
    def clear_watches(self) -> None:
        """Clear all watched paths"""
        self._watched_paths.clear()
        logger.debug("Cleared all file watches")