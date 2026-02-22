"""
Base de signatures pour la détection de menaces connues.
Charge un fichier JSON de hashes (MD5/SHA256) et permet la recherche par hash.
"""
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Chemin par défaut de la base de signatures
DEFAULT_SIGNATURE_PATH = Path(__file__).parent / "signatures" / "signature_db.json"


class SignatureDatabase:
    """Base de signatures : chargement et recherche par hash (MD5, SHA256)."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_SIGNATURE_PATH
        self._by_md5: Dict[str, dict] = {}
        self._by_sha256: Dict[str, dict] = {}
        self._loaded = False
        self.load()

    def load(self) -> bool:
        """Charge le fichier JSON et indexe les signatures par hash."""
        if not self.db_path.exists():
            logger.warning(f"Signature database not found: {self.db_path}")
            return False
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._by_md5.clear()
            self._by_sha256.clear()
            for entry in data.get("signatures", []):
                name = entry.get("name", "Unknown")
                sig = {
                    "name": name,
                    "type": entry.get("type", "Malware"),
                    "description": entry.get("description", ""),
                }
                if entry.get("md5"):
                    self._by_md5[entry["md5"].lower()] = sig
                if entry.get("sha256"):
                    self._by_sha256[entry["sha256"].lower()] = sig
            self._loaded = True
            logger.info(f"Signature database loaded: {len(self._by_sha256)} signatures")
            return True
        except Exception as e:
            logger.error(f"Failed to load signature database: {e}")
            return False

    def get_threat(self, file_path: str) -> Optional[dict]:
        """
        Calcule les hashes du fichier et retourne la menace si connue.
        Retourne None si le fichier n'est pas dans la base.
        """
        if not self._loaded:
            return None
        try:
            md5_h = hashlib.md5()
            sha256_h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5_h.update(chunk)
                    sha256_h.update(chunk)
            md5 = md5_h.hexdigest().lower()
            sha256 = sha256_h.hexdigest().lower()
            return self._by_sha256.get(sha256) or self._by_md5.get(md5)
        except (OSError, PermissionError) as e:
            logger.debug(f"Cannot hash file {file_path}: {e}")
            return None

    def count(self) -> int:
        """Nombre d'entrées uniques (par SHA256)."""
        return len(self._by_sha256)


# Instance globale pour éviter de recharger à chaque scan
_db: Optional[SignatureDatabase] = None


def get_signature_database(db_path: Optional[Path] = None) -> SignatureDatabase:
    """Retourne l'instance globale de la base de signatures."""
    global _db
    if _db is None:
        _db = SignatureDatabase(db_path)
    return _db
