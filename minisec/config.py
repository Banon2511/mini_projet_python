"""
Configuration du moteur MiniSec - indépendant de Flask
"""
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuration d'un scan - pondérations et seuils paramétrables"""
    
    # Dossier racine autorisé (sandbox)
    scan_sandbox: str = field(
        default_factory=lambda: os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scan_sandbox")
        )
    )
    
    # Limites de sécurité
    max_file_size: int = 50 * 1024 * 1024  # 50 MB
    max_files_per_scan: int = 10_000
    scan_timeout_seconds: int = 300  # 5 min
    file_timeout_seconds: float = 10.0  # timeout par fichier
    
    # Pondérations du scoring (ChatGPT recommandation)
    weight_signature: int = 50
    weight_yara: int = 40
    weight_ai: int = 30
    weight_extension: int = 10
    weight_filename: int = 10
    
    # Seuils de niveau de risque
    threshold_high: int = 50
    threshold_medium: int = 20
    
    # Options
    recursive: bool = True
    analyze_content: bool = True
    enable_ai: bool = True
    
    def validate_path(self, path: str) -> bool:
        """Vérifie que le chemin est dans le sandbox"""
        if not path or not isinstance(path, str):
            return False
        try:
            allowed = os.path.abspath(self.scan_sandbox)
            resolved = os.path.abspath(os.path.normpath(path))
            return resolved.startswith(allowed)
        except Exception:
            return False
