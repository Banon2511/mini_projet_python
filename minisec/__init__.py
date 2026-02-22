"""
MiniSec - Moteur d'analyse de sécurité local
Pas de dépendance Flask. Utilisable via CLI, API, script.
"""
from minisec.scanner import scan, get_scanner
from minisec.config import ScanConfig

# SecurityScanner vient du module racine scanner
try:
    from scanner import SecurityScanner
except ImportError:
    SecurityScanner = None

__version__ = "2.0.0"
__all__ = ["SecurityScanner", "ScanConfig", "scan", "get_scanner"]
