"""
Scanner web : réutilise scanner.SecurityScanner (sans doublon).
En cas d'import impossible, fallback minimal avec la même interface.
"""
from typing import List, Dict, Tuple

try:
    from scanner import SecurityScanner

    class WebMiniSecScanner(SecurityScanner):
        """Même implémentation que SecurityScanner, IA désactivée pour le web."""
        def __init__(self, folder_path: str, recursive: bool = False,
                     analyze_content: bool = False):
            super().__init__(
                folder_path,
                recursive=recursive,
                analyze_content=analyze_content,
                enable_ai=False,
            )
except ImportError:
    # Fallback minimal si le module scanner n'est pas disponible
    import os
    import time

    class WebMiniSecScanner:
        """Fallback minimal : même interface que SecurityScanner, pas de logique de scan."""
        def __init__(self, folder_path: str, recursive: bool = False,
                     analyze_content: bool = False):
            self.folder_path = folder_path
            self.recursive = recursive
            self.analyze_content = analyze_content
            self.scan_results: List[Dict] = []
            self.summary = {"Low": 0, "Medium": 0, "High": 0}
            self.total_files = 0
            self.scan_progress = 0
            self.scan_status = "initializing"
            self.enable_ai = False
            self.ai_manager = None
            self.start_time = None
            self.end_time = None

        def validate_folder(self) -> Tuple[bool, str]:
            if not os.path.exists(self.folder_path):
                return False, "Le chemin n'existe pas"
            if not os.path.isdir(self.folder_path):
                return False, "Ce n'est pas un dossier"
            if not os.access(self.folder_path, os.R_OK):
                return False, "Permission refusée"
            return True, "Dossier validé"

        def run_analysis(self) -> Tuple[bool, str]:
            self.scan_status = "validating"
            valid, msg = self.validate_folder()
            if not valid:
                return False, msg
            self.scan_status = "completed"
            self.start_time = time.time()
            self.end_time = time.time()
            return False, "Scanner principal indisponible (module scanner non chargé). Utilisez le CLI ou installez les dépendances."

        def get_scan_summary(self) -> Dict:
            duration = (self.end_time or time.time()) - (self.start_time or time.time())
            return {
                "total_files": self.total_files,
                "analyzed_files": len(self.scan_results),
                "high_risk": self.summary.get("High", 0),
                "medium_risk": self.summary.get("Medium", 0),
                "low_risk": self.summary.get("Low", 0),
                "scan_duration": duration,
                "folder": self.folder_path,
                "recursive": self.recursive,
                "analyze_content": self.analyze_content,
                "scan_status": self.scan_status,
            }
