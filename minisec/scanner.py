"""
Façade du moteur de scan - API propre, sans Flask
"""
import sys
from pathlib import Path

# Permettre l'import du scanner racine
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from minisec.config import ScanConfig


def scan(path: str, config: ScanConfig = None, **kwargs) -> dict:
    """
    Lance un scan sur un chemin.
    API utilisable depuis CLI, API REST, scripts, tests.
    
    Returns:
        dict: {
            "success": bool,
            "message": str,
            "results": list,
            "summary": dict,
            "scan_duration": float
        }
    """
    cfg = config or ScanConfig()
    
    if not cfg.validate_path(path):
        return {
            "success": False,
            "message": "Chemin non autorisé (hors sandbox)",
            "results": [],
            "summary": {},
            "scan_duration": 0
        }
    
    try:
        from scanner import SecurityScanner
        use_ai = kwargs.get("enable_ai", cfg.enable_ai)
    except ImportError:
        from app.web_scanner import WebMiniSecScanner
        SecurityScanner = WebMiniSecScanner
        use_ai = False
    
    sc = SecurityScanner(
        path,
        recursive=kwargs.get("recursive", cfg.recursive),
        analyze_content=kwargs.get("analyze_content", cfg.analyze_content),
        enable_ai=use_ai
    )
    
    import time
    start = time.time()
    ok, msg = sc.run_analysis()
    duration = time.time() - start
    
    # Normaliser les résultats avec explanations
    results = []
    for r in sc.scan_results:
        results.append({
            "file": r.get("name", ""),
            "path": r.get("path", ""),
            "risk_level": r.get("risk_level", "Low"),
            "score": r.get("score", 0),
            "explanations": r.get("reasons", []) or ["Aucune menace détectée"],
            "size": r.get("size", 0),
        })
    
    return {
        "success": ok,
        "message": msg,
        "results": results,
        "summary": {
            "total_files": sc.total_files,
            "analyzed_files": len(sc.scan_results),
            "high": sc.summary.get("High", 0),
            "medium": sc.summary.get("Medium", 0),
            "low": sc.summary.get("Low", 0),
        },
        "scan_duration": round(duration, 2),
        "scanner": sc,
    }


# Réexporter SecurityScanner pour usage direct
def get_scanner(path: str, recursive: bool = True, analyze_content: bool = True, enable_ai: bool = True):
    """Retourne une instance de SecurityScanner configurée."""
    try:
        from scanner import SecurityScanner
        return SecurityScanner(path, recursive=recursive, analyze_content=analyze_content, enable_ai=enable_ai)
    except ImportError:
        from app.web_scanner import WebMiniSecScanner
        return WebMiniSecScanner(path, recursive=recursive, analyze_content=analyze_content)
