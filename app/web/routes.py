"""
Routes web - page d'accueil et formulaire de scan
"""
from pathlib import Path

from flask import Blueprint, render_template, request

from app.web_scanner import WebMiniSecScanner

# Imports conditionnels
try:
    from scanner import SecurityScanner
    USE_AI_SCANNER = True
except Exception:
    SecurityScanner = None
    USE_AI_SCANNER = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def _normalize_results(results):
    """Normalise les résultats pour le template"""
    if not results:
        return []
    return [
        {
            "name": r.get("name"),
            "path": r.get("path"),
            "size": r.get("size", 0),
            "risk_level": r.get("risk_level", "Low"),
            "reasons": r.get("reasons") or ["Aucune menace détectée"],
        }
        for r in results
    ]


def register_web_routes(app):
    """Enregistre les routes web sur l'app"""

    @app.route("/", methods=["GET", "POST"])
    def index():
        results = None
        summary = None
        error = None
        scan_info = None

        if request.method == "POST":
            folder = request.form.get("folder") or "."
            recursive = request.form.get("recursive") == "on"
            analyze_content = request.form.get("analyze_content") == "on"
            folder_path = Path(folder).expanduser().resolve()

            if not folder_path.exists() or not folder_path.is_dir():
                error = "Le chemin indiqué n'existe pas ou n'est pas un dossier."
            else:
                if USE_AI_SCANNER and SecurityScanner:
                    scanner = SecurityScanner(
                        str(folder_path),
                        recursive=recursive,
                        analyze_content=analyze_content,
                        enable_ai=True
                    )
                else:
                    scanner = WebMiniSecScanner(
                        str(folder_path),
                        recursive=recursive,
                        analyze_content=analyze_content
                    )

                success, message = scanner.run_analysis()

                if success:
                    results = _normalize_results(scanner.scan_results)
                    report_id = None
                    try:
                        from report_service import save_report
                        report_id = save_report(scanner, "json")
                    except Exception:
                        pass
                    summary = {
                        "total_files": scanner.total_files,
                        "analyzed_files": len(scanner.scan_results),
                        "high": scanner.summary["High"],
                        "medium": scanner.summary["Medium"],
                        "low": scanner.summary["Low"],
                        "folder": str(folder_path),
                        "recursive": recursive,
                        "analyze_content": analyze_content,
                        "yara_available": YARA_AVAILABLE,
                        "ai_available": getattr(scanner, "enable_ai", False)
                        and getattr(scanner, "ai_manager", None) is not None,
                        "report_id": report_id,
                    }
                    scan_info = {"message": message, "status": scanner.scan_status}
                else:
                    error = message

        return render_template(
            "index.html",
            results=results,
            summary=summary,
            error=error,
            scan_info=scan_info,
        )
