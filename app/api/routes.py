"""
Routes API v1 pour MiniSec Scanner
"""
from pathlib import Path

from flask import request, jsonify, Response

# Import du scanner et validations
try:
    from scanner import SecurityScanner, validate_scan_path
    USE_AI_SCANNER = True
except ImportError:
    SecurityScanner = None
    USE_AI_SCANNER = False
    # Fallback: validation basique quand scanner indisponible
    from app.core.security import validate_scan_path_safe as validate_scan_path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    from signature_db import get_signature_database
    SIGNATURE_DB_AVAILABLE = True
except Exception:
    get_signature_database = None
    SIGNATURE_DB_AVAILABLE = False


def _get_web_scanner():
    """Import tardif pour éviter dépendances circulaires"""
    from app.web_scanner import WebMiniSecScanner
    return WebMiniSecScanner


def _normalize_results(results):
    """Normalise les résultats pour l'API"""
    if not results:
        return []
    return [
        {
            "name": r.get("name"),
            "path": r.get("path"),
            "size": r.get("size", 0),
            "risk_level": r.get("risk_level", "Low"),
            "reasons": r.get("reasons") or ["Aucune menace détectée"],
            "score": r.get("score", 0),
            "extension": r.get("extension", ""),
        }
        for r in results
    ]


def _run_scan(folder_path: str, recursive: bool, analyze_content: bool):
    """Exécute un scan et retourne (scanner, success, message)"""
    path = Path(folder_path).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        return None, False, "Le chemin indiqué n'existe pas ou n'est pas un dossier."

    if not validate_scan_path(str(path)):
        return None, False, "Le chemin spécifié n'est pas autorisé pour des raisons de sécurité"

    if USE_AI_SCANNER and SecurityScanner:
        scanner = SecurityScanner(
            str(path),
            recursive=recursive,
            analyze_content=analyze_content,
            enable_ai=True
        )
    else:
        WebMiniSecScanner = _get_web_scanner()
        scanner = WebMiniSecScanner(
            str(path),
            recursive=recursive,
            analyze_content=analyze_content
        )

    success, message = scanner.run_analysis()
    return scanner, success, message


def register_api_routes(bp):
    """Enregistre les routes sur le blueprint"""

    @bp.route("/status", methods=["GET"])
    def api_status():
        """Statut du système (YARA, IA, signatures)"""
        return jsonify({
            "yara_available": YARA_AVAILABLE,
            "ai_scanner_available": USE_AI_SCANNER,
            "signature_db_available": SIGNATURE_DB_AVAILABLE,
            "version": "1.0",
            "status": "ready"
        })

    @bp.route("/scan", methods=["POST"])
    def api_scan():
        """Lance un scan sur un dossier"""
        data = request.get_json(silent=True) or {}

        # Validation
        if not data or "folder" not in data:
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Paramètre 'folder' manquant",
                "status_code": 400
            }), 400

        folder = data.get("folder")
        if not isinstance(folder, str):
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Le champ 'folder' doit être une chaîne de caractères",
                "status_code": 400
            }), 400

        if not folder or not str(folder).strip():
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Le chemin du dossier ne peut pas être vide",
                "status_code": 400
            }), 400

        if len(folder) > 500:
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Le chemin du dossier est trop long",
                "status_code": 400
            }), 400

        recursive = data.get("recursive", False)
        if not isinstance(recursive, bool):
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Le champ 'recursive' doit être un booléen",
                "status_code": 400
            }), 400

        analyze_content = data.get("analyze_content", False)
        if not isinstance(analyze_content, bool):
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Le champ 'analyze_content' doit être un booléen",
                "status_code": 400
            }), 400

        scanner, success, message = _run_scan(folder, recursive, analyze_content)

        if not success:
            return jsonify({
                "error": True,
                "error_code": "SCAN_ERROR",
                "message": message,
                "status_code": 400
            }), 400

        # Générer et sauvegarder le rapport (JSON + CSV)
        report_id = None
        try:
            from report_service import save_report
            report_id = save_report(scanner, "json")
        except Exception:
            pass

        summary_data = {
            "total_files": scanner.total_files,
            "analyzed_files": len(scanner.scan_results),
            "high": scanner.summary.get("High", 0),
            "medium": scanner.summary.get("Medium", 0),
            "low": scanner.summary.get("Low", 0),
            "folder": str(Path(folder).expanduser().resolve()),
            "recursive": recursive,
            "analyze_content": analyze_content,
            "yara_available": YARA_AVAILABLE,
            "ai_available": getattr(scanner, "enable_ai", False) and getattr(scanner, "ai_manager", None) is not None,
        }
        if report_id:
            summary_data["report_id"] = report_id

        return jsonify({
            "success": True,
            "message": message,
            "results": _normalize_results(scanner.scan_results),
            "summary": summary_data,
        })

    @bp.route("/scans/recent", methods=["GET"])
    def api_scans_recent():
        """Liste des scans récents (placeholder - pas de persistance pour l'instant)"""
        return jsonify([])

    @bp.route("/reports/<report_id>", methods=["GET"])
    def api_get_report(report_id):
        """Télécharge un rapport de scan (JSON ou CSV)"""
        format_type = request.args.get("format", "json").lower()
        if format_type not in ("json", "csv"):
            format_type = "json"

        try:
            from report_service import get_report_content
            content, mimetype, filename = get_report_content(report_id, format_type)
            if content is None:
                return jsonify({
                    "error": True,
                    "error_code": "NOT_FOUND",
                    "message": "Rapport introuvable ou expiré",
                    "status_code": 404
                }), 404

            return Response(
                content,
                mimetype=mimetype,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        except Exception:
            return jsonify({
                "error": True,
                "error_code": "INTERNAL_ERROR",
                "message": "Erreur lors de la récupération du rapport",
                "status_code": 500
            }), 500

    @bp.route("/export", methods=["GET"])
    def api_export():
        """Redirection vers /reports/<id> - utilise report_id du dernier scan"""
        report_id = request.args.get("report_id")
        format_type = request.args.get("format", "json")
        if not report_id:
            return jsonify({
                "error": True,
                "error_code": "VALIDATION_ERROR",
                "message": "Paramètre 'report_id' requis (renvoyé après un scan)",
                "status_code": 400
            }), 400
        from flask import redirect
        return redirect(f"/api/v1/reports/{report_id}?format={format_type}")
