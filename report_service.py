"""
Service de génération et sauvegarde des rapports de scan
"""
import json
import csv
import io
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

# Dossier des rapports (relatif à la racine du projet)
REPORTS_DIR = Path(__file__).parent / "reports"
# Index en mémoire : report_id -> (filename_base, created_at)
_reports_index = {}
# Durée de rétention en secondes (24h) - les rapports restent disponibles un temps
REPORT_TTL = 24 * 3600


def _ensure_reports_dir():
    """Crée le dossier reports si nécessaire"""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _build_report_data(scanner) -> dict:
    """Construit la structure du rapport à partir d'un scanner"""
    duration = 0
    if hasattr(scanner, "end_time") and hasattr(scanner, "start_time"):
        if scanner.end_time and scanner.start_time:
            duration = scanner.end_time - scanner.start_time

    summary = {
        "total_files": scanner.total_files,
        "analyzed_files": len(scanner.scan_results),
        "high": scanner.summary.get("High", 0),
        "medium": scanner.summary.get("Medium", 0),
        "low": scanner.summary.get("Low", 0),
        "folder": getattr(scanner, "folder_path", ""),
        "recursive": getattr(scanner, "recursive", False),
        "analyze_content": getattr(scanner, "analyze_content", False),
        "scan_duration": round(duration, 2),
        "scan_status": getattr(scanner, "scan_status", "completed"),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    total = len(scanner.scan_results)
    if total > 0:
        high = scanner.summary.get("High", 0)
        medium = scanner.summary.get("Medium", 0)
        summary["threat_percentage"] = round((high + medium) / total * 100, 1)
    else:
        summary["threat_percentage"] = 0

    results = []
    for r in scanner.scan_results:
        results.append({
            "name": r.get("name", ""),
            "path": r.get("path", ""),
            "size": r.get("size", 0),
            "extension": r.get("extension", ""),
            "risk_level": r.get("risk_level", "Low"),
            "score": r.get("score", 0),
            "reasons": r.get("reasons") or ["Aucune menace détectée"],
        })

    return {"summary": summary, "results": results}


def save_report(scanner, format_type: str = "json") -> Optional[str]:
    """
    Sauvegarde le rapport de scan (JSON et CSV) et retourne l'identifiant du rapport.

    Args:
        scanner: Instance SecurityScanner ou WebMiniSecScanner après run_analysis()
        format_type: 'json' ou 'csv' (les deux sont toujours sauvegardés)

    Returns:
        report_id (str) ou None en cas d'erreur
    """
    _ensure_reports_dir()
    report_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]

    try:
        data = _build_report_data(scanner)
        base_path = REPORTS_DIR / report_id

        # Toujours sauvegarder JSON
        json_path = base_path.with_suffix(".json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)

        # Toujours sauvegarder CSV
        csv_path = base_path.with_suffix(".csv")
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Name", "Path", "Size", "Extension", "Risk Level", "Score", "Reasons"])
            for r in data["results"]:
                writer.writerow([
                    r["name"], r["path"], r["size"], r["extension"],
                    r["risk_level"], r["score"], "; ".join(r["reasons"]),
                ])

        _reports_index[report_id] = (str(base_path), datetime.now(timezone.utc).timestamp())
        return report_id

    except Exception:
        return None


def get_report_content(report_id: str, format_type: str = "json") -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """
    Récupère le contenu d'un rapport pour téléchargement.
    
    Returns:
        (content_bytes, mimetype, filename) ou (None, None, None) si introuvable
    """
    base_path = REPORTS_DIR / report_id

    # Format JSON
    if format_type in ("json", ""):
        path = base_path.with_suffix(".json")
        if not path.exists():
            # Essayer sans extension si report_id contient déjà l'ext
            path = REPORTS_DIR / (report_id if report_id.endswith(".json") else report_id + ".json")
        if path.exists():
            try:
                with open(path, "rb") as f:
                    return f.read(), "application/json", f"rapport_minisec_{report_id}.json"
            except Exception:
                return None, None, None

    # Format CSV
    elif format_type == "csv":
        path = base_path.with_suffix(".csv")
        if not path.exists():
            path = REPORTS_DIR / (report_id + ".csv" if not report_id.endswith(".csv") else report_id)
        if path.exists():
            try:
                with open(path, "rb") as f:
                    return f.read(), "text/csv", f"rapport_minisec_{report_id}.csv"
            except Exception:
                return None, None, None

    return None, None, None


def generate_report_content(scanner, format_type: str = "json") -> Tuple[bytes, str, str]:
    """
    Génère le contenu du rapport sans sauvegarder (pour téléchargement immédiat).
    
    Returns:
        (content_bytes, mimetype, filename)
    """
    data = _build_report_data(scanner)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format_type == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name", "Path", "Size", "Extension", "Risk Level", "Score", "Reasons"])
        for r in data["results"]:
            writer.writerow([
                r["name"], r["path"], r["size"], r["extension"],
                r["risk_level"], r["score"], "; ".join(r["reasons"]),
            ])
        content = output.getvalue().encode("utf-8")
        return content, "text/csv", f"rapport_minisec_{ts}.csv"

    # JSON par défaut
    content = json.dumps(data, indent=2, default=str, ensure_ascii=False).encode("utf-8")
    return content, "application/json", f"rapport_minisec_{ts}.json"
