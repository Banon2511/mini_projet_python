#!/usr/bin/env python3
"""
CLI MiniSec - Moteur d'analyse de sécurité local
Usage: python minisec_cli.py scan <path> [--recursive] [--ai] [--no-content]
       python -m minisec_cli scan ./demo_samples --recursive --ai
"""
import argparse
import json
import sys
from pathlib import Path

# Ajouter le répertoire parent au path
sys.path.insert(0, str(Path(__file__).resolve().parent))


def cmd_scan(args):
    """Exécute un scan via le moteur (sans Flask)"""
    from minisec.scanner import scan
    from minisec.config import ScanConfig
    
    cfg = ScanConfig(
        recursive=args.recursive,
        analyze_content=args.analyze_content,
        enable_ai=args.ai
    )
    # En CLI, sandbox = dossier scanné (usage local contrôlé par l'utilisateur)
    target = Path(args.path or ".").resolve()
    cfg.scan_sandbox = str(target) if target.is_dir() else str(target.parent)
    
    result = scan(args.path or ".", config=cfg)
    
    if not result["success"]:
        print(f"Erreur: {result['message']}", file=sys.stderr)
        return 1
    
    summary = result["summary"]
    print(f"\n=== MiniSec Scan ===\n")
    print(f"Dossier: {args.path or '.'}")
    print(f"Fichiers analysés: {summary.get('analyzed_files', 0)}")
    print(f"Risque élevé: {summary.get('high', 0)} | Moyen: {summary.get('medium', 0)} | Faible: {summary.get('low', 0)}")
    print(f"Durée: {result.get('scan_duration', 0):.2f}s\n")
    
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        for r in result.get("results", []):
            if r["risk_level"] in ("High", "HIGH") or (args.verbose and r["risk_level"] in ("Medium", "MEDIUM")):
                print(f"  [{r['risk_level']}] {r['file']} (score: {r['score']})")
                for ex in r.get("explanations", [])[:3]:
                    print(f"      - {ex}")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="MiniSec - Moteur d'analyse de sécurité local",
        prog="minisec"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commandes")
    
    scan_parser = subparsers.add_parser("scan", help="Analyser un dossier")
    scan_parser.add_argument("path", nargs="?", default=".", help="Chemin du dossier à scanner")
    scan_parser.add_argument("--recursive", "-r", action="store_true", help="Inclure les sous-dossiers")
    scan_parser.add_argument("--ai", action="store_true", help="Activer l'analyse IA")
    scan_parser.add_argument("--no-content", action="store_true", help="Désactiver l'analyse de contenu")
    scan_parser.add_argument("--analyze-content", action="store_true", default=True, help="Analyser le contenu (défaut: on)")
    scan_parser.add_argument("--json", "-j", action="store_true", help="Sortie JSON")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Afficher aussi les fichiers Medium")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        # Fix analyze_content
        if hasattr(args, 'no_content') and args.no_content:
            args.analyze_content = False
        if not hasattr(args, 'analyze_content'):
            args.analyze_content = True
        return cmd_scan(args)
    
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
