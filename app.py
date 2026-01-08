from pathlib import Path

from flask import Flask, render_template, request

from MiniSec_Scanner import MiniSecScanner

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    """
    Page principale :
    - GET  : affiche le formulaire
    - POST : lance un scan sur un dossier fourni (côté serveur pour l'instant)
    """
    results = None
    summary = None
    error = None

    if request.method == "POST":
        folder = request.form.get("folder") or "."
        recursive = request.form.get("recursive") == "on"
        analyze_content = request.form.get("analyze_content") == "on"

        folder_path = Path(folder).expanduser().resolve()

        if not folder_path.exists() or not folder_path.is_dir():
            error = "Le chemin indiqué n'existe pas ou n'est pas un dossier."
        else:
            scanner = MiniSecScanner(str(folder_path), recursive=recursive, analyze_content=analyze_content)

            # On utilise directement la logique d'analyse sans les impressions terminal
            if scanner.validate_folder():
                files_info = scanner.scan_files()
                if files_info:
                    for file_info in files_info:
                        result = scanner.analyze_file(file_info)
                        scanner.scan_results.append(result)
                        scanner.summary[result["risk_level"]] += 1

                results = scanner.scan_results
                summary = {
                    "total_files": scanner.total_files,
                    "analyzed_files": len(scanner.scan_results),
                    "high": scanner.summary["High"],
                    "medium": scanner.summary["Medium"],
                    "low": scanner.summary["Low"],
                    "folder": str(folder_path),
                    "recursive": recursive,
                    "analyze_content": analyze_content,
                }
            else:
                error = "Impossible de valider le dossier cible."

    return render_template("index.html", results=results, summary=summary, error=error)


if __name__ == "__main__":
    # Pour développement local
    app.run(debug=True)


