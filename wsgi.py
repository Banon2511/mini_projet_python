"""
Point d'entrée WSGI pour l'application web MiniSec.
Lancer avec : python wsgi.py
"""
import os
import sys

# S'assurer que le répertoire du projet est dans le PYTHONPATH
sys_path = os.path.dirname(os.path.abspath(__file__))
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
