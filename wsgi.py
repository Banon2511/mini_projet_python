"""
Point d'entrée WSGI pour MiniSec Scanner

Usage:
  - Développement: python wsgi.py
  - Production:    gunicorn wsgi:app
"""
import os

# Charger les variables d'environnement avant create_app
if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()

from app import create_app

app = application = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
