# Structure du projet MiniSec Scanner

## Vue d'ensemble

```
mini_projet_python/
├── wsgi.py                 # Point d'entrée (gunicorn wsgi:app | python wsgi.py)
├── config.py               # Configuration centralisée (Dev, Test, Prod)
├── requirements.txt        # Dépendances Python
│
├── app/                    # Package Flask (create_app)
│   ├── __init__.py         # Factory create_app(), initialisation
│   ├── api/                # API REST v1
│   │   ├── __init__.py     # Enregistrement du blueprint
│   │   └── routes.py       # /api/v1/scan, /api/v1/status, /api/v1/scans/recent
│   ├── web/                # Routes HTML
│   │   ├── __init__.py
│   │   └── routes.py       # Page d'accueil, formulaire de scan
│   ├── web_scanner.py      # Scanner de repli (sans IA) si scanner indisponible
│   ├── core/               # Logique centrale
│   │   ├── config.py       # Réexport de la config
│   │   └── security.py     # validate_scan_path, validate_scan_path_safe
│   └── models/             # Modèles ORM (ScanHistory, etc.)
│
├── minisec/                # Moteur de scan (CLI / scripts)
│   ├── __init__.py         # Exports: scan, ScanConfig, SecurityScanner
│   ├── scanner.py          # Façade scan() → utilise scanner.SecurityScanner
│   └── config.py           # ScanConfig (dataclass)
│
├── scanner.py              # SecurityScanner principal (IA, YARA, signatures)
├── ai_models.py            # Modèles IA (AIDetector, etc.)
├── signature_db.py         # Base de signatures (MD5/SHA256)
├── models.py               # Modèles SQLAlchemy (racine)
├── error_handlers.py       # Exceptions, setup_error_handlers
├── validators.py           # Schémas Marshmallow
├── logging_config.py       # Logging, rate limiting, cache (optionnel)
│
├── templates/              # Jinja2
│   └── index.html
├── static/                 # Assets statiques (optionnel)
├── signatures/             # Base de hashes
│   └── signature_db.json
│
├── tests/
│   ├── conftest.py         # Fixtures pytest
│   ├── test_flask.py       # Tests API /api/v1/*
│   ├── test_scanner.py
│   └── test_ai_models.py
│
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## API REST v1

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/` | Page d'accueil (formulaire) |
| POST | `/` | Scan via formulaire (server-side) |
| GET | `/api/v1/status` | Statut système (YARA, IA, signatures) |
| POST | `/api/v1/scan` | Lance un scan (JSON: folder, recursive, analyze_content) |
| GET | `/api/v1/scans/recent` | Liste des scans récents (placeholder) |

## Lancer l'application

```bash
# Développement
python wsgi.py

# Production
gunicorn wsgi:app --bind 0.0.0.0:5000
```

## Tests

```bash
pytest tests/ -v
```
