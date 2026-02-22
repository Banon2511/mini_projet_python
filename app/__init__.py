"""
Application web MiniSec - Interface Flask
Factory d'application avec configuration centralisée.
"""
from flask import Flask

from app.core.config import get_config


def create_app(config=None):
    """Crée et configure l'application Flask."""
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
        instance_relative_config=True,
    )
    cfg = config or get_config()
    app.config.from_object(cfg)
    cfg.init_app(app)

    # Base de données (optionnelle — nécessite Flask-SQLAlchemy)
    try:
        from app.models import db, init_db
        db.init_app(app)
        with app.app_context():
            init_db()
    except ImportError as e:
        app.logger.debug(f"Base de données non chargée (dépendance optionnelle): {e}")
    except Exception as e:
        app.logger.warning(f"Base de données non initialisée: {e}")

    # Routes web (page d'accueil, formulaire)
    from app.web.routes import register_web_routes
    register_web_routes(app)

    # Routes API v1
    from app.api import register_routes
    register_routes(app)

    # Gestionnaires d'erreurs
    from error_handlers import setup_error_handlers
    setup_error_handlers(app)

    # Logging (optionnel, évite erreurs si dépendances manquantes)
    try:
        from logging_config import setup_logging
        setup_logging(app)
    except ImportError:
        pass

    # Headers de sécurité (X-Frame-Options, etc.)
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    return app
