"""
API MiniSec - Blueprint v1
"""
from flask import Blueprint

from app.api import routes

API_V1_PREFIX = "/api/v1"


def register_routes(app):
    """Enregistre les blueprints API sur l'application"""
    api_bp = Blueprint("api_v1", __name__, url_prefix=API_V1_PREFIX)
    routes.register_api_routes(api_bp)
    app.register_blueprint(api_bp)
