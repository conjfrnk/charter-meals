"""Routes package for Charter Meals."""

from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.main import main_bp


def register_blueprints(app):
    """Register all blueprints with the Flask app."""
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(main_bp)
