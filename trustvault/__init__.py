import os
import sqlite3
from flask import Flask, render_template, g
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine
from trustvault.config import config_by_name
from trustvault.models.base import db
from trustvault.services.authz import get_current_user, get_current_tenant

csrf = CSRFProtect()


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enforce foreign key constraints on all SQLite connections."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def create_app(config_name: str = "default") -> Flask:
    """
    Application factory pattern.
    Configures database, security middleware, blueprints, and error handlers.
    """
    app = Flask(__name__)
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)

    # Ensure storage paths exist
    os.makedirs(app.config["STORAGE_PATH"], exist_ok=True)
    if "sqlite" in app.config["SQLALCHEMY_DATABASE_URI"]:
        instance_dir = os.path.join(app.root_path, "..", "instance")
        os.makedirs(instance_dir, exist_ok=True)

    # Context processors for templates
    @app.context_processor
    def inject_auth_context():
        return {
            "current_user": get_current_user(),
            "current_tenant": get_current_tenant(),
        }

    # Security Headers Middleware
    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Production Content Security Policy
        if not app.config.get("TESTING"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "frame-ancestors 'none';"
            )
        return response

    # Register blueprints
    from trustvault.blueprints.auth import auth_bp
    from trustvault.blueprints.main import main_bp
    from trustvault.blueprints.documents import documents_bp
    from trustvault.blueprints.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)

    # Custom Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html", error=error), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html", error=error), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template("errors/500.html", error=error), 500

    return app
