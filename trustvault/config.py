import os
from datetime import timedelta
from dotenv import load_dotenv

# Load .env file from project root if it exists
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(project_root, ".env"))


class Config:
    """Base application configuration with security-first defaults."""
    SECRET_KEY = os.getenv("SECRET_KEY", "insecure-dev-fallback-key-do-not-use-in-production")
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///instance/trustvault.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Storage settings
    STORAGE_PATH = os.getenv("STORAGE_PATH", os.path.join(project_root, "storage", "tenants"))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 10 * 1024 * 1024))  # 10 MB default
    
    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(
        seconds=int(os.getenv("PERMANENT_SESSION_LIFETIME_SECONDS", 3600))
    )
    
    # CSRF settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = False  # Keep false by default for security testing
    TESTING = False


from sqlalchemy.pool import StaticPool


class TestingConfig(Config):
    """Testing environment configuration using in-memory SQLite with StaticPool."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"check_same_thread": False},
        "poolclass": StaticPool,
    }
    WTF_CSRF_ENABLED = False  # Disabled during automated tests for simplified payload testing
    STORAGE_PATH = os.path.join(project_root, "tests", "temp_storage")


class ProductionConfig(Config):
    """Hardened production environment configuration."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True  # Strict HTTPS enforcement
    SESSION_COOKIE_SAMESITE = "Lax"


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
