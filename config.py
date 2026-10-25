import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base application configuration with secure defaults."""
    # Secrets management
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-key-replace-in-production-1234567890abcdef")
    
    # Database configuration (parameterized SQLite default)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'secureweb.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
    }

    # Session security controls (OWASP A07: Identification and Authentication Failures)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "t")
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = True

    # CSRF protection (OWASP A01: Broken Access Control & A04: Insecure Design)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # Token expires after 1 hour

    # Rate Limiting configuration
    RATELIMIT_DEFAULT = "200 per day; 50 per hour"
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_HEADERS_ENABLED = True

    # Security Headers config
    SECURITY_HEADERS = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    }


class DevelopmentConfig(Config):
    """Configuration for local development."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    """Configuration for automated test suite execution."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = True  # Enable CSRF in tests to verify protection
    SESSION_COOKIE_SECURE = False
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"


class ProductionConfig(Config):
    """Configuration for production deployment."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True  # Strict HTTPS enforcement for cookies

    @classmethod
    def init_app(cls, app):
        # Validate that a secure random key is set
        secret_key = os.environ.get("SECRET_KEY")
        if not secret_key or secret_key.startswith("dev-insecure"):
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: "
                "Production environment requires a strong, randomly generated SECRET_KEY! "
                "Generate one using: python -c 'import secrets; print(secrets.token_hex(32))'"
            )


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
