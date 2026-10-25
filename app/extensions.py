"""Flask extension instances initialized here to prevent circular imports."""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Configure Flask-Login
login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to access this secure resource."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"  # Mitigates session hijacking by checking user agent and IP
