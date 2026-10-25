from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    """
    User database model representing authenticated principals.
    Enforces secure password hashing via Werkzeug scrypt/pbkdf2.
    Never stores plaintext passwords.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' or 'admin'
    bio = db.Column(db.String(250), nullable=True, default="")
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Relationships
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def __init__(self, username, email, role="user", bio=""):
        self.username = username.strip()
        self.email = email.strip().lower()
        self.role = role if role in ("user", "admin") else "user"
        self.bio = bio.strip() if bio else ""

    def set_password(self, password: str):
        """
        Hash password using Werkzeug's secure hash algorithm.
        scrypt (or pbkdf2 fallback) provides strong resistance to GPU/ASIC cracking.
        """
        if not password or len(password) < 8:
            raise ValueError("Password does not meet minimum security length of 8 characters.")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Verify password against stored cryptographic hash using constant-time comparison.
        """
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        """Check if user has administrative privileges."""
        return self.role == "admin"

    @property
    def is_active(self) -> bool:
        """Flask-Login property: checks whether account is enabled and not locked."""
        if not self.is_active_account:
            return False
        if self.locked_until and self.locked_until > datetime.utcnow():
            return False
        return True

    def __repr__(self):
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"


class AuditLog(db.Model):
    """
    Security Audit Trail Model (OWASP A09: Security Logging and Monitoring Failures).
    Tracks critical authentication, authorization, and administrative events.
    """
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = db.Column(db.String(64), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'SUCCESS', 'FAILURE', 'WARNING'
    details = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<AuditLog id={self.id} action='{self.action}' status='{self.status}'>"


@login_manager.user_loader
def load_user(user_id: str):
    """Flask-Login callback to reload user object from session ID."""
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None
