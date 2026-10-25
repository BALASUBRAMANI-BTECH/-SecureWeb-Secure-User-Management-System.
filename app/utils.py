import re
from urllib.parse import urlparse, urljoin
from functools import wraps
from flask import request, abort, current_app
from flask_login import current_user
from app.extensions import db
from app.models import AuditLog


def is_safe_url(target: str) -> bool:
    """
    Validate target redirect URL to prevent Open Redirect vulnerabilities (CWE-601).
    Ensures target is either a relative path or points to the exact same host/domain.
    Rejects backslashes, protocol-relative '//', and invalid schemes.
    """
    if not target:
        return False

    # Block backslashes and protocol-relative URLs (e.g. //evil.com or \evil.com)
    if target.startswith("//") or target.startswith("\\\\") or "\\" in target:
        return False

    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))

    return (
        test_url.scheme in ("http", "https")
        and ref_url.netloc == test_url.netloc
    )


def admin_required(f):
    """
    Decorator that enforces Role-Based Access Control (RBAC).
    Restricts access strictly to users with the 'admin' role.
    Returns HTTP 403 Forbidden for authenticated non-admin users.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        
        if not current_user.is_admin():
            log_security_event(
                action="UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT",
                status="WARNING",
                details=f"User '{current_user.username}' (ID: {current_user.id}) attempted to access admin endpoint: {request.path}",
                user=current_user
            )
            abort(403)
            
        return f(*args, **kwargs)
    return decorated_function


def log_security_event(action: str, status: str, details: str = None, user = None):
    """
    Record security and audit events to the database (OWASP A09).
    Captures IP address, timestamp, principal, action, and outcome.
    """
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        username = None
        user_id = None

        if user:
            username = getattr(user, "username", None)
            user_id = getattr(user, "id", None)
        elif current_user and current_user.is_authenticated:
            username = current_user.username
            user_id = current_user.id

        log_entry = AuditLog(
            action=action,
            status=status,
            details=details,
            user_id=user_id,
            username=username,
            ip_address=ip
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # In a real environment, fallback to structured file logger
        current_app.logger.error(f"Failed to record audit log: {str(e)}")


def validate_password_complexity(password: str) -> tuple[bool, str]:
    """
    Enforce OWASP-aligned password complexity standards:
    - Minimum 8 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one digit (0-9)
    - At least one special character (!@#$%^&*()-_+=~`[]{}|:;"'<>,.?/)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one number (0-9)."
    if not re.search(r'[!@#$%^&*()_\-+=\[\]{}|:;"\'<>,.?/~`]', password):
        return False, "Password must include at least one special character (e.g. !@#$%^&*)."
    return True, ""
