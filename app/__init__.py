import os
import click
from flask import Flask, render_template, request
from config import config_by_name
from app.extensions import db, login_manager, csrf, limiter


def create_app(config_name: str = "default") -> Flask:
    """
    Application factory pattern.
    Configures extensions, blueprints, security headers, and CLI management commands.
    """
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    cfg = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(cfg)

    # Initialize environment-specific checks (e.g. strict secret key in prod)
    if hasattr(cfg, "init_app"):
        cfg.init_app(app)

    # Ensure instance folder exists for SQLite storage
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register Blueprints
    from app.auth import auth_bp
    from app.main import main_bp
    from app.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    # Register Security Headers middleware (OWASP A05: Security Misconfiguration)
    @app.after_request
    def set_security_headers(response):
        headers = app.config.get("SECURITY_HEADERS", {})
        for header, value in headers.items():
            response.headers[header] = value

        # Anti-caching for sensitive and authenticated pages
        sensitive_endpoints = ["/dashboard", "/profile", "/change-password", "/admin", "/login"]
        if any(request.path.startswith(prefix) for prefix in sensitive_endpoints):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response

    # Register Error Handlers
    register_error_handlers(app)

    # Register CLI Management Commands
    register_commands(app)

    return app


def register_error_handlers(app: Flask):
    """
    Register uniform error handlers to prevent stack trace leakage (OWASP A05).
    """
    @app.errorhandler(400)
    def bad_request(error):
        message = getattr(error, "description", "The request was invalid or CSRF token verification failed.")
        return render_template("errors/400.html", message=message), 400

    @app.errorhandler(403)
    def forbidden(error):
        message = getattr(error, "description", "You do not have administrative authorization to access this resource.")
        return render_template("errors/403.html", message=message), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(429)
    def ratelimit_handler(error):
        message = "Too many requests. Rate limit exceeded. Please wait a moment before trying again."
        return render_template("errors/429.html", message=message), 429

    @app.errorhandler(500)
    def internal_server_error(error):
        # In production, log internal error without showing traceback to user
        app.logger.error(f"Internal Server Error: {error}")
        return render_template("errors/500.html"), 500


def register_commands(app: Flask):
    """
    Register CLI utility commands for database initialization and administrative bootstrapping.
    """
    from app.models import User, AuditLog

    @app.cli.command("init-db")
    def init_db():
        """Initialize and create all database tables."""
        with app.app_context():
            db.create_all()
            click.echo("[+] Database schema created successfully.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True, help="Administrator username.")
    @click.option("--email", prompt=True, help="Administrator email address.")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Admin password.")
    def create_admin(username, email, password):
        """Create the initial secure administrator account safely without hardcoding."""
        with app.app_context():
            db.create_all()
            from app.utils import validate_password_complexity
            is_valid, err = validate_password_complexity(password)
            if not is_valid:
                click.echo(f"[-] Error: {err}", err=True)
                return

            existing = User.query.filter(
                (User.username.ilike(username.strip())) | (User.email.ilike(email.strip()))
            ).first()
            if existing:
                click.echo(f"[-] Error: User with username '{username}' or email '{email}' already exists.", err=True)
                return

            admin_user = User(
                username=username.strip(),
                email=email.strip().lower(),
                role="admin",
                bio="System Administrator"
            )
            admin_user.set_password(password)
            db.session.add(admin_user)

            log_entry = AuditLog(
                action="ADMIN_ACCOUNT_BOOTSTRAPPED",
                status="SUCCESS",
                username=admin_user.username,
                details=f"Administrator account '{admin_user.username}' bootstrapped via CLI command."
            )
            db.session.add(log_entry)
            db.session.commit()

            click.echo(f"[+] Administrator account '{admin_user.username}' created successfully!")
