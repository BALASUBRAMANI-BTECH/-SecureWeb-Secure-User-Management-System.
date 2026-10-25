from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf
from app.auth import auth_bp
from app.extensions import db, limiter
from app.models import User
from app.forms import RegistrationForm, LoginForm, EmptyForm
from app.utils import is_safe_url, log_security_event


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    """
    Handle new user registration.
    Enforces strict input validation, password hashing, and logs security events.
    """
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Role is explicitly hardcoded to 'user' to eliminate privilege escalation
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role="user"
        )
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        log_security_event(
            action="USER_REGISTRATION",
            status="SUCCESS",
            details=f"New user registered: '{user.username}' (Email: {user.email})",
            user=user
        )

        flash("Account created successfully! You can now sign in with your credentials.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", title="Register", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def login():
    """
    Authenticate users via username or email and password.
    Includes rate limiting, anti-enumeration generic messaging,
    session fixation protection, and safe redirect validation.
    """
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        login_id = form.login_id.data.strip()
        password = form.password.data

        # Case-insensitive lookup by username OR email
        user = User.query.filter(
            (User.username.ilike(login_id)) | (User.email.ilike(login_id))
        ).first()

        if user and user.check_password(password):
            # Check if account is active or locked
            if not user.is_active:
                log_security_event(
                    action="LOGIN_BLOCKED_SUSPENDED",
                    status="WARNING",
                    details=f"Login attempt on inactive/locked account for identifier '{login_id}'.",
                    user=user
                )
                flash("Your account has been deactivated or locked. Please contact security administration.", "danger")
                return render_template("login.html", title="Sign In", form=form)

            # Prevent Session Fixation: clear existing session data before authenticating
            session.clear()

            # Establish authenticated session
            login_user(user, remember=form.remember_me.data)

            # Regenerate CSRF token in rotated session
            generate_csrf()

            # Update login telemetry
            user.last_login = datetime.utcnow()
            user.failed_login_attempts = 0
            db.session.commit()

            log_security_event(
                action="LOGIN_SUCCESS",
                status="SUCCESS",
                details=f"Successful authentication for user '{user.username}'.",
                user=user
            )

            flash(f"Welcome back, {user.username}!", "success")

            # Validate redirect URL against Open Redirect vulnerabilities (CWE-601)
            next_page = request.args.get("next")
            if not next_page or not is_safe_url(next_page):
                next_page = url_for("main.dashboard")

            return redirect(next_page)

        # Authentication failed: increment failed count if user exists
        if user:
            user.failed_login_attempts += 1
            db.session.commit()

        log_security_event(
            action="LOGIN_FAILED",
            status="FAILURE",
            details=f"Failed login attempt for identifier '{login_id}' from IP: {request.remote_addr}."
        )

        # Generic error message to prevent user enumeration (OWASP A07)
        flash("Invalid username/email or password.", "danger")

    return render_template("login.html", title="Sign In", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Secure logout endpoint requiring a CSRF-protected POST request.
    Invalidates session and terminates authentication.
    """
    form = EmptyForm()
    if form.validate_on_submit():
        user_name = current_user.username
        log_security_event(
            action="LOGOUT",
            status="SUCCESS",
            details=f"User '{user_name}' signed out.",
            user=current_user
        )

        # Flask-Login logout & complete session destruction
        logout_user()
        session.clear()
        generate_csrf()

        flash("You have been securely signed out.", "info")
        return redirect(url_for("auth.login"))

    # If CSRF validation fails
    abort(400)
