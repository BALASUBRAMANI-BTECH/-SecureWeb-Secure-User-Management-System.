from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.main import main_bp
from app.extensions import db
from app.models import User, AuditLog
from app.forms import ProfileUpdateForm, ChangePasswordForm, EmptyForm
from app.utils import log_security_event


@main_bp.route("/")
def index():
    """
    Landing page showcasing project overview, security architecture,
    and OWASP Top 10 mitigation matrix.
    """
    total_users = User.query.count()
    return render_template("index.html", title="Home", total_users=total_users)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Authenticated user dashboard displaying identity, role,
    session status, and personal security telemetry.
    """
    logout_form = EmptyForm()
    # Fetch recent security logs for current user only (preventing BOLA/IDOR)
    user_logs = (
        AuditLog.query.filter_by(user_id=current_user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "dashboard.html",
        title="Dashboard",
        user=current_user,
        logout_form=logout_form,
        user_logs=user_logs
    )


@main_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """
    Manage personal profile details.
    Restricted strictly to the authenticated user's own record (Anti-IDOR).
    Role escalation is prevented by disallowing role updates through this form.
    """
    form = ProfileUpdateForm()
    logout_form = EmptyForm()

    if form.validate_on_submit():
        current_user.email = form.email.data.strip().lower()
        current_user.bio = form.bio.data.strip() if form.bio.data else ""

        db.session.commit()

        log_security_event(
            action="PROFILE_UPDATED",
            status="SUCCESS",
            details=f"User '{current_user.username}' updated profile information.",
            user=current_user
        )

        flash("Profile updated successfully.", "success")
        return redirect(url_for("main.profile"))

    elif request.method == "GET":
        form.email.data = current_user.email
        form.bio.data = current_user.bio

    return render_template(
        "profile.html",
        title="Profile Settings",
        form=form,
        logout_form=logout_form
    )


@main_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """
    Secure password rotation workflow.
    Requires verification of current password, enforces OWASP complexity rules,
    and invalidates old password hashes.
    """
    form = ChangePasswordForm()
    logout_form = EmptyForm()

    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            log_security_event(
                action="PASSWORD_CHANGE_FAILED",
                status="WARNING",
                details=f"User '{current_user.username}' failed password change: incorrect current password.",
                user=current_user
            )
            flash("Current password verification failed.", "danger")
            return render_template("change_password.html", title="Change Password", form=form, logout_form=logout_form)

        # Update password hash
        current_user.set_password(form.new_password.data)
        db.session.commit()

        log_security_event(
            action="PASSWORD_CHANGE_SUCCESS",
            status="SUCCESS",
            details=f"User '{current_user.username}' successfully changed their password.",
            user=current_user
        )

        flash("Password updated successfully.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("change_password.html", title="Change Password", form=form, logout_form=logout_form)
