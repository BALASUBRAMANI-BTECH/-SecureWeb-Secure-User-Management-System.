from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import current_user
from app.admin import admin_bp
from app.extensions import db
from app.models import User, AuditLog
from app.forms import EmptyForm
from app.utils import admin_required, log_security_event


@admin_bp.route("/")
@admin_bp.route("")
@admin_required
def dashboard():
    """
    Administrative control dashboard.
    Visualizes user metrics, role distributions, and critical security alarms.
    """
    total_users = User.query.count()
    admin_count = User.query.filter_by(role="admin").count()
    standard_users = total_users - admin_count
    inactive_users = User.query.filter_by(is_active_account=False).count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    warning_logs = AuditLog.query.filter(AuditLog.status.in_(["WARNING", "FAILURE"])).count()

    logout_form = EmptyForm()

    return render_template(
        "admin/dashboard.html",
        title="Admin Control Center",
        total_users=total_users,
        admin_count=admin_count,
        standard_users=standard_users,
        inactive_users=inactive_users,
        recent_logs=recent_logs,
        warning_logs=warning_logs,
        logout_form=logout_form
    )


@admin_bp.route("/users")
@admin_required
def users_list():
    """
    User account governance and administration portal.
    """
    users = User.query.order_by(User.id.asc()).all()
    form = EmptyForm()
    logout_form = EmptyForm()

    return render_template(
        "admin/users.html",
        title="User Governance",
        users=users,
        form=form,
        logout_form=logout_form
    )


@admin_bp.route("/users/<int:user_id>/toggle-role", methods=["POST"])
@admin_required
def toggle_user_role(user_id):
    """
    Change user role between 'user' and 'admin'.
    Includes safeguards against self-demotion and eliminating the last administrator.
    """
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)

    target_user = User.query.get_or_404(user_id)

    # Prevent self-demotion
    if target_user.id == current_user.id:
        flash("Action blocked: Administrators cannot demote their own account.", "warning")
        return redirect(url_for("admin.users_list"))

    # If demoting an admin, ensure there is at least one other active admin
    if target_user.role == "admin":
        other_admins = User.query.filter(
            User.role == "admin",
            User.id != target_user.id,
            User.is_active_account == True
        ).count()
        if other_admins == 0:
            flash("Action blocked: Cannot demote the last remaining active administrator.", "danger")
            return redirect(url_for("admin.users_list"))
        target_user.role = "user"
    else:
        target_user.role = "admin"

    db.session.commit()

    log_security_event(
        action="ADMIN_ROLE_CHANGE",
        status="SUCCESS",
        details=f"Admin '{current_user.username}' changed role for '{target_user.username}' to '{target_user.role}'.",
        user=current_user
    )

    flash(f"Role for user '{target_user.username}' updated to '{target_user.role}'.", "success")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/users/<int:user_id>/toggle-status", methods=["POST"])
@admin_required
def toggle_user_status(user_id):
    """
    Activate or deactivate user account.
    Deactivated accounts cannot authenticate.
    """
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)

    target_user = User.query.get_or_404(user_id)

    if target_user.id == current_user.id:
        flash("Action blocked: Administrators cannot deactivate their own account.", "warning")
        return redirect(url_for("admin.users_list"))

    target_user.is_active_account = not target_user.is_active_account
    db.session.commit()

    action_label = "activated" if target_user.is_active_account else "deactivated"
    log_security_event(
        action="ADMIN_ACCOUNT_STATUS_CHANGE",
        status="SUCCESS",
        details=f"Admin '{current_user.username}' {action_label} account for '{target_user.username}'.",
        user=current_user
    )

    flash(f"Account for user '{target_user.username}' was {action_label}.", "info")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    """
    Safely delete a user account from database.
    Prevents self-deletion or deletion of the last administrator.
    """
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)

    target_user = User.query.get_or_404(user_id)

    if target_user.id == current_user.id:
        flash("Action blocked: Administrators cannot delete their own account.", "warning")
        return redirect(url_for("admin.users_list"))

    if target_user.role == "admin":
        other_admins = User.query.filter(User.role == "admin", User.id != target_user.id).count()
        if other_admins == 0:
            flash("Action blocked: Cannot delete the only remaining administrator account.", "danger")
            return redirect(url_for("admin.users_list"))

    username_cached = target_user.username
    db.session.delete(target_user)
    db.session.commit()

    log_security_event(
        action="ADMIN_USER_DELETED",
        status="WARNING",
        details=f"Admin '{current_user.username}' permanently deleted user account '{username_cached}'.",
        user=current_user
    )

    flash(f"User '{username_cached}' has been removed.", "success")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/audit-logs")
@admin_required
def audit_logs():
    """
    System-wide security event journal and forensic log viewer.
    """
    page = request.args.get("page", 1, type=int)
    status_filter = request.args.get("status", "").strip().upper()

    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if status_filter in ["SUCCESS", "FAILURE", "WARNING"]:
        query = query.filter_by(status=status_filter)

    logs = query.paginate(page=page, per_page=20, error_out=False)
    logout_form = EmptyForm()

    return render_template(
        "admin/audit_logs.html",
        title="Security Audit Logs",
        logs=logs,
        status_filter=status_filter,
        logout_form=logout_form
    )
