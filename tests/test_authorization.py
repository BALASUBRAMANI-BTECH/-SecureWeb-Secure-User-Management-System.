import pytest
from app.models import User
from tests.conftest import extract_csrf_token


def test_unauthenticated_private_pages_redirect(client):
    """Test that unauthenticated requests to protected endpoints redirect to login."""
    endpoints = ["/dashboard", "/profile", "/change-password", "/admin", "/admin/users", "/admin/audit-logs"]
    for endpoint in endpoints:
        res = client.get(endpoint, follow_redirects=False)
        assert res.status_code == 302, f"Endpoint {endpoint} should redirect unauthenticated request"
        assert "/login" in res.headers["Location"]


def test_standard_user_admin_access_returns_403(client, test_user):
    """
    Test that authenticated standard users are strictly forbidden from accessing
    admin endpoints (OWASP A01: Broken Access Control).
    """
    # Log in as standard user
    login_res = client.get("/login")
    csrf = extract_csrf_token(login_res)
    client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    })

    admin_endpoints = ["/admin/", "/admin/users", "/admin/audit-logs"]
    for ep in admin_endpoints:
        res = client.get(ep)
        assert res.status_code == 403, f"Standard user should receive 403 for {ep}"
        assert b"403 - Access Forbidden" in res.data


def test_admin_user_can_access_admin_portal(client, admin_user):
    """Test that users with the 'admin' role can successfully access administrative endpoints."""
    login_res = client.get("/login")
    csrf = extract_csrf_token(login_res)
    client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "security_admin",
        "password": "AdminSecurePass123!@#"
    })

    dash_res = client.get("/admin/")
    assert dash_res.status_code == 200
    assert b"ADMIN CONTROL CENTER" in dash_res.data

    users_res = client.get("/admin/users")
    assert users_res.status_code == 200
    assert b"Directory & Privilege Management" in users_res.data

    audit_res = client.get("/admin/audit-logs")
    assert audit_res.status_code == 200
    assert b"Forensic Audit Trail" in audit_res.data


def test_admin_cannot_demote_or_delete_self(client, admin_user, app):
    """Test safeguards preventing administrative self-demotion or self-deletion."""
    login_res = client.get("/login")
    csrf = extract_csrf_token(login_res)
    client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "security_admin",
        "password": "AdminSecurePass123!@#"
    }, follow_redirects=True)

    users_page = client.get("/admin/users")
    admin_csrf = extract_csrf_token(users_page)

    # Attempt to demote self
    demote_res = client.post(f"/admin/users/{admin_user.id}/toggle-role", data={
        "csrf_token": admin_csrf
    }, follow_redirects=True)
    assert b"Administrators cannot demote their own account" in demote_res.data

    # Attempt to delete self with refreshed CSRF token
    fresh_csrf = extract_csrf_token(demote_res)
    delete_res = client.post(f"/admin/users/{admin_user.id}/delete", data={
        "csrf_token": fresh_csrf
    }, follow_redirects=True)
    assert b"Administrators cannot delete their own account" in delete_res.data

    with app.app_context():
        recheck = User.query.get(admin_user.id)
        assert recheck is not None
        assert recheck.role == "admin"


def test_admin_can_toggle_role_of_other_user(client, admin_user, test_user, app):
    """Test that an admin can promote a standard user to admin and demote back."""
    login_res = client.get("/login")
    csrf = extract_csrf_token(login_res)
    client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "security_admin",
        "password": "AdminSecurePass123!@#"
    }, follow_redirects=True)

    users_page = client.get("/admin/users")
    admin_csrf = extract_csrf_token(users_page)

    # Promote standard_user
    res = client.post(f"/admin/users/{test_user.id}/toggle-role", data={
        "csrf_token": admin_csrf
    }, follow_redirects=True)
    assert res.status_code == 200

    with app.app_context():
        u = User.query.get(test_user.id)
        assert u.role == "admin"

    # Demote back with refreshed token
    fresh_csrf2 = extract_csrf_token(res)
    res2 = client.post(f"/admin/users/{test_user.id}/toggle-role", data={
        "csrf_token": fresh_csrf2
    }, follow_redirects=True)
    assert res2.status_code == 200

    with app.app_context():
        u2 = User.query.get(test_user.id)
        assert u2.role == "user"


def test_user_cannot_escalate_role_via_profile_or_registration(client, test_user, app):
    """
    Test that users cannot escalate their role by injecting role='admin'
    in registration or profile update forms.
    """
    # 1. Registration privilege escalation attempt
    reg_page = client.get("/register")
    csrf = extract_csrf_token(reg_page)
    client.post("/register", data={
        "csrf_token": csrf,
        "username": "hacker_wannabe",
        "email": "hacker@example.com",
        "password": "HackerPass123!@#",
        "confirm_password": "HackerPass123!@#",
        "role": "admin"  # Malicious parameter
    })

    with app.app_context():
        u = User.query.filter_by(username="hacker_wannabe").first()
        assert u is not None
        assert u.role == "user"  # Role must stay 'user'

    # 2. Profile update privilege escalation attempt
    login_res = client.get("/login")
    login_csrf = extract_csrf_token(login_res)
    client.post("/login", data={
        "csrf_token": login_csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    })

    profile_page = client.get("/profile")
    prof_csrf = extract_csrf_token(profile_page)
    client.post("/profile", data={
        "csrf_token": prof_csrf,
        "email": "user@example.com",
        "bio": "Attempting privilege escalation",
        "role": "admin"  # Malicious parameter
    })

    with app.app_context():
        u2 = User.query.get(test_user.id)
        assert u2.role == "user"


def test_cli_create_admin_command(runner, app):
    """Test CLI management command to securely create first administrator."""
    result = runner.invoke(args=[
        "create-admin",
        "--username", "cli_superadmin",
        "--email", "cli_admin@example.com",
        "--password", "CliAdminSecret123!@#"
    ])
    assert result.exit_code == 0
    assert "created successfully" in result.output

    with app.app_context():
        admin = User.query.filter_by(username="cli_superadmin").first()
        assert admin is not None
        assert admin.role == "admin"
        assert admin.check_password("CliAdminSecret123!@#") is True
