import pytest
from app.models import User
from tests.conftest import extract_csrf_token


def test_register_success(client, app):
    """Test successful user registration with valid credentials and complexity compliance."""
    res = client.get("/register")
    csrf_token = extract_csrf_token(res)

    payload = {
        "csrf_token": csrf_token,
        "username": "new_sec_user",
        "email": "newuser@example.com",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }

    post_res = client.post("/register", data=payload, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"Account created successfully" in post_res.data

    with app.app_context():
        user = User.query.filter_by(username="new_sec_user").first()
        assert user is not None
        assert user.email == "newuser@example.com"
        assert user.role == "user"  # Role defaults strictly to user
        # Password must NOT be stored in plaintext
        assert user.password_hash != "StrongPassword123!"
        assert user.check_password("StrongPassword123!") is True


def test_register_duplicate_username(client, test_user):
    """Test that duplicate usernames are rejected."""
    res = client.get("/register")
    csrf = extract_csrf_token(res)

    payload = {
        "csrf_token": csrf,
        "username": "standard_user",  # Already taken by test_user
        "email": "unique_email@example.com",
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }

    post_res = client.post("/register", data=payload)
    assert post_res.status_code == 200
    assert b"This username is already taken" in post_res.data


def test_register_duplicate_email(client, test_user):
    """Test that duplicate email addresses are rejected."""
    res = client.get("/register")
    csrf = extract_csrf_token(res)

    payload = {
        "csrf_token": csrf,
        "username": "unique_username",
        "email": "user@example.com",  # Already taken by test_user
        "password": "StrongPassword123!",
        "confirm_password": "StrongPassword123!"
    }

    post_res = client.post("/register", data=payload)
    assert post_res.status_code == 200
    assert b"An account with this email address already exists" in post_res.data


def test_register_weak_password_rejected(client):
    """Test that weak passwords failing OWASP complexity rules are rejected."""
    res = client.get("/register")
    csrf = extract_csrf_token(res)

    weak_passwords = [
        ("short", "at least 8 characters"),
        ("nouppercase123!", "at least one uppercase letter"),
        ("NOLOWERCASE123!", "at least one lowercase letter"),
        ("NoNumbersHere!", "at least one number"),
        ("NoSpecialChar123", "at least one special character")
    ]

    for pwd, expected_msg in weak_passwords:
        payload = {
            "csrf_token": csrf,
            "username": f"user_{pwd[:4]}",
            "email": f"{pwd[:4]}@example.com",
            "password": pwd,
            "confirm_password": pwd
        }
        post_res = client.post("/register", data=payload)
        assert expected_msg.encode("utf-8") in post_res.data


def test_login_success_with_username(client, test_user):
    """Test valid login using username."""
    res = client.get("/login")
    csrf = extract_csrf_token(res)

    payload = {
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    }

    post_res = client.post("/login", data=payload, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"Welcome back, standard_user!" in post_res.data
    assert b"Dashboard" in post_res.data


def test_login_success_with_email(client, test_user):
    """Test valid login using registered email address."""
    res = client.get("/login")
    csrf = extract_csrf_token(res)

    payload = {
        "csrf_token": csrf,
        "login_id": "user@example.com",
        "password": "StandardPass123!@#"
    }

    post_res = client.post("/login", data=payload, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"Welcome back, standard_user!" in post_res.data


def test_login_invalid_credentials_generic_error(client, test_user):
    """
    Test that invalid credentials produce a generic error message
    to prevent user enumeration (OWASP A07).
    """
    res = client.get("/login")
    csrf = extract_csrf_token(res)

    # 1. Existing user, wrong password
    post_res1 = client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "WrongPassword123!"
    })
    assert b"Invalid username/email or password." in post_res1.data

    # 2. Non-existent user
    res2 = client.get("/login")
    csrf2 = extract_csrf_token(res2)
    post_res2 = client.post("/login", data={
        "csrf_token": csrf2,
        "login_id": "nonexistent_principal",
        "password": "AnyPassword123!"
    })
    # Both responses must present the identical generic error message
    assert b"Invalid username/email or password." in post_res2.data


def test_logout_invalidates_session(client, test_user):
    """Test that CSRF-protected POST logout invalidates authenticated session."""
    # Log in first
    res = client.get("/login")
    csrf = extract_csrf_token(res)
    r_login = client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    }, follow_redirects=True)
    assert r_login.status_code == 200

    # Extract authenticated CSRF token from rendered dashboard
    dash_csrf = extract_csrf_token(r_login)

    # Post to logout with CSRF token
    logout_res = client.post("/logout", data={"csrf_token": dash_csrf}, follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"You have been securely signed out" in logout_res.data

    # Verify session is invalidated; dashboard access must redirect to login
    subsequent_res = client.get("/dashboard", follow_redirects=False)
    assert subsequent_res.status_code == 302
    assert "/login" in subsequent_res.headers["Location"]


def test_logout_get_method_rejected(client, test_user):
    """Test that GET requests to /logout are disallowed (requires CSRF-protected POST)."""
    get_res = client.get("/logout")
    # Method Not Allowed (405)
    assert get_res.status_code == 405
