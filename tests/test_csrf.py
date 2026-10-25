import pytest
from tests.conftest import extract_csrf_token


def test_missing_csrf_token_rejected_400(client):
    """Test that state-changing POST requests without CSRF token are rejected with HTTP 400."""
    res = client.post("/login", data={
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    })
    assert res.status_code == 400
    assert b"CSRF" in res.data or b"Bad Request" in res.data


def test_invalid_csrf_token_rejected_400(client):
    """Test that state-changing POST requests with tampered CSRF token are rejected."""
    res = client.post("/register", data={
        "csrf_token": "tampered_bogus_token_12345",
        "username": "attacker",
        "email": "attacker@example.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert res.status_code == 400


def test_valid_csrf_token_accepted(client, test_user):
    """Test that requests with valid CSRF token pass verification."""
    login_page = client.get("/login")
    csrf_token = extract_csrf_token(login_page)
    assert csrf_token != ""

    res = client.post("/login", data={
        "csrf_token": csrf_token,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Welcome back, standard_user!" in res.data


def test_logout_missing_csrf_rejected_400(client, test_user):
    """Test that POST /logout without CSRF token is rejected."""
    # Login first with valid CSRF
    login_page = client.get("/login")
    csrf = extract_csrf_token(login_page)
    client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    })

    # Logout attempt without CSRF token
    logout_res = client.post("/logout", data={})
    assert logout_res.status_code == 400
