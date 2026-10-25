import pytest
from app.models import User
from config import ProductionConfig
from tests.conftest import extract_csrf_token


def test_sql_injection_login_payload_fails(client, test_user):
    """
    Test that standard and advanced SQL injection payloads cannot bypass authentication.
    OWASP A03: Injection prevention via SQLAlchemy ORM.
    """
    sqli_payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT 1, 'admin', 'hash' --",
        '" OR ""="',
        "admin' /*",
    ]

    for payload in sqli_payloads:
        with client.application.app_context():
            from app.extensions import limiter
            limiter.reset()

        login_page = client.get("/login")
        csrf = extract_csrf_token(login_page)

        res = client.post("/login", data={
            "csrf_token": csrf,
            "login_id": payload,
            "password": "random_password"
        })
        assert res.status_code == 200
        assert b"Invalid username/email or password." in res.data
        assert b"Dashboard" not in res.data


def test_xss_payload_escaped_in_html(client, test_user):
    """
    Test that Cross-Site Scripting (XSS) payloads are escaped by Jinja2 templates (OWASP A03).
    Verifies that raw script tags are never rendered unescaped.
    """
    # Log in
    login_page = client.get("/login")
    csrf = extract_csrf_token(login_page)
    res_login = client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    }, follow_redirects=True)
    assert res_login.status_code == 200

    # Update profile with XSS payload in bio
    prof_page = client.get("/profile")
    prof_csrf = extract_csrf_token(prof_page)
    xss_payload = "<script>alert('XSS_ATTACK')</script>"

    res_prof = client.post("/profile", data={
        "csrf_token": prof_csrf,
        "email": "user@example.com",
        "bio": xss_payload
    }, follow_redirects=True)
    assert res_prof.status_code == 200

    # Inspect dashboard rendering
    dash_res = client.get("/dashboard")
    raw_data = dash_res.data.decode("utf-8")

    # The raw <script> tag must NOT exist in the document
    assert "<script>alert('XSS_ATTACK')</script>" not in raw_data
    # Escaped HTML representation must be present
    assert "&lt;script&gt;alert(&#39;XSS_ATTACK&#39;)&lt;/script&gt;" in raw_data or "&lt;script&gt;" in raw_data


def test_security_headers_present(client):
    """Test that all required OWASP security headers are present in HTTP responses."""
    res = client.get("/")
    assert res.status_code == 200

    # Content-Security-Policy
    csp = res.headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp

    # X-Content-Type-Options
    assert res.headers.get("X-Content-Type-Options") == "nosniff"

    # X-Frame-Options
    assert res.headers.get("X-Frame-Options") == "DENY"

    # Referrer-Policy
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_anti_cache_headers_on_authenticated_endpoints(client, test_user):
    """Test that sensitive authenticated endpoints include no-cache directives to prevent history sniffing."""
    login_page = client.get("/login")
    csrf = extract_csrf_token(login_page)
    client.post("/login", data={
        "csrf_token": csrf,
        "login_id": "standard_user",
        "password": "StandardPass123!@#"
    })

    dash_res = client.get("/dashboard")
    cache_control = dash_res.headers.get("Cache-Control", "")
    assert "no-store" in cache_control
    assert "no-cache" in cache_control


def test_anti_open_redirect_protection(client, test_user):
    """
    Test that malicious 'next' redirect parameters targeting external URLs
    are detected and neutralized (CWE-601 / OWASP A01).
    """
    malicious_targets = [
        "https://evil-phishing-site.com/steal-creds",
        "http://attacker.com",
        "//evil.com",
        "\\\\evil.com",
        "javascript:alert(1)",
    ]

    for evil_url in malicious_targets:
        cl = client.application.test_client()
        with client.application.app_context():
            from app.extensions import limiter
            limiter.reset()

        login_page = cl.get(f"/login?next={evil_url}")
        csrf = extract_csrf_token(login_page)

        res = cl.post(f"/login?next={evil_url}", data={
            "csrf_token": csrf,
            "login_id": "standard_user",
            "password": "StandardPass123!@#"
        }, follow_redirects=False)

        # Must redirect to /dashboard and NOT the external URL
        assert res.status_code == 302
        redirect_target = res.headers.get("Location")
        assert not redirect_target.startswith("https://evil-phishing-site.com")
        assert not redirect_target.startswith("//evil.com")
        assert "/dashboard" in redirect_target


def test_rate_limiting_triggered(client, test_user):
    """Test that excessive failed requests trigger HTTP 429 Too Many Requests."""
    login_page = client.get("/login")
    csrf = extract_csrf_token(login_page)

    hit_429 = False
    # Route limit is 5 per minute
    for _ in range(8):
        res = client.post("/login", data={
            "csrf_token": csrf,
            "login_id": "wrong_user",
            "password": "WrongPassword123!"
        })
        if res.status_code == 429:
            hit_429 = True
            assert b"429 - Rate Limit Exceeded" in res.data or b"Too many requests" in res.data
            break

    assert hit_429, "Rate limiter failed to trigger HTTP 429 after exceeding limit threshold"


def test_production_configuration_integrity():
    """Verify production security configuration flags."""
    assert ProductionConfig.DEBUG is False
    assert ProductionConfig.SESSION_COOKIE_SECURE is True
    assert ProductionConfig.SESSION_COOKIE_HTTPONLY is True
    assert ProductionConfig.SESSION_COOKIE_SAMESITE == "Lax"

    # Test that unconfigured or default secret key in production raises a ValueError
    class MockApp:
        pass

    import os
    old_val = os.environ.get("SECRET_KEY")
    try:
        os.environ["SECRET_KEY"] = "dev-insecure-key"
        with pytest.raises(ValueError) as excinfo:
            ProductionConfig.init_app(MockApp())
        assert "Production environment requires a strong" in str(excinfo.value)
    finally:
        if old_val:
            os.environ["SECRET_KEY"] = old_val
        else:
            os.environ.pop("SECRET_KEY", None)
