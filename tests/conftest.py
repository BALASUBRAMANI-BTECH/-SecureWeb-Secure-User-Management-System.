import pytest
from bs4 import BeautifulSoup
from app import create_app
from app.extensions import db
from app.models import User, AuditLog
from config import TestingConfig


class PytestConfig(TestingConfig):
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"


@pytest.fixture
def app():
    """Create and configure a Flask app instance for testing."""
    application = create_app("testing")
    application.config.from_object(PytestConfig)

    with application.app_context():
        db.create_all()

    yield application

    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client for issuing requests."""
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_limiter(app):
    """Reset rate limiter buckets before each test to prevent cross-test throttle pollution."""
    from app.extensions import limiter
    with app.app_context():
        limiter.reset()


@pytest.fixture
def runner(app):
    """CLI runner for testing Flask management commands."""
    return app.test_cli_runner()


def extract_csrf_token(response) -> str:
    """Helper function to extract CSRF token from rendered HTML response."""
    soup = BeautifulSoup(response.data.decode("utf-8"), "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    if csrf_input and csrf_input.get("value"):
        return csrf_input.get("value")
    return ""


@pytest.fixture
def test_user(app):
    """Create and return a standard test user."""
    with app.app_context():
        user = User(
            username="standard_user",
            email="user@example.com",
            role="user",
            bio="Standard test account."
        )
        user.set_password("StandardPass123!@#")
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        db.session.expunge(user)
        return user


@pytest.fixture
def admin_user(app):
    """Create and return an administrator test user."""
    with app.app_context():
        admin = User(
            username="security_admin",
            email="admin@example.com",
            role="admin",
            bio="Security Administrator"
        )
        admin.set_password("AdminSecurePass123!@#")
        db.session.add(admin)
        db.session.commit()
        db.session.refresh(admin)
        db.session.expunge(admin)
        return admin
