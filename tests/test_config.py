"""
Tests for configuration module.
"""

from config import FIREBASE_CONFIG, generate_csrf_token, validate_csrf_token


def test_generate_csrf_token():
    """Test CSRF token generation."""
    session_token = "test_session_123"
    csrf_token = generate_csrf_token(session_token)

    assert csrf_token is not None
    assert len(csrf_token) > 0
    assert isinstance(csrf_token, str)


def test_validate_csrf_token_valid():
    """Test valid CSRF token validation."""
    session_token = "test_session_123"
    csrf_token = generate_csrf_token(session_token)

    assert validate_csrf_token(session_token, csrf_token) is True


def test_validate_csrf_token_invalid():
    """Test invalid CSRF token validation."""
    session_token = "test_session_123"
    generate_csrf_token(session_token)

    assert validate_csrf_token(session_token, "invalid_token") is False


def test_validate_csrf_token_unknown_session():
    """Test CSRF validation with unknown session."""
    assert validate_csrf_token("unknown_session", "any_token") is False


def test_firebase_config_structure():
    """Test Firebase config has required fields."""
    required_fields = [
        "api_key",
        "auth_domain",
        "project_id",
        "storage_bucket",
        "messaging_sender_id",
        "app_id",
        "measurement_id",
    ]

    for field in required_fields:
        assert field in FIREBASE_CONFIG
        assert isinstance(FIREBASE_CONFIG[field], str)
