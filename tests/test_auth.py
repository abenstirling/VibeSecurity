"""
Tests for authentication utilities.
"""

from auth import get_user_id_from_token, is_premium_user


def test_get_user_id_from_token():
    """Test extracting user ID from decoded token."""
    token = {"uid": "test_user_123", "email": "test@example.com"}
    user_id = get_user_id_from_token(token)
    assert user_id == "test_user_123"


def test_get_user_id_from_token_missing_uid():
    """Test handling token without UID."""
    token = {"email": "test@example.com"}
    user_id = get_user_id_from_token(token)
    assert user_id is None


def test_is_premium_user_true():
    """Test premium user detection."""
    token = {"uid": "test_user", "premium": True}
    assert is_premium_user(token) is True


def test_is_premium_user_false():
    """Test non-premium user detection."""
    token = {"uid": "test_user", "premium": False}
    assert is_premium_user(token) is False


def test_is_premium_user_missing_field():
    """Test premium detection with missing field."""
    token = {"uid": "test_user"}
    assert is_premium_user(token) is False
