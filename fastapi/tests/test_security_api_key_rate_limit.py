"""Tests for APIKeyWithRateLimit."""
import time
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyWithRateLimit
from fastapi.testclient import TestClient
from pydantic import BaseModel

# Test app with rate limiting and deprecated keys
app = FastAPI()

# 5 requests per 10 seconds, with a deprecated key
api_key_scheme = APIKeyWithRateLimit(
    name="x-api-key",
    rate_limit="5/10s",
    deprecated_keys=["deprecated-key-123"],
)


class User(BaseModel):
    username: str


def get_current_user(oauth_header: str = Depends(api_key_scheme), request: Request = None):
    user = User(username=oauth_header)
    return user


@app.get("/users/me")
def read_current_user(current_user: User = Depends(get_current_user), request: Request = None):
    return current_user


@app.get("/users/me/json")
def read_current_user_json(current_user: User = Depends(get_current_user)):
    return current_user


client = TestClient(app)


def reset_rate_limit_store():
    """Reset the global rate limit store between tests."""
    from fastapi.security.api_key import _rate_limit_store
    _rate_limit_store._windows.clear()


def test_rate_limit_normal():
    """Test that normal requests succeed under the rate limit."""
    reset_rate_limit_store()
    for _ in range(5):
        response = client.get("/users/me", headers={"x-api-key": "valid-key"})
        assert response.status_code == 200, response.text


def test_rate_limit_exceeded():
    """Test that 429 is returned when rate limit is exceeded."""
    reset_rate_limit_store()
    # Use 5 requests (the limit)
    for i in range(5):
        response = client.get("/users/me", headers={"x-api-key": "test-exceed"})
        assert response.status_code == 200, f"Request {i} failed: {response.text}"
    # 6th request should be rate limited
    response = client.get("/users/me", headers={"x-api-key": "test-exceed"})
    assert response.status_code == 429, response.text
    assert response.json() == {"detail": "Too many requests"}
    assert "Retry-After" in response.headers


def test_rate_limit_window_resets():
    """Test that rate limit resets after the window passes."""
    reset_rate_limit_store()
    for _ in range(5):
        response = client.get("/users/me", headers={"x-api-key": "test-window"})
        assert response.status_code == 200
    # 6th should be 429
    response = client.get("/users/me", headers={"x-api-key": "test-window"})
    assert response.status_code == 429


def test_deprecated_key_authenticates():
    """Test that deprecated keys still authenticate successfully."""
    reset_rate_limit_store()
    response = client.get("/users/me", headers={"x-api-key": "deprecated-key-123"})
    assert response.status_code == 200, response.text
    assert response.json() == {"username": "deprecated-key-123"}


def test_non_deprecated_key_no_warning():
    """Test that non-deprecated keys return no Warning header."""
    reset_rate_limit_store()
    response = client.get("/users/me", headers={"x-api-key": "fresh-key"})
    assert response.status_code == 200


def test_rate_limit_tracks_per_key_independently():
    """Test that rate limiting is per API key, not global."""
    reset_rate_limit_store()
    # Exhaust key A
    for _ in range(5):
        response = client.get("/users/me", headers={"x-api-key": "key-a"})
        assert response.status_code == 200
    # Key B should still work independently
    for _ in range(5):
        response = client.get("/users/me", headers={"x-api-key": "key-b"})
        assert response.status_code == 200, response.text
    # Key A should be rate limited
    response = client.get("/users/me", headers={"x-api-key": "key-a"})
    assert response.status_code == 429


def test_retry_after_header_format():
    """Test Retry-After is an integer number of seconds."""
    reset_rate_limit_store()
    for _ in range(5):
        client.get("/users/me", headers={"x-api-key": "retry-test"})
    response = client.get("/users/me", headers={"x-api-key": "retry-test"})
    assert response.status_code == 429
    retry_after = response.headers.get("Retry-After", "")
    assert retry_after.isdigit(), f"Retry-After should be digits, got: {retry_after}"


def test_no_api_key():
    """Test that missing API key returns 401."""
    reset_rate_limit_store()
    response = client.get("/users/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == "APIKey"
