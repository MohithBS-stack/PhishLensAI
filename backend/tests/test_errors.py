"""Tests for structured error responses."""
from fastapi import status
from app.core.errors import NotFoundError, ValidationException, build_error_payload


def test_404_structured_error(client):
    """Verify non-existent routes return structured error JSON."""
    response = client.get("/non_existent_route")
    assert response.status_code == status.HTTP_404_NOT_FOUND

    data = response.json()
    assert "error" in data
    error = data["error"]
    assert error["status_code"] == 404
    assert "message" in error
    assert "timestamp" in error
    assert "request_id" in error
    assert "X-Request-ID" in response.headers


def test_custom_app_exception_structure():
    """Verify AppException and its subclasses have expected attributes."""
    exc = NotFoundError(message="URL not found", details={"url": "http://example.com"})
    assert exc.status_code == 404
    assert exc.error_code == "RESOURCE_NOT_FOUND"
    assert exc.message == "URL not found"
    assert exc.details == {"url": "http://example.com"}

    payload = build_error_payload(
        code=exc.error_code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
        request_id="test-req-123",
    )
    assert payload["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert payload["error"]["request_id"] == "test-req-123"
    assert payload["error"]["details"]["url"] == "http://example.com"
