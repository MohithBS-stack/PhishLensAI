"""Tests for health check endpoints."""
from fastapi import status


def test_root_health_endpoint(client):
    """Verify GET /health returns 200 and valid schema."""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK

    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "PhishLens AI API"
    assert data["version"] == "1.0.0"
    assert "environment" in data
    assert "timestamp" in data
    assert "system" in data
    assert "python_version" in data["system"]
    assert "platform" in data["system"]
    assert "models_loaded" in data
    assert isinstance(data["models_loaded"], dict)
    assert isinstance(data["models_loaded"].get("url_classifier"), bool)
    assert isinstance(data["models_loaded"].get("sms_classifier"), bool)
    # When artifacts exist in models/saved/, they evaluate to True
    assert data["models_loaded"]["url_classifier"] is True
    assert data["models_loaded"]["sms_classifier"] is True

    # Check Request-ID header
    assert "X-Request-ID" in response.headers


def test_api_v1_health_endpoint(client):
    """Verify GET /api/v1/health returns 200 matching root health."""
    response = client.get("/api/v1/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
