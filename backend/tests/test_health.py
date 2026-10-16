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


def test_cors_origin_regex_and_preflight(client):
    """Verify that project-specific Vercel domains match while third-party apps are blocked."""
    # 1. Allowed project Vercel preview origin via regex
    response = client.get("/health", headers={"Origin": "https://phishlens-ai-custom-branch.vercel.app"})
    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("access-control-allow-origin") == "https://phishlens-ai-custom-branch.vercel.app"

    # 2. Preflight OPTIONS request for project Vercel origin
    options_res = client.options(
        "/health",
        headers={
            "Origin": "https://phishlens-ai-custom-branch.vercel.app",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert options_res.status_code == status.HTTP_200_OK
    assert options_res.headers.get("access-control-allow-origin") == "https://phishlens-ai-custom-branch.vercel.app"

    # 3. Disallowed arbitrary third-party Vercel app (strictly rejected)
    arbitrary_vercel = client.get("/health", headers={"Origin": "https://unrelated-tenant-app.vercel.app"})
    assert "access-control-allow-origin" not in arbitrary_vercel.headers

    # 4. Disallowed attacker origin
    disallowed = client.get("/health", headers={"Origin": "https://malicious-site.com"})
    assert "access-control-allow-origin" not in disallowed.headers
