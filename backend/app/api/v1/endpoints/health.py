"""Health check endpoint."""
from datetime import datetime, timezone
import platform
import sys
from fastapi import APIRouter
from app.core.config import settings
from app.schemas.health import HealthResponse, SystemInfo
from app.services.model_registry import model_registry

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """Returns application health, environment metadata, and loaded model status."""
    return HealthResponse(
        status="healthy",
        app_name=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        system=SystemInfo(
            python_version=sys.version.split()[0],
            platform=platform.system(),
        ),
        models_loaded=model_registry.get_status(),
    )
