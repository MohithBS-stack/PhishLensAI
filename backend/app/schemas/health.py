"""Health check response schemas."""
from datetime import datetime
from typing import Dict
from pydantic import BaseModel, Field


class SystemInfo(BaseModel):
    python_version: str
    platform: str


class HealthResponse(BaseModel):
    status: str = Field(default="healthy", description="Service health status")
    app_name: str = Field(description="Name of the application")
    version: str = Field(description="Semantic version")
    environment: str = Field(description="Runtime environment")
    timestamp: datetime = Field(description="Current UTC timestamp")
    system: SystemInfo = Field(description="Operating environment telemetry")
    models_loaded: Dict[str, bool] = Field(
        default_factory=dict,
        description="Status of ML model artifacts in memory",
    )
