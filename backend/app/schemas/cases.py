"""Pydantic schemas for Persistent Investigation Cases."""
from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_PAYLOAD_BYTES = 1048576  # 1 MB maximum payload size to prevent DoS attacks
VALID_VERDICTS = {"benign", "suspicious", "high-risk", "inconclusive"}
SUPPORTED_SCHEMA_VERSIONS = {1}


def _strip_binary_data(obj: Any) -> Any:
    """Recursively traverses nested structures to redact raw binary blobs and base64 data URIs."""
    if isinstance(obj, dict):
        return {k: _strip_binary_data(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_strip_binary_data(elem) for elem in obj]
    elif isinstance(obj, str):
        if (
            obj.startswith("data:image/")
            or obj.startswith("data:audio/")
            or (len(obj) > 1024 and ";base64," in obj[:64])
        ):
            return "[BINARY_DATA_STRIPPED_FOR_PRIVACY]"
    return obj


class CaseCreateRequest(BaseModel):
    """Payload to save an investigation report."""

    case_id: Optional[str] = Field(None, max_length=64, description="Optional client/scan identifier")
    investigation_type: str = Field("unified", max_length=32, description="Modality or scan type")
    schema_version: int = Field(1, description="Schema version of the report payload envelope")
    report_payload: Dict[str, Any] = Field(..., description="Full structured forensic report payload")

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: int) -> int:
        if v not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"Unsupported schema_version {v}. Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            )
        return v

    @field_validator("report_payload")
    @classmethod
    def validate_payload_size(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("report_payload must be a JSON object dictionary.")

        # Check serialized byte size
        try:
            serialized = json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"report_payload is not JSON serializable: {exc}")

        if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"report_payload exceeds maximum size limit of {MAX_PAYLOAD_BYTES} bytes.")

        # Sanitize / Redact unnecessary binary or raw base64 content recursively
        return _strip_binary_data(v)


class CaseSummaryResponse(BaseModel):
    """Summary of an investigation case for listing."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    investigation_type: str
    verdict: str
    threat_score: float
    severity: str
    schema_version: int
    created_at: datetime
    summary: Optional[str] = None


class CaseDetailResponse(BaseModel):
    """Full detail of an investigation case for report restoration."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    investigation_type: str
    verdict: str
    threat_score: float
    severity: str
    schema_version: int
    report_payload: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class CaseListResponse(BaseModel):
    """Paginated collection of investigation cases."""

    items: List[CaseSummaryResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
