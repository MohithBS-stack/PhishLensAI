"""Authenticated Case History Endpoints for PhishLens AI."""
from datetime import datetime, timezone
import logging
import math
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user
from app.core.errors import AppException
from app.db.session import get_db
from app.models.case import InvestigationCase
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.cases import (
    CaseCreateRequest,
    CaseDetailResponse,
    CaseListResponse,
    CaseSummaryResponse,
    VALID_VERDICTS,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["Case History"])


def _extract_summary(payload: dict) -> Optional[str]:
    """Safely extracts a readable one-line summary from the report payload."""
    explanation = payload.get("explanation")
    if isinstance(explanation, dict) and explanation.get("summary"):
        return str(explanation["summary"])[:255]
    if payload.get("executive_summary"):
        return str(payload["executive_summary"])[:255]
    return None


@router.post(
    "",
    response_model=CaseDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Save an authenticated investigation case",
)
async def save_case(
    payload: CaseCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> CaseDetailResponse:
    """Saves a forensic report to the authenticated user's private persistent case ledger."""
    # 1. Resolve case_id
    raw_case_id = payload.case_id or payload.report_payload.get("case_id")
    if raw_case_id and isinstance(raw_case_id, str) and raw_case_id.strip():
        clean_case_id = raw_case_id.strip()
    else:
        clean_case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    # 2. Derive verdict from payload
    raw_verdict = payload.report_payload.get("verdict") or payload.report_payload.get("threat_level")
    verdict = str(raw_verdict).lower() if raw_verdict else "inconclusive"
    if verdict not in VALID_VERDICTS:
        verdict = "inconclusive"

    # 3. Derive threat_score from payload
    raw_score = payload.report_payload.get("score")
    if raw_score is None:
        raw_score = payload.report_payload.get("overall_threat_score", 0.0)
    try:
        threat_score = max(0.0, min(100.0, float(raw_score)))
    except (ValueError, TypeError):
        threat_score = 0.0

    # 4. Derive severity
    if threat_score >= 70.0:
        severity = "critical" if threat_score >= 85.0 else "high"
    elif threat_score >= 40.0:
        severity = "medium"
    else:
        severity = "low"

    # Check if case_id already exists for this user (idempotent update)
    stmt = select(InvestigationCase).where(
        InvestigationCase.case_id == clean_case_id,
        InvestigationCase.user_id == current_user.id,
    )
    existing_case = (await db.execute(stmt)).scalar_one_or_none()

    if existing_case:
        existing_case.verdict = verdict
        existing_case.threat_score = threat_score
        existing_case.severity = severity
        existing_case.schema_version = payload.schema_version
        existing_case.report_payload = payload.report_payload
        existing_case.investigation_type = payload.investigation_type
        existing_case.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(existing_case)
        return CaseDetailResponse.model_validate(existing_case)

    # Check if case_id collides with another user's case (if so, generate length-safe unique suffix)
    collision_stmt = select(InvestigationCase).where(InvestigationCase.case_id == clean_case_id)
    if (await db.execute(collision_stmt)).scalar_one_or_none():
        base_prefix = clean_case_id[:58]
        clean_case_id = f"{base_prefix}-{uuid.uuid4().hex[:4].upper()}"

    new_case = InvestigationCase(
        id=uuid.uuid4(),
        case_id=clean_case_id,
        user_id=current_user.id,
        investigation_type=payload.investigation_type,
        verdict=verdict,
        threat_score=threat_score,
        severity=severity,
        schema_version=payload.schema_version,
        report_payload=payload.report_payload,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    db.add(new_case)
    try:
        await db.commit()
        await db.refresh(new_case)
    except IntegrityError:
        await db.rollback()
        # Handle concurrent collision race: append a fresh high-entropy suffix
        base_prefix = clean_case_id[:53]
        new_case.id = uuid.uuid4()
        new_case.case_id = f"{base_prefix}-{uuid.uuid4().hex[:8].upper()}"
        db.add(new_case)
        await db.commit()
        await db.refresh(new_case)

    return CaseDetailResponse.model_validate(new_case)


@router.get(
    "",
    response_model=CaseListResponse,
    status_code=status.HTTP_200_OK,
    summary="List authenticated user's investigation cases",
)
async def list_cases(
    page: int = Query(1, ge=1, description="Page number starting from 1"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> CaseListResponse:
    """Returns a paginated list of cases owned by the authenticated operator with stable sorting."""
    # 1. Total count query
    count_stmt = select(func.count(InvestigationCase.id)).where(
        InvestigationCase.user_id == current_user.id
    )
    total = (await db.execute(count_stmt)).scalar() or 0

    # 2. Paginated items query
    stmt = (
        select(InvestigationCase)
        .where(InvestigationCase.user_id == current_user.id)
        .order_by(InvestigationCase.created_at.desc(), InvestigationCase.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    cases = (await db.execute(stmt)).scalars().all()

    items: list[CaseSummaryResponse] = []
    for c in cases:
        items.append(
            CaseSummaryResponse(
                id=c.id,
                case_id=c.case_id,
                investigation_type=c.investigation_type,
                verdict=c.verdict,
                threat_score=c.threat_score,
                severity=c.severity,
                schema_version=c.schema_version,
                created_at=c.created_at,
                summary=_extract_summary(c.report_payload),
            )
        )

    total_pages = math.ceil(total / page_size) if total > 0 else 1

    return CaseListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve single investigation case detail",
)
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> CaseDetailResponse:
    """Retrieves full case report. Enforces strict user ownership; returns 404 if not found or unauthorized."""
    stmt = select(InvestigationCase).where(
        InvestigationCase.case_id == case_id,
        InvestigationCase.user_id == current_user.id,
    )
    case_record = (await db.execute(stmt)).scalar_one_or_none()

    if not case_record:
        raise AppException(
            message="Investigation case not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="CASE_NOT_FOUND",
        )

    return CaseDetailResponse.model_validate(case_record)


@router.delete(
    "/{case_id}",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete an investigation case",
)
async def delete_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> MessageResponse:
    """Deletes an investigation case owned by the authenticated user. Returns 404 if not found or unauthorized."""
    stmt = select(InvestigationCase).where(
        InvestigationCase.case_id == case_id,
        InvestigationCase.user_id == current_user.id,
    )
    case_record = (await db.execute(stmt)).scalar_one_or_none()

    if not case_record:
        raise AppException(
            message="Investigation case not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="CASE_NOT_FOUND",
        )

    await db.delete(case_record)
    await db.commit()

    return MessageResponse(message=f"Investigation case {case_id} deleted successfully.")
