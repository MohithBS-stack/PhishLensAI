"""Investigation Case Database Model for PhishLens AI."""
from datetime import datetime, timezone
import uuid
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import GUID

if TYPE_CHECKING:
    from app.models.user import User


class InvestigationCase(Base):
    """Persistent investigation case report entity."""

    __tablename__ = "investigation_cases"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        primary_key=True,
        default=uuid.uuid4,
    )
    case_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    investigation_type: Mapped[str] = mapped_column(
        String(32),
        default="unified",
        nullable=False,
    )
    verdict: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    threat_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    schema_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    report_payload: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="cases",
    )

    __table_args__ = (
        Index("ix_investigation_cases_user_created", "user_id", "created_at"),
    )
