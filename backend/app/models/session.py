"""Refresh Session Database Model."""
from datetime import datetime, timezone
import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.user import GUID

if TYPE_CHECKING:
    from app.models.user import User


class RefreshSession(Base):
    """Server-side refresh session for rotating refresh tokens."""

    __tablename__ = "refresh_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    replaced_by_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        GUID,
        ForeignKey("refresh_sessions.id", ondelete="SET NULL"),
        nullable=True,
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
        back_populates="refresh_sessions",
    )

    @property
    def is_expired(self) -> bool:
        """Returns True if session has expired."""
        now = datetime.now(timezone.utc)
        # Ensure comparison is timezone-aware
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp

    @property
    def is_revoked(self) -> bool:
        """Returns True if explicitly revoked or replaced."""
        return self.revoked_at is not None

    @property
    def is_active(self) -> bool:
        """Returns True if the session is currently valid for authentication."""
        return not self.is_expired and not self.is_revoked

    def __repr__(self) -> str:
        return f"<RefreshSession id={self.id} user_id={self.user_id} is_active={self.is_active}>"
