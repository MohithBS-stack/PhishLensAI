"""Create investigation_cases table

Revision ID: 0002_cases
Revises: 0001_initial
Create Date: 2026-10-17 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_cases"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    uuid_type = postgresql.UUID(as_uuid=True) if is_postgres else sa.CHAR(36)
    json_type = postgresql.JSONB if is_postgres else sa.JSON

    op.create_table(
        "investigation_cases",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("case_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", uuid_type, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("investigation_type", sa.String(length=32), server_default="unified", nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("threat_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("schema_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("report_payload", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_investigation_cases_case_id", "investigation_cases", ["case_id"], unique=True)
    op.create_index("ix_investigation_cases_user_id", "investigation_cases", ["user_id"])
    op.create_index("ix_investigation_cases_user_created", "investigation_cases", ["user_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_investigation_cases_user_created", table_name="investigation_cases")
    op.drop_index("ix_investigation_cases_user_id", table_name="investigation_cases")
    op.drop_index("ix_investigation_cases_case_id", table_name="investigation_cases")
    op.drop_table("investigation_cases")
