"""Repeatable PostgreSQL integration tests for PhishLens AI.

These tests execute against a live PostgreSQL database via asyncpg.
When running in environments without a PostgreSQL instance (such as local dev without Docker/psql),
these tests are skipped. In CI (GitHub Actions), they run against a disposable PostgreSQL container.
"""
from datetime import datetime, timedelta, timezone
import os
import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

TEST_DB_URL = os.getenv("TEST_DATABASE_URL")
if TEST_DB_URL:
    if TEST_DB_URL.startswith("postgres://"):
        TEST_DB_URL = TEST_DB_URL.replace("postgres://", "postgresql+asyncpg://", 1)
    elif TEST_DB_URL.startswith("postgresql://") and not TEST_DB_URL.startswith("postgresql+asyncpg://"):
        TEST_DB_URL = TEST_DB_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

is_postgres_available = bool(TEST_DB_URL and "postgresql+asyncpg" in TEST_DB_URL)
is_ci = os.getenv("CI", "").lower() in ["true", "1"] or os.getenv("GITHUB_ACTIONS", "").lower() in ["true", "1"]

if is_ci and not is_postgres_available:
    pytest.fail(
        "CRITICAL CI FAILURE: PostgreSQL test service is required in CI but TEST_DATABASE_URL is missing or invalid! "
        "PostgreSQL integration tests cannot silently skip in CI.",
        pytrace=False,
    )

pytestmark = [
    pytest.mark.skipif(
        not is_postgres_available,
        reason="PostgreSQL test database not available. Set TEST_DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db to run live PostgreSQL integration tests.",
    ),
    pytest.mark.asyncio,
]


import pytest_asyncio

@pytest_asyncio.fixture(scope="function")
async def pg_engine():
    """Async engine fixture connected to PostgreSQL test database."""
    engine = create_async_engine(TEST_DB_URL, echo=False)
    from app.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def pg_session(pg_engine):
    """Session fixture for PostgreSQL integration tests."""
    session_factory = async_sessionmaker(bind=pg_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.mark.asyncio
async def test_pg_alembic_upgrade_and_downgrade(pg_engine):
    """Verify Alembic migration upgrade, downgrade, and re-upgrade on PostgreSQL."""
    from alembic.config import Config
    from alembic import command
    import asyncio

    from app.models import Base

    # Ensure tables are dropped first so Alembic manages table creation from base
    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    ini_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    alembic_cfg = Config(ini_path)
    script_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic"))
    alembic_cfg.set_main_option("script_location", script_dir)
    alembic_cfg.set_main_option("sqlalchemy.url", TEST_DB_URL)

    # Run upgrade to head
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")

    # Run downgrade to base
    await asyncio.to_thread(command.downgrade, alembic_cfg, "base")

    # Re-upgrade to head
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")


@pytest.mark.asyncio
async def test_pg_registration_and_login_asyncpg(pg_session: AsyncSession):
    """Verify user registration and credential verification on PostgreSQL via asyncpg."""
    from app.models.user import User
    from app.core.security import hash_password, verify_password

    user_id = uuid.uuid4()
    raw_password = "SecurePassword123!"
    hashed = hash_password(raw_password)

    new_user = User(
        id=user_id,
        email="pg_user@phishlens.internal",
        hashed_password=hashed,
        full_name="Postgres Integration User",
        is_active=True,
        is_verified=True,
    )
    pg_session.add(new_user)
    await pg_session.commit()

    # Query back
    stmt = select(User).where(User.email == "pg_user@phishlens.internal")
    retrieved = (await pg_session.execute(stmt)).scalar_one_or_none()
    assert retrieved is not None
    assert retrieved.id == user_id
    assert verify_password(raw_password, retrieved.hashed_password) is True


@pytest.mark.asyncio
async def test_pg_uuid_persistence_and_retrieval(pg_session: AsyncSession):
    """Verify native PostgreSQL UUID column types preserve exact UUID objects."""
    from app.models.user import User
    from app.core.security import hash_password

    test_id = uuid.uuid4()
    user = User(
        id=test_id,
        email="uuid_test@phishlens.internal",
        hashed_password=hash_password("Pass123!"),
    )
    pg_session.add(user)
    await pg_session.commit()

    stmt = select(User).where(User.id == test_id)
    retrieved = (await pg_session.execute(stmt)).scalar_one()
    assert isinstance(retrieved.id, uuid.UUID)
    assert retrieved.id == test_id


@pytest.mark.asyncio
async def test_pg_concurrent_duplicate_registration(pg_engine):
    """Verify that PostgreSQL unique index ix_users_email rejects concurrent duplicate registrations."""
    from app.models.user import User
    from app.core.security import hash_password

    session_factory = async_sessionmaker(bind=pg_engine, class_=AsyncSession, expire_on_commit=False)
    dup_email = "duplicate@phishlens.internal"

    async with session_factory() as session1:
        u1 = User(id=uuid.uuid4(), email=dup_email, hashed_password=hash_password("P1!"))
        session1.add(u1)
        await session1.commit()

    # Attempt to insert same email in second session
    async with session_factory() as session2:
        u2 = User(id=uuid.uuid4(), email=dup_email, hashed_password=hash_password("P2!"))
        session2.add(u2)
        with pytest.raises(IntegrityError):
            await session2.commit()


@pytest.mark.asyncio
async def test_pg_refresh_token_rotation_and_revocation(pg_session: AsyncSession):
    """Verify RefreshSession rotation and single-use revocation on PostgreSQL."""
    from app.models.user import User
    from app.models.session import RefreshSession
    from app.core.security import generate_secure_token, hash_token, hash_password

    user_id = uuid.uuid4()
    user = User(id=user_id, email="refresh_pg@phishlens.internal", hashed_password=hash_password("P!"))
    pg_session.add(user)

    token_a = generate_secure_token(32)
    session_a = RefreshSession(
        id=uuid.uuid4(),
        user_id=user_id,
        token_hash=hash_token(token_a),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    pg_session.add(session_a)
    await pg_session.commit()

    # Rotate with FOR UPDATE row lock on PostgreSQL
    stmt = select(RefreshSession).where(RefreshSession.id == session_a.id).with_for_update()
    locked_session = (await pg_session.execute(stmt)).scalar_one()

    token_b = generate_secure_token(32)
    session_b = RefreshSession(
        id=uuid.uuid4(),
        user_id=user_id,
        token_hash=hash_token(token_b),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    pg_session.add(session_b)

    locked_session.revoked_at = datetime.now(timezone.utc)
    locked_session.replaced_by_session_id = session_b.id
    await pg_session.commit()

    # Query back and verify rotation state
    await pg_session.refresh(session_a)
    assert session_a.replaced_by_session_id == session_b.id
    assert session_a.revoked_at is not None
    assert session_a.is_active is False


@pytest.mark.asyncio
async def test_pg_foreign_key_cascade_and_set_null(pg_session: AsyncSession):
    """Verify foreign key ON DELETE CASCADE and ON DELETE SET NULL on PostgreSQL."""
    from app.models.user import User
    from app.models.session import RefreshSession
    from app.core.security import hash_password, hash_token

    user = User(id=uuid.uuid4(), email="fk_test@phishlens.internal", hashed_password=hash_password("P!"))
    pg_session.add(user)

    s1 = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token("t1"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    s2 = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token("t2"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        replaced_by_session_id=s1.id,
    )
    pg_session.add_all([s1, s2])
    await pg_session.commit()

    # Deleting s1 should set replaced_by_session_id to NULL on s2
    await pg_session.delete(s1)
    await pg_session.commit()
    await pg_session.refresh(s2)
    assert s2.replaced_by_session_id is None

    # Deleting user should cascade delete s2
    await pg_session.delete(user)
    await pg_session.commit()
    stmt = select(RefreshSession).where(RefreshSession.id == s2.id)
    rem = (await pg_session.execute(stmt)).scalar_one_or_none()
    assert rem is None


@pytest.mark.asyncio
async def test_pg_investigation_case_jsonb_and_cascade(pg_session: AsyncSession):
    """Verify InvestigationCase JSONB storage and user CASCADE deletion on PostgreSQL."""
    from app.models.user import User
    from app.models.case import InvestigationCase
    from app.core.security import hash_password

    user_id = uuid.uuid4()
    user = User(id=user_id, email="case_pg@phishlens.internal", hashed_password=hash_password("Pass123!"))
    pg_session.add(user)
    await pg_session.commit()

    case_id_val = "CASE-PG-2026-001"
    sample_jsonb = {
        "verdict": "high-risk",
        "score": 92.5,
        "evidence_by_modality": {"text": [{"indicator": "urgency"}]},
    }
    case = InvestigationCase(
        id=uuid.uuid4(),
        case_id=case_id_val,
        user_id=user_id,
        investigation_type="unified",
        verdict="high-risk",
        threat_score=92.5,
        severity="critical",
        schema_version=1,
        report_payload=sample_jsonb,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    pg_session.add(case)
    await pg_session.commit()

    # Query back and verify JSONB payload deserialization
    stmt = select(InvestigationCase).where(InvestigationCase.case_id == case_id_val)
    retrieved = (await pg_session.execute(stmt)).scalar_one()
    assert retrieved.report_payload["verdict"] == "high-risk"
    assert retrieved.report_payload["evidence_by_modality"]["text"][0]["indicator"] == "urgency"

    # Verify user deletion cascades to investigation cases on PostgreSQL
    await pg_session.delete(user)
    await pg_session.commit()
    case_stmt = select(InvestigationCase).where(InvestigationCase.case_id == case_id_val)
    assert (await pg_session.execute(case_stmt)).scalar_one_or_none() is None
