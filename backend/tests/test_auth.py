"""Automated tests for Phase 1 Authentication and Session Management."""
from datetime import datetime, timedelta, timezone
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.rate_limit import auth_rate_limiter
from app.core.security import (
    create_access_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.session import RefreshSession
from app.models.user import User

# In-memory SQLite async engine dedicated for tests
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="function")
async def test_db_session():
    """Creates a fresh in-memory database and yields an active session per test."""
    engine = create_async_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def client(test_db_session: AsyncSession):
    """Provides an AsyncClient with database session dependency overridden."""
    auth_rate_limiter.reset_all()

    async def override_get_db():
        yield test_db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        yield async_client

    app.dependency_overrides.clear()
    auth_rate_limiter.reset_all()



@pytest.mark.asyncio
async def test_registration_success(client: AsyncClient, test_db_session: AsyncSession):
    """Test successful user registration returns access token and sets refresh cookie."""
    payload = {
        "email": "analyst@example.com",
        "password": "SecurePassword123!",
        "full_name": "Security Analyst",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60
    assert data["user"]["email"] == "analyst@example.com"
    assert data["user"]["full_name"] == "Security Analyst"
    assert "password" not in data["user"]
    assert "hashed_password" not in data["user"]

    # Verify cookie was set
    assert settings.REFRESH_COOKIE_NAME in response.cookies
    refresh_token = response.cookies[settings.REFRESH_COOKIE_NAME]
    assert len(refresh_token) > 20

    # Verify user exists in database
    stmt = select(User).where(User.email == "analyst@example.com")
    user = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert user is not None
    assert user.is_active is True


@pytest.mark.asyncio
async def test_registration_duplicate_email_rejected(client: AsyncClient):
    """Test duplicate registration with same or case-varied email is rejected with 409 Conflict."""
    payload1 = {
        "email": "investigator@soc.io",
        "password": "InitialPassword123!",
    }
    resp1 = await client.post("/api/v1/auth/register", json=payload1)
    assert resp1.status_code == 201

    # Second attempt with uppercase variation
    payload2 = {
        "email": "INVESTIGATOR@soc.io",
        "password": "SecondPassword123!",
    }
    resp2 = await client.post("/api/v1/auth/register", json=payload2)
    assert resp2.status_code == 409
    err = resp2.json()["error"]
    assert err["code"] == "EMAIL_ALREADY_REGISTERED"


@pytest.mark.asyncio
async def test_password_hashing_argon2id(test_db_session: AsyncSession, client: AsyncClient):
    """Verify password is saved with Argon2id and never matches plaintext."""
    raw_password = "SuperSecretPassword2026!"
    payload = {
        "email": "crypto_test@phishlens.internal",
        "password": raw_password,
    }
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201

    stmt = select(User).where(User.email == "crypto_test@phishlens.internal")
    user = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert user is not None

    # Never matches plaintext
    assert user.hashed_password != raw_password
    # Argon2id signature prefix
    assert user.hashed_password.startswith("$argon2id$")
    # Verifies cleanly with Argon2id verifier
    assert verify_password(raw_password, user.hashed_password) is True
    assert verify_password("WrongPassword!", user.hashed_password) is False


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    """Test successful login with registered credentials."""
    reg_payload = {
        "email": "operator@soc.corp",
        "password": "PasswordOperation123!",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {
        "email": "OPERATOR@soc.corp",  # tests case normalization
        "password": "PasswordOperation123!",
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == "operator@soc.corp"
    assert settings.REFRESH_COOKIE_NAME in response.cookies


@pytest.mark.asyncio
async def test_login_invalid_credentials_rejected(client: AsyncClient):
    """Test login with wrong password or unknown email returns generic 401 error."""
    reg_payload = {
        "email": "valid_user@example.com",
        "password": "CorrectPassword123!",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    # 1. Valid email, wrong password
    bad_pw_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "valid_user@example.com", "password": "WrongPassword999!"},
    )
    assert bad_pw_resp.status_code == 401
    assert bad_pw_resp.json()["error"]["message"] == "Invalid email or password."
    assert bad_pw_resp.json()["error"]["code"] == "INVALID_CREDENTIALS"

    # 2. Unknown email
    unknown_user_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent_analyst@example.com", "password": "AnyPassword123!"},
    )
    assert unknown_user_resp.status_code == 401
    assert unknown_user_resp.json()["error"]["message"] == "Invalid email or password."
    assert unknown_user_resp.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_access_token_expiry_rejection(client: AsyncClient, test_db_session: AsyncSession):
    """Test expired access token is rejected on protected /auth/me route."""
    reg_payload = {
        "email": "expiry_user@example.com",
        "password": "PasswordExpiry123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    user_id = reg_resp.json()["user"]["id"]

    # Manually mint an expired access token (expired 5 minutes ago)
    expired_token = create_access_token(
        user_id=user_id,
        expires_delta=timedelta(minutes=-5),
    )

    headers = {"Authorization": f"Bearer {expired_token}"}
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 401
    assert me_resp.json()["error"]["code"] == "TOKEN_EXPIRED"


@pytest.mark.asyncio
async def test_refresh_token_rotation_success(client: AsyncClient, test_db_session: AsyncSession):
    """Test refresh endpoint rotates token, invalidates previous session, and sets new cookie."""
    reg_payload = {
        "email": "rotation_analyst@example.com",
        "password": "RotationPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    old_refresh_token = reg_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Perform refresh using the cookie
    refresh_resp = await client.post("/api/v1/auth/refresh")
    assert refresh_resp.status_code == 200

    new_data = refresh_resp.json()
    assert "access_token" in new_data
    new_refresh_token = refresh_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Ensure token was rotated
    assert new_refresh_token != old_refresh_token

    # Verify old session record is marked revoked and replaced
    old_hash = hash_token(old_refresh_token)
    stmt = select(RefreshSession).where(RefreshSession.token_hash == old_hash)
    old_session = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert old_session is not None
    assert old_session.revoked_at is not None
    assert old_session.replaced_by_session_id is not None


@pytest.mark.asyncio
async def test_refresh_token_concurrency_grace_period(client: AsyncClient, test_db_session: AsyncSession):
    """Test that duplicate/concurrent refresh requests within the rotation grace period succeed safely."""
    reg_payload = {
        "email": "concurrency_user@example.com",
        "password": "ConcurrencyPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    first_token = reg_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # First rotation
    rot_resp = await client.post("/api/v1/auth/refresh")
    assert rot_resp.status_code == 200
    second_token = rot_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Immediate second request with old first_token (e.g. duplicate tab fetch within 15s)
    client.cookies.set(settings.REFRESH_COOKIE_NAME, first_token)
    grace_resp = await client.post("/api/v1/auth/refresh")
    assert grace_resp.status_code == 200
    assert "access_token" in grace_resp.json()

    # Verify that the active second session was NOT revoked
    valid_hash = hash_token(second_token)
    stmt = select(RefreshSession).where(RefreshSession.token_hash == valid_hash)
    second_session = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert second_session is not None
    assert second_session.revoked_at is None


@pytest.mark.asyncio
async def test_refresh_token_reuse_attack_detection(client: AsyncClient, test_db_session: AsyncSession):
    """Test reuse of an already-rotated refresh token outside grace window revokes all user sessions."""
    reg_payload = {
        "email": "theft_target@example.com",
        "password": "TargetPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    stolen_first_token = reg_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Legitimate user rotates token once
    rot1_resp = await client.post("/api/v1/auth/refresh")
    assert rot1_resp.status_code == 200
    valid_second_token = rot1_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Simulate elapsed time beyond the 15-second grace period on the replaced session
    first_hash = hash_token(stolen_first_token)
    stmt = select(RefreshSession).where(RefreshSession.token_hash == first_hash)
    first_session = (await test_db_session.execute(stmt)).scalar_one_or_none()
    first_session.revoked_at = datetime.now(timezone.utc) - timedelta(seconds=30)
    await test_db_session.commit()

    # Attacker attempts to use stolen_first_token outside grace window
    client.cookies.set(settings.REFRESH_COOKIE_NAME, stolen_first_token)
    attacker_resp = await client.post("/api/v1/auth/refresh")
    assert attacker_resp.status_code == 401
    assert attacker_resp.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"

    # Verify that legitimate user's second session was also revoked for safety
    valid_hash = hash_token(valid_second_token)
    stmt = select(RefreshSession).where(RefreshSession.token_hash == valid_hash)
    second_session = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert second_session is not None
    assert second_session.revoked_at is not None

    # Legitimate user can no longer refresh with second token either
    client.cookies.set(settings.REFRESH_COOKIE_NAME, valid_second_token)
    second_attempt = await client.post("/api/v1/auth/refresh")
    assert second_attempt.status_code == 401



@pytest.mark.asyncio
async def test_refresh_session_expired_rejection(client: AsyncClient, test_db_session: AsyncSession):
    """Test expired refresh session is rejected."""
    reg_payload = {
        "email": "exp_refresh@example.com",
        "password": "ExpPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    token = reg_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Manually expire session in DB
    token_digest = hash_token(token)
    stmt = select(RefreshSession).where(RefreshSession.token_hash == token_digest)
    session = (await test_db_session.execute(stmt)).scalar_one_or_none()
    session.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await test_db_session.commit()

    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "REFRESH_SESSION_EXPIRED"


@pytest.mark.asyncio
async def test_logout_invalidates_session(client: AsyncClient, test_db_session: AsyncSession):
    """Test logout revokes the server-side refresh session and clears cookie."""
    reg_payload = {
        "email": "logout_user@example.com",
        "password": "LogoutPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    token = reg_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Call logout
    logout_resp = await client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 200
    assert logout_resp.json()["message"] == "Successfully logged out."

    # Verify session is revoked in database
    token_digest = hash_token(token)
    stmt = select(RefreshSession).where(RefreshSession.token_hash == token_digest)
    session = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert session is not None
    assert session.revoked_at is not None

    # Subsequent refresh attempt fails
    client.cookies.set(settings.REFRESH_COOKIE_NAME, token)
    fail_refresh = await client.post("/api/v1/auth/refresh")
    assert fail_refresh.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_endpoint(client: AsyncClient):
    """Test GET /api/v1/auth/me behavior under authorized and unauthorized conditions."""
    # 1. Unauthorized (no token)
    unauth_resp = await client.get("/api/v1/auth/me")
    assert unauth_resp.status_code == 401
    assert unauth_resp.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"

    # 2. Register and test with valid Bearer token
    reg_payload = {
        "email": "profile_user@example.com",
        "password": "ProfilePassword123!",
        "full_name": "Chief Security Officer",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    access_token = reg_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {access_token}"}
    me_resp = await client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    profile = me_resp.json()
    assert profile["email"] == "profile_user@example.com"
    assert profile["full_name"] == "Chief Security Officer"
    assert profile["is_active"] is True


@pytest.mark.asyncio
async def test_cookie_security_attributes(client: AsyncClient):
    """Test that refresh cookie contains HttpOnly and Path security attributes."""
    reg_payload = {
        "email": "cookie_test@example.com",
        "password": "CookiePassword123!",
    }
    resp = await client.post("/api/v1/auth/register", json=reg_payload)
    assert resp.status_code == 201

    # Check Set-Cookie header text
    set_cookie_header = resp.headers.get("set-cookie", "")
    assert settings.REFRESH_COOKIE_NAME in set_cookie_header
    assert "httponly" in set_cookie_header.lower()
    assert "path=/api/v1/auth" in set_cookie_header.lower()


def test_production_configuration_safety():
    """Verify that Settings validation fails fast and safely if production secrets are missing or default."""
    from pydantic import ValidationError
    from app.core.config import Settings

    # 1. Production with default dev JWT key should fail
    with pytest.raises(ValidationError) as exc1:
        Settings(
            ENVIRONMENT="production",
            DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/db",
            JWT_SECRET_KEY="dev-insecure-jwt-secret-key-change-in-production",
        )
    assert "JWT_SECRET_KEY must be securely configured" in str(exc1.value)

    # 2. Production with missing/sqlite DATABASE_URL should fail
    with pytest.raises(ValidationError) as exc2:
        Settings(
            ENVIRONMENT="production",
            DATABASE_URL="",
            JWT_SECRET_KEY="a" * 32,
        )
    assert "DATABASE_URL must be configured with a managed PostgreSQL" in str(exc2.value)

    # 3. Production with valid Postgres and strong 32+ char key should succeed
    prod_settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+asyncpg://prod_user:strongpass@db.internal:5432/phishlens_prod",
        JWT_SECRET_KEY="a" * 32,
    )
    assert prod_settings.is_production is True
    assert prod_settings.resolved_cookie_secure is True
    assert prod_settings.resolved_cookie_samesite == "none"


def test_env_file_and_env_local_precedence_and_overrides(tmp_path, monkeypatch):
    """Verify that Settings loads .env and .env.local with correct precedence,
    where .env.local overrides .env, and real process environment variables retain highest priority."""
    from app.core.config import Settings

    env_file = tmp_path / ".env"
    env_local_file = tmp_path / ".env.local"

    # 1. Base .env defines values
    env_file.write_text("PROJECT_NAME=BaseProject\nAPI_V1_PREFIX=/api/v1\nPORT=8000\n", encoding="utf-8")
    # 2. .env.local overrides PROJECT_NAME and PORT
    env_local_file.write_text("PROJECT_NAME=LocalOverrideProject\nPORT=9000\n", encoding="utf-8")

    # Clear any conflicting process environment variables
    monkeypatch.delenv("PROJECT_NAME", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("API_V1_PREFIX", raising=False)

    # Initialize Settings with the custom tuple
    s = Settings(_env_file=(str(env_file), str(env_local_file)))
    assert s.PROJECT_NAME == "LocalOverrideProject"
    assert s.PORT == 9000
    assert s.API_V1_PREFIX == "/api/v1"

    # 3. Real process environment variables retain higher priority over both .env and .env.local
    monkeypatch.setenv("PROJECT_NAME", "ProcessEnvPriorityProject")
    monkeypatch.setenv("PORT", "9999")
    s_proc = Settings(_env_file=(str(env_file), str(env_local_file)))
    assert s_proc.PROJECT_NAME == "ProcessEnvPriorityProject"
    assert s_proc.PORT == 9999
    assert s_proc.API_V1_PREFIX == "/api/v1"

    # 4. Graceful fallback when .env.local is absent
    env_local_file.unlink()
    monkeypatch.delenv("PROJECT_NAME", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    s_no_local = Settings(_env_file=(str(env_file), str(env_local_file)))
    assert s_no_local.PROJECT_NAME == "BaseProject"
    assert s_no_local.PORT == 8000


def test_guid_type_postgresql_and_sqlite_compatibility():
    """Verify platform-independent GUID type binds UUID objects for PostgreSQL and strings for SQLite."""
    import uuid
    from sqlalchemy.dialects.postgresql import dialect as pg_dialect
    from sqlalchemy.dialects.sqlite import dialect as sqlite_dialect
    from app.models.user import GUID

    guid_type = GUID()
    test_uuid = uuid.uuid4()

    # PostgreSQL bind expects a UUID object
    pg_bound = guid_type.process_bind_param(test_uuid, pg_dialect())
    assert isinstance(pg_bound, uuid.UUID)
    assert pg_bound == test_uuid

    # PostgreSQL bind converts string to UUID object
    pg_str_bound = guid_type.process_bind_param(str(test_uuid), pg_dialect())
    assert isinstance(pg_str_bound, uuid.UUID)

    # SQLite bind expects a 36-char string
    sqlite_bound = guid_type.process_bind_param(test_uuid, sqlite_dialect())
    assert isinstance(sqlite_bound, str)
    assert len(sqlite_bound) == 36

    # Result value always returns uuid.UUID
    result_from_str = guid_type.process_result_value(str(test_uuid), sqlite_dialect())
    assert isinstance(result_from_str, uuid.UUID)
    assert result_from_str == test_uuid


@pytest.mark.asyncio
async def test_refresh_grace_period_rejected_if_successor_revoked(client: AsyncClient, test_db_session: AsyncSession):
    """Verify that an old token within the grace period CANNOT be used if its successor was revoked/logged out."""
    reg_payload = {
        "email": "revoked_successor@example.com",
        "password": "SuccessorPassword123!",
    }
    reg_resp = await client.post("/api/v1/auth/register", json=reg_payload)
    token_a = reg_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # Rotate Token A -> Token B
    rot_resp = await client.post("/api/v1/auth/refresh")
    assert rot_resp.status_code == 200
    token_b = rot_resp.cookies[settings.REFRESH_COOKIE_NAME]

    # User explicitly logs out with Token B (which revokes Token B)
    logout_resp = await client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 200

    # Attacker or lingering tab presents Token A (within 15s grace window, but successor B is revoked)
    client.cookies.set(settings.REFRESH_COOKIE_NAME, token_a)
    replay_resp = await client.post("/api/v1/auth/refresh")
    assert replay_resp.status_code == 401
    assert replay_resp.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"


@pytest.mark.asyncio
async def test_refresh_token_missing_cookie_rejected_even_with_header(client: AsyncClient):
    """Verify that X-Refresh-Token header is ignored and missing cookie returns 401."""
    # Attempt to send refresh token via custom header without cookie
    headers = {"X-Refresh-Token": "some-arbitrary-token-value"}
    resp = await client.post("/api/v1/auth/refresh", headers=headers)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "REFRESH_TOKEN_MISSING"


@pytest.mark.asyncio
async def test_rate_limit_registration_exceeded(client: AsyncClient):
    """Verify that registration endpoint enforces rate limits and returns 429 with Retry-After."""
    # Make 5 successful registrations (limit is 5 per min per IP)
    for i in range(5):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": f"ratelimit_{i}@example.com", "password": "Password123!"},
        )
        assert resp.status_code == 201

    # 6th attempt should be blocked with 429
    blocked_resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "ratelimit_blocked@example.com", "password": "Password123!"},
    )
    assert blocked_resp.status_code == 429
    assert blocked_resp.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in blocked_resp.headers
    assert int(blocked_resp.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_rate_limit_login_attempts_and_recovery(client: AsyncClient):
    """Verify login rate limits by IP/account on failed attempts and resets on success."""
    # Register an account
    email = "target_login_limit@example.com"
    pwd = "ValidPassword123!"
    await client.post("/api/v1/auth/register", json={"email": email, "password": pwd})

    # Fire 5 invalid password attempts (account limit is 5 per 300s)
    for _ in range(5):
        bad_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword999!"},
        )
        assert bad_resp.status_code == 401

    # 6th attempt should be blocked by rate limiter with 429
    rate_limited_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd},
    )
    assert rate_limited_resp.status_code == 429
    assert rate_limited_resp.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in rate_limited_resp.headers


@pytest.mark.asyncio
async def test_concurrent_refresh_across_separate_sessions():
    """Verify that concurrent refresh operations across separate DB sessions serialize via row locking."""
    import uuid
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.db.base import Base
    from app.models.user import User
    from app.models.session import RefreshSession
    from app.core.security import hash_password, generate_secure_token, hash_token

    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

    # Setup user and initial refresh session
    user_id = uuid.uuid4()
    raw_token = generate_secure_token(32)
    token_digest = hash_token(raw_token)

    async with session_factory() as s_init:
        user = User(
            id=user_id,
            email="concurrent_sessions@test.com",
            hashed_password=hash_password("Password123!"),
            is_active=True,
        )
        s_init.add(user)
        ref_sess = RefreshSession(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=token_digest,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        s_init.add(ref_sess)
        await s_init.commit()

    # Open two separate async sessions to simulate concurrent workers/requests
    async with session_factory() as db_session_1:
        async with session_factory() as db_session_2:
            # Worker 1 locks row with with_for_update
            stmt1 = select(RefreshSession).where(RefreshSession.token_hash == token_digest).with_for_update()
            s1 = (await db_session_1.execute(stmt1)).scalar_one()
            assert s1.replaced_by_session_id is None

            # Worker 1 performs rotation
            new_id = uuid.uuid4()
            s1.revoked_at = datetime.now(timezone.utc)
            s1.replaced_by_session_id = new_id
            await db_session_1.commit()

            # Worker 2 queries same row with with_for_update
            stmt2 = select(RefreshSession).where(RefreshSession.token_hash == token_digest).with_for_update()
            s2 = (await db_session_2.execute(stmt2)).scalar_one()

            # Worker 2 observes that the row has already been replaced
            assert s2.replaced_by_session_id == new_id
            assert s2.revoked_at is not None

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_rate_limiter_memory_boundedness():
    """Verify that InMemorySlidingWindowLimiter bounds memory and evicts LRU buckets when capacity is reached."""
    from app.core.rate_limit import InMemorySlidingWindowLimiter

    small_limiter = InMemorySlidingWindowLimiter(max_buckets=3)
    # Fill 3 buckets
    small_limiter.check_limit("key_1", max_requests=5, window_seconds=60)
    small_limiter.check_limit("key_2", max_requests=5, window_seconds=60)
    small_limiter.check_limit("key_3", max_requests=5, window_seconds=60)
    assert len(small_limiter._buckets) == 3
    assert "key_1" in small_limiter._buckets

    # Add 4th key; should evict LRU (key_1)
    small_limiter.check_limit("key_4", max_requests=5, window_seconds=60)
    assert len(small_limiter._buckets) == 3
    assert "key_1" not in small_limiter._buckets
    assert "key_4" in small_limiter._buckets


@pytest.mark.asyncio
async def test_rate_limit_email_normalization_cannot_be_bypassed(client: AsyncClient):
    """Verify that changing email capitalization or whitespace does not bypass rate limits."""
    # Register an account
    email = "casing_test@example.com"
    pwd = "ValidPassword123!"
    await client.post("/api/v1/auth/register", json={"email": email, "password": pwd})

    # Send 5 attempts with various whitespace and casing
    variations = [
        "casing_test@example.com",
        "  casing_test@example.com",
        "Casing_Test@Example.COM",
        "  CASING_TEST@example.com  ",
        "CASING_test@EXAMPLE.com",
    ]
    for var_email in variations:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": var_email, "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    # 6th attempt with yet another casing variation should be rate limited (429)
    blocked_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "  CASING_TEST@EXAMPLE.COM  ", "password": pwd},
    )
    assert blocked_resp.status_code == 429
    assert blocked_resp.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_client_ip_does_not_trust_unconfigured_forwarded_for(client: AsyncClient):
    """Verify that arbitrary X-Forwarded-For headers are ignored by default and cannot bypass IP limits."""
    # Register account
    email = "spoof_ip_test@example.com"
    pwd = "Password123!"
    await client.post("/api/v1/auth/register", json={"email": email, "password": pwd})

    # Fail login 5 times sending random spoofed X-Forwarded-For headers
    for i in range(5):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "BadPassword!"},
            headers={"X-Forwarded-For": f"198.51.100.{i}"},
        )
        assert resp.status_code == 401

    # Attempt with another spoofed header should be blocked because default TRUST_FORWARDED_FOR is False
    blocked = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": pwd},
        headers={"X-Forwarded-For": "203.0.113.99"},
    )
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"


@pytest.mark.asyncio
async def test_refresh_session_flush_ordering_and_rollback_atomicity(test_db_session: AsyncSession):
    """Verify that rotation persists replacement session before predecessor references it,
    and rollback preserves atomicity without leaving a partially rotated session."""
    import uuid
    user = User(
        id=uuid.uuid4(),
        email="atomicity_test@phishlens.internal",
        hashed_password=hash_password("Password123!"),
    )
    test_db_session.add(user)
    await test_db_session.commit()

    # Create initial session
    s1 = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token("token_1"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    test_db_session.add(s1)
    await test_db_session.commit()

    # 1. Successful rotation with explicit flush ordering
    s2 = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token("token_2"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    test_db_session.add(s2)
    await test_db_session.flush()

    s1.revoked_at = datetime.now(timezone.utc)
    s1.replaced_by_session_id = s2.id
    await test_db_session.commit()

    await test_db_session.refresh(s1)
    await test_db_session.refresh(s2)
    assert s1.replaced_by_session_id == s2.id
    assert s1.is_active is False
    assert s2.is_active is True

    # 2. Simulated failure after flush - rollback must not leave partial rotation
    s3 = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token("token_3"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    test_db_session.add(s3)
    await test_db_session.flush()

    s2.revoked_at = datetime.now(timezone.utc)
    s2.replaced_by_session_id = s3.id

    s2_id = s2.id
    s3_id = s3.id

    # Simulate transaction rollback (e.g. failure before commit)
    await test_db_session.rollback()

    # Query back states
    res_s2 = (await test_db_session.execute(select(RefreshSession).where(RefreshSession.id == s2_id))).scalar_one()
    res_s3 = (await test_db_session.execute(select(RefreshSession).where(RefreshSession.id == s3_id))).scalar_one_or_none()

    # s3 should not exist in DB
    assert res_s3 is None
    # s2 should remain active and unrevoked, not replaced by s3
    assert res_s2.replaced_by_session_id is None
    assert res_s2.revoked_at is None
    assert res_s2.is_active is True
