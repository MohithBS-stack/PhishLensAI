"""Automated tests for Phase 3 Persistent Investigation Cases."""
from datetime import datetime, timezone
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.case import InvestigationCase
from app.models.user import User

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
    async def override_get_db():
        yield test_db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


async def create_test_user(db: AsyncSession, email: str = "analyst@test.com") -> User:
    """Helper to create an active verified user."""
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=hash_password("SuperSecret123!"),
        full_name="Forensic Analyst",
        is_active=True,
        is_verified=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def get_auth_headers(user_id: uuid.UUID) -> dict:
    """Generates a Bearer Authorization header for testing."""
    token = create_access_token(user_id)
    return {"Authorization": f"Bearer {token}"}


SAMPLE_REPORT_PAYLOAD = {
    "case_id": "CASE-20261017-TEST01",
    "verdict": "high-risk",
    "score": 88.5,
    "threat_level": "critical",
    "evidence_by_modality": {
        "text": [
            {
                "evidence_id": "EV-01",
                "source_modality": "text",
                "indicator_type": "urgency_deadline",
                "description": "Urgent deadline threat detected.",
                "severity": "high",
                "evidence_source": "sms_classifier",
                "confidence": 0.96,
                "observed_versus_inferred": "inferred",
                "limitations_and_missing_checks": [],
            }
        ]
    },
    "all_evidence": [],
    "manipulation_tactics": [],
    "supporting_excerpts": ["Urgent: verify your account now"],
    "model_signals": {},
    "missing_checks": [],
    "uncertainty": {
        "is_uncertain": False,
        "uncertainty_level": "low",
        "reasons": [],
        "calibration_disclosure": "Uncalibrated",
        "conflicting_signals": [],
    },
    "safe_next_steps": ["Do not click links"],
    "explanation": {
        "summary": "High risk credential phishing attempt.",
        "executive_brief": "Observed urgent credential request.",
        "key_concerns": ["Fake urgency"],
        "manipulation_tactics_explained": [],
        "remediation_advice": ["Block sender"],
        "is_llm_generated": False,
        "model_name": "deterministic-fallback",
    },
}


@pytest.mark.asyncio
async def test_save_case_authenticated(client: AsyncClient, test_db_session: AsyncSession):
    """Authenticated user can successfully save an investigation case."""
    user = await create_test_user(test_db_session)
    headers = get_auth_headers(user.id)

    payload = {
        "case_id": "CASE-20261017-TEST01",
        "investigation_type": "unified",
        "report_payload": SAMPLE_REPORT_PAYLOAD,
    }

    res = await client.post("/api/v1/cases", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["case_id"] == "CASE-20261017-TEST01"
    assert data["verdict"] == "high-risk"
    assert data["threat_score"] == 88.5
    assert data["severity"] == "critical"
    assert data["schema_version"] == 1
    assert data["report_payload"]["verdict"] == "high-risk"


@pytest.mark.asyncio
async def test_save_case_unauthenticated_rejected(client: AsyncClient):
    """Anonymous/unauthenticated users are rejected with 401."""
    payload = {
        "case_id": "CASE-20261017-ANON",
        "investigation_type": "unified",
        "report_payload": SAMPLE_REPORT_PAYLOAD,
    }

    res = await client.post("/api/v1/cases", json=payload)
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_save_case_idempotent_update(client: AsyncClient, test_db_session: AsyncSession):
    """Saving the same case_id for the same user updates the existing record."""
    user = await create_test_user(test_db_session)
    headers = get_auth_headers(user.id)

    payload = {
        "case_id": "CASE-IDEMPOTENT-01",
        "investigation_type": "unified",
        "report_payload": {**SAMPLE_REPORT_PAYLOAD, "score": 50.0, "verdict": "suspicious"},
    }

    res1 = await client.post("/api/v1/cases", json=payload, headers=headers)
    assert res1.status_code == 201
    assert res1.json()["threat_score"] == 50.0

    # Save again with updated score
    updated_payload = {
        "case_id": "CASE-IDEMPOTENT-01",
        "investigation_type": "unified",
        "report_payload": {**SAMPLE_REPORT_PAYLOAD, "score": 75.0, "verdict": "high-risk"},
    }
    res2 = await client.post("/api/v1/cases", json=updated_payload, headers=headers)
    assert res2.status_code == 201
    assert res2.json()["threat_score"] == 75.0

    # Ensure only 1 record exists in DB
    stmt = select(InvestigationCase).where(InvestigationCase.case_id == "CASE-IDEMPOTENT-01")
    records = (await test_db_session.execute(stmt)).scalars().all()
    assert len(records) == 1


@pytest.mark.asyncio
async def test_save_case_collision_across_users(client: AsyncClient, test_db_session: AsyncSession):
    """If user B submits a case_id already used by user A, B gets a unique suffixed case_id."""
    user_a = await create_test_user(test_db_session, "usera@test.com")
    user_b = await create_test_user(test_db_session, "userb@test.com")

    payload = {
        "case_id": "CASE-COLLISION-01",
        "investigation_type": "unified",
        "report_payload": SAMPLE_REPORT_PAYLOAD,
    }

    # User A saves
    res_a = await client.post("/api/v1/cases", json=payload, headers=get_auth_headers(user_a.id))
    assert res_a.status_code == 201
    assert res_a.json()["case_id"] == "CASE-COLLISION-01"

    # User B saves with same case_id
    res_b = await client.post("/api/v1/cases", json=payload, headers=get_auth_headers(user_b.id))
    assert res_b.status_code == 201
    assert res_b.json()["case_id"].startswith("CASE-COLLISION-01-")
    assert res_b.json()["case_id"] != res_a.json()["case_id"]


@pytest.mark.asyncio
async def test_save_case_payload_size_limit(client: AsyncClient, test_db_session: AsyncSession):
    """Payloads exceeding maximum size limit are rejected with 422."""
    user = await create_test_user(test_db_session)
    headers = get_auth_headers(user.id)

    huge_payload = {
        "case_id": "CASE-TOO-LARGE",
        "investigation_type": "unified",
        "report_payload": {
            "blob": "A" * (1048576 + 100),  # > 1 MB
        },
    }

    res = await client.post("/api/v1/cases", json=huge_payload, headers=headers)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_list_cases_user_isolation_and_pagination(client: AsyncClient, test_db_session: AsyncSession):
    """User only sees their own cases with accurate pagination and ordering."""
    user_a = await create_test_user(test_db_session, "usera_list@test.com")
    user_b = await create_test_user(test_db_session, "userb_list@test.com")

    # Seed 5 cases for User A
    for i in range(5):
        db_case = InvestigationCase(
            id=uuid.uuid4(),
            case_id=f"CASE-A-{i}",
            user_id=user_a.id,
            investigation_type="unified",
            verdict="suspicious",
            threat_score=40.0 + i,
            severity="medium",
            schema_version=1,
            report_payload={**SAMPLE_REPORT_PAYLOAD, "score": 40.0 + i},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        test_db_session.add(db_case)

    # Seed 2 cases for User B
    for i in range(2):
        db_case = InvestigationCase(
            id=uuid.uuid4(),
            case_id=f"CASE-B-{i}",
            user_id=user_b.id,
            investigation_type="unified",
            verdict="benign",
            threat_score=10.0,
            severity="low",
            schema_version=1,
            report_payload={**SAMPLE_REPORT_PAYLOAD, "score": 10.0},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        test_db_session.add(db_case)

    await test_db_session.commit()

    # Query User A (page_size = 3)
    res_a = await client.get("/api/v1/cases?page=1&page_size=3", headers=get_auth_headers(user_a.id))
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["total"] == 5
    assert len(data_a["items"]) == 3
    assert data_a["page"] == 1
    assert data_a["total_pages"] == 2
    # Verify no cases belonging to User B are visible to User A
    for item in data_a["items"]:
        assert item["case_id"].startswith("CASE-A-")

    # Query User B
    res_b = await client.get("/api/v1/cases", headers=get_auth_headers(user_b.id))
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["total"] == 2
    assert len(data_b["items"]) == 2
    for item in data_b["items"]:
        assert item["case_id"].startswith("CASE-B-")


@pytest.mark.asyncio
async def test_get_case_detail_and_ownership_enforcement(client: AsyncClient, test_db_session: AsyncSession):
    """User can retrieve their own case detail, but other users receive 404."""
    user_a = await create_test_user(test_db_session, "user_get_a@test.com")
    user_b = await create_test_user(test_db_session, "user_get_b@test.com")

    case_a = InvestigationCase(
        id=uuid.uuid4(),
        case_id="CASE-PRIVATE-01",
        user_id=user_a.id,
        investigation_type="unified",
        verdict="high-risk",
        threat_score=92.0,
        severity="critical",
        schema_version=1,
        report_payload=SAMPLE_REPORT_PAYLOAD,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    test_db_session.add(case_a)
    await test_db_session.commit()

    # User A accesses own case -> 200
    res_a = await client.get("/api/v1/cases/CASE-PRIVATE-01", headers=get_auth_headers(user_a.id))
    assert res_a.status_code == 200
    assert res_a.json()["case_id"] == "CASE-PRIVATE-01"
    assert res_a.json()["report_payload"]["verdict"] == "high-risk"

    # User B accesses User A's case -> 404 (not 403 to prevent ownership enumeration)
    res_b = await client.get("/api/v1/cases/CASE-PRIVATE-01", headers=get_auth_headers(user_b.id))
    assert res_b.status_code == 404

    # Anonymous user access -> 401
    res_anon = await client.get("/api/v1/cases/CASE-PRIVATE-01")
    assert res_anon.status_code == 401


@pytest.mark.asyncio
async def test_delete_case_ownership_enforcement(client: AsyncClient, test_db_session: AsyncSession):
    """User can delete their own case, but cannot delete another user's case."""
    user_a = await create_test_user(test_db_session, "user_del_a@test.com")
    user_b = await create_test_user(test_db_session, "user_del_b@test.com")

    case_a = InvestigationCase(
        id=uuid.uuid4(),
        case_id="CASE-TO-DELETE",
        user_id=user_a.id,
        investigation_type="unified",
        verdict="benign",
        threat_score=5.0,
        severity="low",
        schema_version=1,
        report_payload=SAMPLE_REPORT_PAYLOAD,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    test_db_session.add(case_a)
    await test_db_session.commit()

    # User B attempts to delete User A's case -> 404
    del_b = await client.delete("/api/v1/cases/CASE-TO-DELETE", headers=get_auth_headers(user_b.id))
    assert del_b.status_code == 404

    # Confirm case still exists
    stmt = select(InvestigationCase).where(InvestigationCase.case_id == "CASE-TO-DELETE")
    assert (await test_db_session.execute(stmt)).scalar_one_or_none() is not None

    # User A deletes their own case -> 200
    del_a = await client.delete("/api/v1/cases/CASE-TO-DELETE", headers=get_auth_headers(user_a.id))
    assert del_a.status_code == 200
    assert "deleted successfully" in del_a.json()["message"]

    # Confirm case is deleted from DB
    assert (await test_db_session.execute(stmt)).scalar_one_or_none() is None

    # Subsequent GET returns 404
    get_again = await client.get("/api/v1/cases/CASE-TO-DELETE", headers=get_auth_headers(user_a.id))
    assert get_again.status_code == 404


@pytest.mark.asyncio
async def test_cascade_delete_user_deletes_cases(test_db_session: AsyncSession):
    """Deleting a user account automatically cascades and deletes all their stored cases."""
    user = await create_test_user(test_db_session, "cascade_user@test.com")
    case = InvestigationCase(
        id=uuid.uuid4(),
        case_id="CASE-CASCADE-01",
        user_id=user.id,
        investigation_type="unified",
        verdict="benign",
        threat_score=10.0,
        severity="low",
        schema_version=1,
        report_payload=SAMPLE_REPORT_PAYLOAD,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    test_db_session.add(case)
    await test_db_session.commit()

    # Delete user
    await test_db_session.delete(user)
    await test_db_session.commit()

    # Verify case is gone
    stmt = select(InvestigationCase).where(InvestigationCase.case_id == "CASE-CASCADE-01")
    assert (await test_db_session.execute(stmt)).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_anonymous_scan_endpoints_remain_operational(client: AsyncClient):
    """Anonymous scan endpoints continue to operate without any authentication headers."""
    payload = {"text": "Your account security code is 654321."}
    res = await client.post("/api/v1/scan/unified", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "case_id" in data
    assert "verdict" in data
    assert "score" in data


@pytest.mark.asyncio
async def test_save_case_unsupported_schema_version_rejected(client: AsyncClient, test_db_session: AsyncSession):
    """Unsupported schema_version is rejected with 422."""
    user = await create_test_user(test_db_session)
    headers = get_auth_headers(user.id)

    payload = {
        "case_id": "CASE-BAD-VER",
        "investigation_type": "unified",
        "schema_version": 99,
        "report_payload": SAMPLE_REPORT_PAYLOAD,
    }

    res = await client.post("/api/v1/cases", json=payload, headers=headers)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_save_case_nested_binary_stripping(client: AsyncClient, test_db_session: AsyncSession):
    """Nested binary data URIs are recursively stripped before database persistence."""
    user = await create_test_user(test_db_session)
    headers = get_auth_headers(user.id)

    payload_with_binaries = {
        **SAMPLE_REPORT_PAYLOAD,
        "nested_evidence": {
            "screenshot_b64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
            "deep": [
                {"audio_raw": "data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="}
            ],
        },
    }

    payload = {
        "case_id": "CASE-STRIP-BIN",
        "investigation_type": "unified",
        "schema_version": 1,
        "report_payload": payload_with_binaries,
    }

    res = await client.post("/api/v1/cases", json=payload, headers=headers)
    assert res.status_code == 201
    stored = res.json()["report_payload"]["nested_evidence"]
    assert stored["screenshot_b64"] == "[BINARY_DATA_STRIPPED_FOR_PRIVACY]"
    assert stored["deep"][0]["audio_raw"] == "[BINARY_DATA_STRIPPED_FOR_PRIVACY]"


@pytest.mark.asyncio
async def test_save_case_long_case_id_collision_safe(client: AsyncClient, test_db_session: AsyncSession):
    """A 64-character case_id colliding with another user is safely truncated and kept <= 64 chars."""
    user_a = await create_test_user(test_db_session, "user_long_a@test.com")
    user_b = await create_test_user(test_db_session, "user_long_b@test.com")

    long_id = "A" * 64
    payload = {
        "case_id": long_id,
        "investigation_type": "unified",
        "schema_version": 1,
        "report_payload": SAMPLE_REPORT_PAYLOAD,
    }

    res_a = await client.post("/api/v1/cases", json=payload, headers=get_auth_headers(user_a.id))
    assert res_a.status_code == 201
    assert len(res_a.json()["case_id"]) == 64

    res_b = await client.post("/api/v1/cases", json=payload, headers=get_auth_headers(user_b.id))
    assert res_b.status_code == 201
    b_id = res_b.json()["case_id"]
    assert len(b_id) <= 64
    assert b_id != res_a.json()["case_id"]


@pytest.mark.asyncio
async def test_save_case_server_derives_verdict_and_score(client: AsyncClient, test_db_session: AsyncSession):
    """The server derives threat_score, verdict, and severity from the validated payload."""
    user = await create_test_user(test_db_session)
    headers = get_auth_headers(user.id)

    # Payload with high score (88.5) and high-risk verdict
    payload = {
        "case_id": "CASE-DERIVE-01",
        "investigation_type": "unified",
        "schema_version": 1,
        "report_payload": {
            **SAMPLE_REPORT_PAYLOAD,
            "score": 88.5,
            "verdict": "high-risk",
        },
    }

    res = await client.post("/api/v1/cases", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["threat_score"] == 88.5
    assert data["verdict"] == "high-risk"
    assert data["severity"] == "critical"  # derived automatically since score >= 85.0
