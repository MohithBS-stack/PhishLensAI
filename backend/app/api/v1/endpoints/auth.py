"""Authentication Endpoints for PhishLens AI."""
from datetime import datetime, timedelta, timezone
import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user
from app.core.config import settings
from app.core.errors import AppException
from app.core.rate_limit import auth_rate_limiter, enforce_rate_limit, get_client_ip
from app.core.security import (
    create_access_token,
    generate_secure_token,
    hash_password,
    hash_token,
    verify_dummy_password,
    verify_password,
)
from app.db.session import get_db
from app.models.session import RefreshSession
from app.models.user import User
from app.schemas.auth import (
    MessageResponse,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_refresh_cookie(response: Response, raw_token: str, expires_at: datetime) -> None:
    """Sets the HttpOnly, Secure, SameSite refresh token cookie on the response."""
    max_age = int(settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400)
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw_token,
        max_age=max_age,
        expires=expires_at,
        path="/api/v1/auth",
        domain=settings.COOKIE_DOMAIN or None,
        secure=settings.resolved_cookie_secure,
        httponly=True,
        samesite=settings.resolved_cookie_samesite,
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Deletes the refresh token cookie."""
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
        domain=settings.COOKIE_DOMAIN or None,
        secure=settings.resolved_cookie_secure,
        httponly=True,
        samesite=settings.resolved_cookie_samesite,
    )


def _extract_refresh_token(request: Request) -> Optional[str]:
    """Extracts the refresh token strictly from the HttpOnly cookie.

    Does not accept tokens from headers or query parameters to eliminate XSS token leakage.
    """
    cookie_token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if cookie_token and cookie_token.strip():
        return cookie_token.strip()
    return None


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    payload: UserRegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Registers a new user, hashes password with Argon2id, and issues session tokens."""
    # Rate limit: max 5 registrations per IP per minute
    enforce_rate_limit(request, scope="auth:register", max_requests=5, window_seconds=60)
    # Rate limit: max 3 registration attempts per (IP, email) per 5 minutes
    enforce_rate_limit(
        request,
        scope="auth:register_account",
        max_requests=3,
        window_seconds=300,
        extra_identifier=payload.email,
    )

    # Check for existing account by normalized email
    stmt = select(User).where(User.email == payload.email)
    existing_user = (await db.execute(stmt)).scalar_one_or_none()
    if existing_user:
        raise AppException(
            message="An account with this email address already exists.",
            status_code=status.HTTP_409_CONFLICT,
            error_code="EMAIL_ALREADY_REGISTERED",
        )


    # Hash password using Argon2id
    hashed_pw = hash_password(payload.password)

    new_user = User(
        id=uuid.uuid4(),
        email=payload.email,
        hashed_password=hashed_pw,
        full_name=payload.full_name,
        is_active=True,
        is_verified=False,
    )
    db.add(new_user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise AppException(
            message="An account with this email address already exists.",
            status_code=status.HTTP_409_CONFLICT,
            error_code="EMAIL_ALREADY_REGISTERED",
        )


    # Create server-side refresh session
    now = datetime.now(timezone.utc)
    raw_refresh_token = generate_secure_token(32)
    session_expiry = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    refresh_session = RefreshSession(
        id=uuid.uuid4(),
        user_id=new_user.id,
        token_hash=hash_token(raw_refresh_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=session_expiry,
    )
    db.add(refresh_session)
    await db.commit()
    await db.refresh(new_user)

    # Set HttpOnly refresh cookie
    _set_refresh_cookie(response, raw_refresh_token, session_expiry)

    # Generate short-lived access token
    access_token = create_access_token(user_id=new_user.id)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(new_user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and establish session",
)
async def login(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticates credentials using Argon2id and returns short-lived access token + HttpOnly cookie."""
    # Rate limit: max 10 attempts per IP per minute
    enforce_rate_limit(request, scope="auth:login_ip", max_requests=10, window_seconds=60)
    # Rate limit: max 5 failed attempts per (IP, email) per 5 minutes
    enforce_rate_limit(
        request,
        scope="auth:login_account",
        max_requests=5,
        window_seconds=300,
        extra_identifier=payload.email,
    )

    stmt = select(User).where(User.email == payload.email)
    user = (await db.execute(stmt)).scalar_one_or_none()

    if not user:
        # Dummy Argon2 verification to neutralize timing side-channel attacks
        verify_dummy_password()
        raise AppException(
            message="Invalid email or password.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="INVALID_CREDENTIALS",
        )

    if not verify_password(payload.password, user.hashed_password):
        raise AppException(
            message="Invalid email or password.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="INVALID_CREDENTIALS",
        )

    if not user.is_active:
        raise AppException(
            message="User account is inactive or disabled.",
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="USER_INACTIVE",
        )

    # Clear account rate limit on successful authentication
    auth_rate_limiter.reset_key(f"auth:login_account:{get_client_ip(request)}:{payload.email.strip().lower()}")

    # Create server-side refresh session
    now = datetime.now(timezone.utc)
    raw_refresh_token = generate_secure_token(32)
    session_expiry = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    refresh_session = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token(raw_refresh_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=session_expiry,
    )
    db.add(refresh_session)
    await db.commit()

    # Set HttpOnly refresh cookie
    _set_refresh_cookie(response, raw_refresh_token, session_expiry)

    # Generate short-lived access token
    access_token = create_access_token(user_id=user.id)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate refresh token and issue new access token",
)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Validates and rotates the refresh session, enforcing single-use and reuse attack detection."""
    # Rate limit: max 30 refresh calls per IP per minute
    enforce_rate_limit(request, scope="auth:refresh", max_requests=30, window_seconds=60)

    raw_token = _extract_refresh_token(request)
    if not raw_token:
        raise AppException(
            message="Refresh token not found or missing.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="REFRESH_TOKEN_MISSING",
        )

    token_digest = hash_token(raw_token)
    stmt = (
        select(RefreshSession)
        .where(RefreshSession.token_hash == token_digest)
        .with_for_update()
    )
    session = (await db.execute(stmt)).scalar_one_or_none()

    if not session:
        _clear_refresh_cookie(response)
        raise AppException(
            message="Invalid refresh session.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="INVALID_REFRESH_SESSION",
        )

    # Check for reuse of replaced or revoked token
    if session.replaced_by_session_id is not None or session.revoked_at is not None:
        now = datetime.now(timezone.utc)
        revoked_at = session.revoked_at
        if revoked_at and revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)

        # Grace period for token rotation (e.g. 15s) to tolerate network retries or concurrent tab refreshes
        if (
            session.replaced_by_session_id is not None
            and revoked_at is not None
            and (now - revoked_at).total_seconds() <= settings.REFRESH_ROTATION_GRACE_SECONDS
        ):
            # Critical Security Invariant: The successor replacement session must be actively valid.
            # If the user logged out or the successor was revoked, this predecessor token CANNOT be used.
            rep_stmt = select(RefreshSession).where(RefreshSession.id == session.replaced_by_session_id)
            replacement_session = (await db.execute(rep_stmt)).scalar_one_or_none()
            if replacement_session and replacement_session.is_active:
                user_stmt = select(User).where(User.id == session.user_id)
                user = (await db.execute(user_stmt)).scalar_one_or_none()
                if user and user.is_active:
                    access_token = create_access_token(user_id=user.id)
                    return TokenResponse(
                        access_token=access_token,
                        token_type="bearer",
                        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                        user=UserResponse.model_validate(user),
                    )

        # Outside grace window or replacement session was revoked/logged out: REUSE ATTACK DETECTED
        await db.execute(
            update(RefreshSession)
            .where(RefreshSession.user_id == session.user_id, RefreshSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.commit()
        _clear_refresh_cookie(response)
        logger.warning(
            f"Security alert: Refresh token reuse detected for user_id={session.user_id}. All sessions revoked."
        )
        raise AppException(
            message="Refresh token has already been used or revoked. All active sessions have been invalidated.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="REFRESH_TOKEN_REUSED",
        )

    # Check if session expired
    if session.is_expired:
        _clear_refresh_cookie(response)
        raise AppException(
            message="Refresh session has expired. Please log in again.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="REFRESH_SESSION_EXPIRED",
        )

    # Fetch user associated with session
    user_stmt = select(User).where(User.id == session.user_id)
    user = (await db.execute(user_stmt)).scalar_one_or_none()
    if not user or not user.is_active:
        _clear_refresh_cookie(response)
        raise AppException(
            message="User account inactive or not found.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="USER_INACTIVE",
        )

    # Rotate: Create new session record
    now = datetime.now(timezone.utc)
    new_raw_token = generate_secure_token(32)
    new_session_expiry = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    new_session = RefreshSession(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=hash_token(new_raw_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        expires_at=new_session_expiry,
    )
    db.add(new_session)

    # Mark old session as replaced and revoked
    session.revoked_at = now
    session.replaced_by_session_id = new_session.id

    await db.commit()

    # Set new rotating cookie
    _set_refresh_cookie(response, new_raw_token, new_session_expiry)

    # Issue new access token
    access_token = create_access_token(user_id=user.id)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke session and clear refresh cookie",
)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Invalidates the server-side refresh session and clears the cookie."""
    raw_token = _extract_refresh_token(request)
    if raw_token:
        token_digest = hash_token(raw_token)
        stmt = select(RefreshSession).where(RefreshSession.token_hash == token_digest)
        session = (await db.execute(stmt)).scalar_one_or_none()
        if session and session.revoked_at is None:
            session.revoked_at = datetime.now(timezone.utc)
            await db.commit()

    _clear_refresh_cookie(response)
    return MessageResponse(message="Successfully logged out.")



@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user profile",
)
async def get_me(
    current_user: User = Depends(get_current_active_user),
) -> UserResponse:
    """Returns profile information for the authenticated user."""
    return UserResponse.model_validate(current_user)
