"""Application Settings and Configuration."""
from typing import Any, List, Optional, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """PhishLens AI runtime configuration via Pydantic."""

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    PROJECT_NAME: str = "PhishLens AI API"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # CORS configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "https://phishlens-ai.vercel.app",
    ]
    CORS_ORIGIN_REGEX: Optional[str] = r"^https:\/\/(phishlens-ai|phish-lens-ai|phishlensai)[a-z0-9-]*\.vercel\.app$"

    # Future Model paths
    URL_MODEL_PATH: str = "models/saved/url_classifier.joblib"
    SMS_MODEL_PATH: str = "models/saved/sms_classifier.joblib"

    # Phase 4: LLM Explanation & Risk Configuration
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    ENABLE_LLM_EXPLANATION: bool = True
    LLM_TIMEOUT_SECONDS: float = 5.0
    RISK_THRESHOLD_HIGH: float = 70.0
    RISK_THRESHOLD_SUSPICIOUS: float = 30.0

    # Phase 1: Database & Persistence
    DATABASE_URL: Optional[str] = None

    # Phase 1: Security & JWT
    JWT_SECRET_KEY: str = "dev-insecure-jwt-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    REFRESH_ROTATION_GRACE_SECONDS: int = 15

    # Phase 1: Cookie Configuration for Refresh Tokens
    REFRESH_COOKIE_NAME: str = "phishlens_refresh_token"
    COOKIE_SECURE: Optional[bool] = None
    COOKIE_SAMESITE: Optional[str] = None
    COOKIE_DOMAIN: Optional[str] = None

    # Phase 1.2: Proxy & Rate Limiting
    TRUST_FORWARDED_FOR: bool = False

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_database_url(cls, v: Any) -> str:
        if isinstance(v, str) and v.strip():
            url = v.strip()
            # Render / Heroku compatibility: postgres:// -> postgresql+asyncpg://
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql+asyncpg://", 1)
            elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
            return url
        # Default local dev fallback to SQLite via aiosqlite
        return "sqlite+aiosqlite:///./phishlens_dev.db"

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        """Fails startup safely if mandatory production security settings are missing or insecure."""
        if self.is_production:
            if (
                not self.JWT_SECRET_KEY
                or self.JWT_SECRET_KEY == "dev-insecure-jwt-secret-key-change-in-production"
                or len(self.JWT_SECRET_KEY) < 32
            ):
                raise ValueError(
                    "Production configuration error: JWT_SECRET_KEY must be securely configured "
                    "with a cryptographically strong secret of at least 32 characters in production."
                )
            if not self.DATABASE_URL or self.DATABASE_URL.startswith("sqlite"):
                raise ValueError(
                    "Production configuration error: DATABASE_URL must be configured with a managed "
                    "PostgreSQL connection string (e.g. postgresql+asyncpg://...) in production."
                )
            if self.JWT_ALGORITHM not in ["HS256", "HS384", "HS512"]:
                raise ValueError(
                    f"Production configuration error: JWT_ALGORITHM '{self.JWT_ALGORITHM}' is not an authorized symmetric algorithm."
                )
        return self

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def resolved_cookie_secure(self) -> bool:
        if self.COOKIE_SECURE is not None:
            return self.COOKIE_SECURE
        return self.is_production

    @property
    def resolved_cookie_samesite(self) -> str:
        if self.COOKIE_SAMESITE is not None:
            return self.COOKIE_SAMESITE.lower()
        return "none" if self.is_production else "lax"



    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            trimmed = v.strip()
            if trimmed.startswith("[") and trimmed.endswith("]"):
                import json
                try:
                    parsed = json.loads(trimmed)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            return [i.strip() for i in trimmed.split(",") if i.strip()]
        elif isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return ["http://localhost:3000", "http://127.0.0.1:3000"]

    @field_validator("CORS_ORIGIN_REGEX", mode="before")
    @classmethod
    def assemble_cors_origin_regex(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        v_str = str(v).strip()
        return v_str if v_str else None


settings = Settings()
