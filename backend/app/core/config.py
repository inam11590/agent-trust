"""Validated settings loaded from the environment or backend/.env."""

from pathlib import Path
from decimal import Decimal
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, make_url
from cryptography.fernet import Fernet

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_env: Literal["development", "local", "test", "staging", "production"] = "local"
    jwt_secret_key: SecretStr = SecretStr("")
    jwt_access_token_expire_minutes: int = Field(default=15, ge=1, le=60)
    jwt_issuer: str = Field(default="agenttrust", min_length=1)
    jwt_audience: str = Field(default="agenttrust-api", min_length=1)
    mfa_encryption_key: SecretStr = SecretStr("")
    mfa_challenge_expire_minutes: int = Field(default=5, ge=2, le=10)
    mfa_max_attempts: int = Field(default=5, ge=3, le=10)
    mfa_lock_minutes: int = Field(default=15, ge=1, le=60)
    mfa_rate_limit_per_minute: int = Field(default=10, ge=1, le=100)
    audit_retention_days: int = Field(default=365, ge=30, le=3650)
    security_event_retention_days: int = Field(default=365, ge=30, le=3650)
    notification_delivery_retention_days: int = Field(default=30, ge=1, le=365)
    postgres_host: str = "localhost"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = "agenttrust"
    postgres_user: str = ""
    postgres_password: SecretStr = SecretStr("")
    postgres_connect_timeout: int = Field(default=5, ge=1, le=30)
    postgres_sslmode: Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"] = "prefer"
    database_url_override: SecretStr = Field(default=SecretStr(""), validation_alias=AliasChoices("DATABASE_URL", "DATABASE_URL_OVERRIDE"))
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=10, ge=0, le=100)
    database_pool_timeout: int = Field(default=10, ge=1, le=60)
    database_pool_recycle_seconds: int = Field(default=1800, ge=60, le=86400)
    redis_url: SecretStr = SecretStr("")
    redis_required: bool = False
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    sentry_dsn: SecretStr = SecretStr("")
    sentry_environment: str = ""
    sentry_traces_sample_rate: float = Field(default=0.0, ge=0, le=1)
    metrics_auth_token: SecretStr = SecretStr("")
    developer_rate_limit_per_minute: int = Field(default=100, ge=1, le=10000)
    agent_signature_clock_window_seconds: int = Field(default=300, ge=30, le=900)
    agent_signed_body_max_bytes: int = Field(default=65536, ge=1024, le=1048576)
    agent_max_active_signing_keys: int = Field(default=3, ge=2, le=10)
    agent_key_expiry_warning_days: int = Field(default=7, ge=1, le=30)
    agent_signature_failure_limit_per_minute: int = Field(default=20, ge=1, le=1000)
    webhook_signing_key: SecretStr = SecretStr("")
    webhook_timeout_seconds: int = Field(default=5, ge=1, le=30)
    webhook_signature_tolerance_seconds: int = Field(default=300, ge=30, le=3600)
    invitation_expire_days: int = Field(default=7, ge=1, le=30)
    invitation_bind_email: bool = True
    web_app_url: str = "http://127.0.0.1:3000"
    api_public_url: str = "http://127.0.0.1:8000"
    cors_allowed_origins: str = "http://127.0.0.1:3000,http://localhost:3000"
    auth_login_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    auth_register_rate_limit_per_minute: int = Field(default=20, ge=1, le=1000)
    account_lock_attempts: int = Field(default=5, ge=2, le=20)
    account_lock_minutes: int = Field(default=15, ge=1, le=1440)
    email_provider: Literal["disabled", "development"] = "development"
    email_api_key: SecretStr = SecretStr("")
    email_from_address: str = "notifications@agenttrust.local"
    email_from_name: str = "AgentTrust"
    fcm_project_id: str = ""
    fcm_access_token: SecretStr = SecretStr("")
    notification_delivery_timeout_seconds: int = Field(default=8, ge=1, le=30)
    notification_max_delivery_attempts: int = Field(default=3, ge=1, le=10)
    notification_retry_base_seconds: int = Field(default=30, ge=1, le=3600)
    notification_worker_batch_size: int = Field(default=50, ge=1, le=500)
    notification_worker_poll_seconds: int = Field(default=10, ge=1, le=300)
    permission_expiry_warning_minutes: int = Field(default=60, ge=5, le=10080)
    risk_low_max: int = Field(default=29, ge=0, le=97)
    risk_medium_max: int = Field(default=59, ge=1, le=98)
    risk_high_max: int = Field(default=79, ge=2, le=99)
    risk_history_days: int = Field(default=30, ge=1, le=365)
    risk_velocity_window_seconds: int = Field(default=60, ge=10, le=3600)
    risk_velocity_medium_count: int = Field(default=5, ge=2, le=10000)
    risk_velocity_high_count: int = Field(default=10, ge=3, le=10000)
    risk_velocity_critical_count: int = Field(default=30, ge=4, le=10000)
    risk_rejection_window_minutes: int = Field(default=10, ge=1, le=1440)
    risk_new_agent_hours: int = Field(default=24, ge=1, le=720)
    risk_recent_permission_minutes: int = Field(default=60, ge=1, le=1440)
    billing_provider: Literal["disabled", "test", "paddle_sandbox"] = "test"
    billing_secret_key: SecretStr = SecretStr("")
    billing_webhook_secret: SecretStr = SecretStr("")
    billing_webhook_tolerance_seconds: int = Field(default=300, ge=5, le=900)
    billing_grace_period_days: int = Field(default=7, ge=1, le=30)
    billing_admin_can_manage: bool = True
    billing_starter_monthly_price: Decimal = Field(default=Decimal("29.00"), ge=0)
    billing_business_monthly_price: Decimal = Field(default=Decimal("149.00"), ge=0)
    billing_price_starter_monthly: str = ""
    billing_price_business_monthly: str = ""
    billing_paddle_api_url: str = "https://sandbox-api.paddle.com"
    region_id: str = "us-east-1"
    region_role: Literal["primary", "standby"] = "primary"
    region_fencing_enabled: bool = False
    backup_storage_path: str = "backups"
    backup_retention_days: int = Field(default=30, ge=1, le=365)
    circuit_breaker_failure_threshold: int = Field(default=5, ge=1, le=50)
    circuit_breaker_recovery_timeout_seconds: int = Field(default=30, ge=5, le=300)
    secondary_control_plane_url: str = ""

    @field_validator("risk_medium_max")
    @classmethod
    def validate_risk_medium(cls, value: int, info) -> int:
        low = info.data.get("risk_low_max", 29)
        if value <= low:
            raise ValueError("RISK_MEDIUM_MAX must be greater than RISK_LOW_MAX")
        return value

    @field_validator("risk_high_max")
    @classmethod
    def validate_risk_high(cls, value: int, info) -> int:
        medium = info.data.get("risk_medium_max", 59)
        if value <= medium:
            raise ValueError("RISK_HIGH_MAX must be greater than RISK_MEDIUM_MAX")
        return value

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if secret and len(secret.encode("utf-8")) < 32:
            raise ValueError("JWT_SECRET_KEY must contain at least 32 bytes of random secret material.")
        return value

    @field_validator("mfa_encryption_key")
    @classmethod
    def validate_mfa_encryption_key(cls, value: SecretStr) -> SecretStr:
        if value.get_secret_value():
            try:
                Fernet(value.get_secret_value().encode())
            except (ValueError, TypeError):
                raise ValueError("MFA_ENCRYPTION_KEY must be a Fernet key") from None
        return value

    @model_validator(mode="after")
    def validate_deployment_environment(self):
        if self.app_env not in {"staging", "production"}:
            return self
        missing = []
        if len(self.jwt_secret_key.get_secret_value().encode()) < 32: missing.append("JWT_SECRET_KEY")
        if not self.mfa_encryption_key.get_secret_value(): missing.append("MFA_ENCRYPTION_KEY")
        if not self.database_configured: missing.append("DATABASE_URL or PostgreSQL credentials")
        elif self.database_url.drivername != "postgresql+psycopg": missing.append("PostgreSQL DATABASE_URL")
        elif self.app_env == "production" and self.database_url.query.get("sslmode") not in {"require", "verify-ca", "verify-full"}:
            missing.append("PostgreSQL TLS (POSTGRES_SSLMODE=require or stronger)")
        if len(self.webhook_signing_key.get_secret_value().encode()) < 32: missing.append("WEBHOOK_SIGNING_KEY")
        if len(self.metrics_auth_token.get_secret_value().encode()) < 32: missing.append("METRICS_AUTH_TOKEN")
        if not self.redis_url.get_secret_value(): missing.append("REDIS_URL")
        if self.rate_limit_backend != "redis": missing.append("RATE_LIMIT_BACKEND=redis")
        if not self.redis_required: missing.append("REDIS_REQUIRED=true")
        if self.billing_provider not in {"test", "paddle_sandbox"}: missing.append("BILLING_PROVIDER=test or paddle_sandbox")
        if not self.web_app_url.startswith("https://"): missing.append("HTTPS WEB_APP_URL")
        if not self.api_public_url.startswith("https://"): missing.append("HTTPS API_PUBLIC_URL")
        if not self.allowed_origins or any(not origin.startswith("https://") for origin in self.allowed_origins): missing.append("HTTPS CORS_ALLOWED_ORIGINS")
        if missing:
            raise ValueError("Unsafe deployment configuration; set: " + ", ".join(missing))
        return self

    @property
    def database_configured(self) -> bool:
        return bool(self.database_url_override.get_secret_value() or (self.postgres_user and self.postgres_password.get_secret_value()))

    @property
    def database_url(self) -> URL:
        override = self.database_url_override.get_secret_value()
        if override:
            if self.app_env in {"staging", "production"} and not override.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ValueError("DATABASE_URL must use PostgreSQL")
            url = make_url(override)
            if url.drivername == "postgresql":
                url = url.set(drivername="postgresql+psycopg")
            if "sslmode" not in url.query:
                url = url.update_query_dict({"sslmode": self.postgres_sslmode})
            if "connect_timeout" not in url.query:
                url = url.update_query_dict({"connect_timeout": str(self.postgres_connect_timeout)})
            return url
        if not self.database_configured:
            raise ValueError("Set POSTGRES_USER and POSTGRES_PASSWORD before using the database.")
        return URL.create(
            "postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
            query={"connect_timeout": str(self.postgres_connect_timeout), "sslmode": self.postgres_sslmode},
        )

    @property
    def allowed_origins(self) -> list[str]:
        origins = [value.strip().rstrip("/") for value in self.cors_allowed_origins.split(",") if value.strip()]
        if self.app_env == "production" and "*" in origins:
            raise ValueError("CORS wildcard origins are not allowed in production")
        return origins
