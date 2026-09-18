"""Production configuration, health, correlation, metrics, and safe-error tests."""

import json
import logging
from unittest.mock import Mock

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import ValidationError
from cryptography.fernet import Fernet
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.core.observability import JsonFormatter, metrics, scrub_error_event
from app.database.session import get_db
from app.main import create_app
from app.services.rate_limit import RedisRateLimiter


def production_values(**changes):
    values = dict(_env_file=None, app_env="production", jwt_secret_key="j" * 40,
        mfa_encryption_key=Fernet.generate_key().decode(),
        DATABASE_URL="postgresql://user:password@db/agenttrust", redis_url="redis://redis:6379/0",
        redis_required=True, rate_limit_backend="redis", webhook_signing_key="w" * 40,
        metrics_auth_token="m" * 40, web_app_url="https://app.agenttrust.example",
        api_public_url="https://api.agenttrust.example",
        cors_allowed_origins="https://app.agenttrust.example", billing_provider="test")
    values["postgres_sslmode"] = "require"
    values.update(changes); return values


def test_production_rejects_missing_security_configuration():
    with pytest.raises(ValidationError, match="Unsafe deployment configuration"): Settings(_env_file=None, app_env="production")


def test_production_accepts_complete_safe_configuration():
    settings = Settings(**production_values())
    assert settings.database_url.drivername == "postgresql+psycopg"


def test_production_rejects_non_postgresql_database():
    with pytest.raises((ValidationError, ValueError), match="PostgreSQL"): Settings(**production_values(DATABASE_URL="sqlite:///bad.db"))


def test_liveness_has_request_id_header():
    app = create_app(); app.state.settings = Settings(_env_file=None, postgres_user="", postgres_password="")
    with TestClient(app) as client: response = client.get("/health/live")
    assert response.status_code == 200 and response.headers["X-Request-ID"].startswith("req_")


def test_valid_caller_request_id_is_preserved():
    app = create_app(); app.state.settings = Settings(_env_file=None, postgres_user="", postgres_password="")
    with TestClient(app) as client: response = client.get("/health/live", headers={"X-Request-ID": "req_customer123"})
    assert response.headers["X-Request-ID"] == "req_customer123"


def test_readiness_hides_database_failure():
    app = create_app(); session = Mock(); session.execute.side_effect = OperationalError("SELECT", {}, Exception("private"))
    app.dependency_overrides[get_db] = lambda: session
    with TestClient(app) as client: response = client.get("/health/ready")
    assert response.status_code == 503 and response.json() == {"detail": "Service dependencies unavailable"}


def test_metrics_are_available_locally_without_sensitive_labels():
    app = create_app(); app.state.settings = Settings(_env_file=None, postgres_user="", postgres_password="")
    with TestClient(app) as client: response = client.get("/metrics")
    assert response.status_code == 200 and "agenttrust_http_requests_total" in response.text
    assert "authorization" not in response.text.lower() or "authorization_decisions" in response.text


def test_metrics_are_hidden_without_production_token():
    app = create_app(); settings = Settings(_env_file=None); settings.app_env = "production"; settings.metrics_auth_token = type(settings.metrics_auth_token)("m" * 40); app.state.settings = settings
    with TestClient(app) as client: response = client.get("/metrics")
    assert response.status_code == 404


def test_unexpected_error_returns_safe_body_and_request_id():
    app = create_app()
    def fail(): raise RuntimeError("private filesystem and secret")
    app.add_api_route("/test-unexpected", fail)
    with TestClient(app, raise_server_exceptions=False) as client: response = client.get("/test-unexpected")
    assert response.status_code == 500 and response.json()["error"] == "INTERNAL_ERROR"
    assert "private" not in response.text and response.json()["request_id"] == response.headers["X-Request-ID"]


def test_json_formatter_contains_operational_fields_not_message_arguments():
    record = logging.LogRecord("test", logging.INFO, __file__, 1, "request complete", (), None)
    record.request_id = "req_test123"; record.route = "/health/live"; record.status_code = 200; record.duration_ms = 1.2
    value = json.loads(JsonFormatter().format(record))
    assert value["service"] == "agenttrust-api" and value["request_id"] == "req_test123" and value["duration_ms"] == 1.2


def test_redis_rate_limiter_fails_closed_when_redis_is_unavailable():
    limiter = RedisRateLimiter.__new__(RedisRateLimiter)
    limiter.namespace = "test"; limiter.client = Mock()
    limiter.client.pipeline.side_effect = ConnectionError("private Redis address")
    assert limiter.allow("account", 10) is False


def test_error_tracking_removes_request_and_user_data():
    event = {"request": {"headers": {"Authorization": "secret"}}, "user": {"id": "private"},
             "extra": {"token": "secret"}, "breadcrumbs": ["private"], "message": "private",
             "exception": {"values": [{"type": "RuntimeError", "value": "secret",
                 "stacktrace": {"frames": [{"filename": "app/main.py", "vars": {"token": "secret"},
                     "context_line": "private"}]}}]}}
    assert scrub_error_event(event, {}) == {"exception": {"values": [{"type": "RuntimeError",
        "stacktrace": {"frames": [{"filename": "app/main.py"}]}}]}}


def test_production_metrics_requires_correct_token():
    app = create_app(); settings = Settings(_env_file=None); settings.app_env = "production"; settings.metrics_auth_token = type(settings.metrics_auth_token)("m" * 40); app.state.settings = settings
    with TestClient(app) as client:
        rejected = client.get("/metrics", headers={"X-Metrics-Token": "wrong"})
        accepted = client.get("/metrics", headers={"X-Metrics-Token": "m" * 40})
    assert rejected.status_code == 404 and accepted.status_code == 200
