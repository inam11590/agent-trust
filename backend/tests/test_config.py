import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_settings_read_environment_and_hide_password(monkeypatch):
    monkeypatch.setenv("POSTGRES_PORT", "5433")
    monkeypatch.setenv("POSTGRES_PASSWORD", "test-only-placeholder")
    settings = Settings(_env_file=None)

    assert settings.postgres_port == 5433
    assert "test-only-placeholder" not in repr(settings)


def test_settings_reject_invalid_port(monkeypatch):
    monkeypatch.setenv("POSTGRES_PORT", "70000")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_database_url_handles_special_characters_and_masks_password():
    settings = Settings(_env_file=None, postgres_user="test-user", postgres_password="test:@/%value")
    assert settings.database_url.password == "test:@/%value"
    assert "test:@/%value" not in str(settings.database_url)
    assert settings.database_url.drivername == "postgresql+psycopg"


def test_database_url_requires_credentials():
    settings = Settings(_env_file=None, postgres_user="", postgres_password="")
    with pytest.raises(ValueError, match="Set POSTGRES_USER"):
        _ = settings.database_url
