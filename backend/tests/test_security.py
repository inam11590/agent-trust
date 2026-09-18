import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError

from app.core.config import Settings
from app.core.security import create_access_token, decode_access_token, hash_password, verify_password


@pytest.fixture
def settings():
    return Settings(_env_file=None, jwt_secret_key=secrets.token_urlsafe(48))


def claims(settings):
    now = datetime.now(timezone.utc)
    return {
        "sub": str(uuid4()), "iat": now, "exp": now + timedelta(minutes=15),
        "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "token_type": "access",
    }


def test_password_hash_is_salted_and_verifiable():
    password = secrets.token_urlsafe(24)
    first = hash_password(password)
    second = hash_password(password)
    assert first.startswith("$argon2id$")
    assert first != second
    assert password not in first
    assert verify_password(password, first)
    assert not verify_password(password + "wrong", first)
    assert not verify_password(password, "!unusable-hash")


def test_access_token_round_trip_and_lifetime(settings):
    user_id = uuid4()
    token = create_access_token(user_id, settings)
    assert decode_access_token(token, settings) == user_id
    payload = jwt.decode(
        token, settings.jwt_secret_key.get_secret_value(), algorithms=["HS256"],
        issuer=settings.jwt_issuer, audience=settings.jwt_audience,
    )
    assert payload["exp"] - payload["iat"] == 900
    assert set(payload) == {"sub", "iat", "exp", "iss", "aud", "token_type"}


@pytest.mark.parametrize("change", [
    "expired", "future", "issuer", "audience", "type", "subject", "missing_exp", "bad_exp",
])
def test_invalid_claims_are_rejected(settings, change):
    payload = claims(settings)
    if change == "expired":
        payload["exp"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif change == "future":
        payload["iat"] = datetime.now(timezone.utc) + timedelta(minutes=5)
    elif change == "issuer":
        payload["iss"] = "other-service"
    elif change == "audience":
        payload["aud"] = "other-api"
    elif change == "type":
        payload["token_type"] = "refresh"
    elif change == "subject":
        payload["sub"] = "not-a-uuid"
    elif change == "missing_exp":
        del payload["exp"]
    else:
        payload["exp"] = []
    token = jwt.encode(payload, settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings)


@pytest.mark.parametrize("mode", ["wrong_key", "wrong_algorithm", "unsigned", "malformed", "oversized"])
def test_invalid_signatures_and_formats_are_rejected(settings, mode):
    key = settings.jwt_secret_key.get_secret_value()
    if mode == "wrong_key":
        token = jwt.encode(claims(settings), secrets.token_urlsafe(48), algorithm="HS256")
    elif mode == "wrong_algorithm":
        token = jwt.encode(claims(settings), key, algorithm="HS512")
    elif mode == "unsigned":
        token = jwt.encode(claims(settings), "", algorithm="none")
    elif mode == "malformed":
        token = "not.a.jwt"
    else:
        token = "a" * 4097
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings)


def test_signing_requires_a_configured_secret():
    with pytest.raises(ValueError, match="not configured"):
        create_access_token(uuid4(), Settings(_env_file=None, jwt_secret_key=""))


def test_short_signing_key_is_rejected_without_exposing_value():
    key = secrets.token_urlsafe(8)
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, jwt_secret_key=key)
    assert key not in str(error.value)


@pytest.mark.parametrize("minutes", [0, 61])
def test_invalid_token_lifetime_is_rejected(minutes):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_access_token_expire_minutes=minutes)
