"""Password hashing and JWT operations, independent of HTTP and persistence."""

import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

from app.core.config import Settings

ALGORITHM = "HS256"
password_hash = PasswordHash.recommended()
# Unknown accounts still perform a password verification to reduce timing leaks.
DUMMY_PASSWORD_HASH = password_hash.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hash.verify(password, stored_hash)
    except (UnknownHashError, ValueError):
        # Fail closed for unusable or malformed legacy hashes.
        password_hash.verify(password, DUMMY_PASSWORD_HASH)
        return False


def signing_key(settings: Settings) -> str:
    key = settings.jwt_secret_key.get_secret_value()
    if not key:
        raise ValueError("JWT_SECRET_KEY is not configured.")
    return key


def create_access_token(user_id: UUID, settings: Settings, *, session_token: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    claims = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "token_type": "access",
        }
    if session_token is not None:
        claims["jti"] = session_token
    return jwt.encode(claims, signing_key(settings), algorithm=ALGORITHM)


def decode_access_claims(token: str, settings: Settings) -> tuple[UUID, str | None]:
    if len(token) > 4096:
        raise InvalidTokenError("Invalid token")
    key = signing_key(settings)
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "iat", "exp", "iss", "aud", "token_type"]},
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise InvalidTokenError("Invalid token claims") from exc
    if payload["token_type"] != "access":
        raise InvalidTokenError("Invalid token type")
    if any(type(payload[field]) is not int for field in ("iat", "exp")):
        raise InvalidTokenError("Invalid token timestamps")
    try:
        user_id = UUID(payload["sub"])
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidTokenError("Invalid token subject") from exc
    session_token = payload.get("jti")
    if session_token is not None and (not isinstance(session_token, str) or len(session_token) < 32 or len(session_token) > 128):
        raise InvalidTokenError("Invalid session identifier")
    return user_id, session_token


def decode_access_token(token: str, settings: Settings) -> UUID:
    return decode_access_claims(token, settings)[0]
