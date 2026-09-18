"""Authentication requests against real PostgreSQL, with transaction rollback."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import create_access_token, verify_password
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import AuthSession, SecurityEvent, User

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Set RUN_DATABASE_TESTS=1 to test authentication against migrated PostgreSQL.",
)


@pytest.fixture(scope="module")
def engine():
    engine = create_database_engine(Settings())
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
                yield session
        finally:
            transaction.rollback()


@pytest.fixture
def client(db):
    app = create_app()
    app.state.settings = Settings(
        _env_file=None, jwt_secret_key=secrets.token_urlsafe(48),
        postgres_user="", postgres_password="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as client:
        yield client


@pytest.fixture
def account():
    return {
        "email": f"auth-{uuid4()}@example.com",
        "password": secrets.token_urlsafe(24),
        "full_name": "Test User",
    }


def register(client, account):
    response = client.post("/auth/register", json=account)
    assert response.status_code == 201, response.text
    return response.json()


def login(client, account):
    response = client.post("/auth/login", json={key: account[key] for key in ("email", "password")})
    assert response.status_code == 200, response.text
    return response


def test_register_login_and_me(client, db, account):
    user = register(client, account)
    assert set(user) == {"id", "email", "full_name", "is_active", "created_at", "updated_at"}
    stored = db.get(User, UUID(user["id"]))
    assert stored.hashed_password.startswith("$argon2id$")
    assert verify_password(account["password"], stored.hashed_password)
    assert stored.hashed_password != account["password"]
    token_response = login(client, account)
    token = token_response.json()
    assert token["token_type"] == "bearer"
    assert token["expires_in"] == 900
    assert token_response.headers["Cache-Control"] == "no-store"
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token['access_token']}"})
    assert response.status_code == 200
    assert response.json() == user
    assert "password" not in response.text
    assert response.headers["Cache-Control"] == "no-store"


def test_email_normalization_and_duplicate_registration(client, db, account):
    account["email"] = account["email"].upper()
    account["full_name"] = "  Test User  "
    registered = register(client, account)
    assert registered["email"] == account["email"].lower()
    assert registered["full_name"] == "Test User"
    account["email"] = account["email"].lower()
    duplicate = client.post("/auth/register", json=account)
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Email is already registered"}
    assert db.scalar(select(func.count()).select_from(User).where(User.email == account["email"])) == 1
    account["email"] = account["email"].upper()
    login(client, account)


def test_registration_handles_unique_constraint_race(client, db, account, monkeypatch):
    register(client, account)
    monkeypatch.setattr("app.services.auth.find_user_by_email", lambda *_: None)
    response = client.post("/auth/register", json=account)
    assert response.status_code == 409
    assert response.json() == {"detail": "Email is already registered"}
    # A handled conflict leaves the session usable.
    assert db.scalar(select(func.count()).select_from(User)) >= 1


def test_database_blocks_case_variant_email(client, db, account):
    register(client, account)
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(User(email=account["email"].upper(), full_name="Duplicate", hashed_password="!unusable"))
            db.flush()


@pytest.mark.parametrize("change", ["email", "short_password", "long_password", "name", "extra", "missing"])
def test_invalid_registration_returns_safe_validation_errors(client, db, account, change):
    existing_users = db.scalar(select(func.count()).select_from(User))
    if change == "email":
        account["email"] = "invalid-email"
    elif change == "short_password":
        account["password"] = "xY9!private"
    elif change == "long_password":
        account["password"] = "a" * 129
    elif change == "name":
        account["full_name"] = "   "
    elif change == "extra":
        account["is_active"] = False
    else:
        del account["email"]
    response = client.post("/auth/register", json=account)
    assert response.status_code == 422
    assert account["password"] not in response.text
    assert all("input" not in error for error in response.json()["detail"])
    assert db.scalar(select(func.count()).select_from(User)) == existing_users


def test_failed_login_has_same_error_for_wrong_password_unknown_and_inactive(client, db, account):
    registered = register(client, account)
    bodies = [
        {"email": account["email"], "password": "wrong-password"},
        {"email": f"missing-{uuid4()}@example.com", "password": account["password"]},
    ]
    responses = [client.post("/auth/login", json=body) for body in bodies]
    user = db.get(User, UUID(registered["id"]))
    user.is_active = False
    db.commit()
    responses.append(client.post("/auth/login", json={key: account[key] for key in ("email", "password")}))
    for response in responses:
        assert response.status_code == 401
        assert response.json() == {"detail": "Incorrect email or password"}
        assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("authorization", [None, "Basic abc", "Bearer not-a-token"])
def test_me_requires_valid_bearer_token(client, authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize("mode", ["expired", "tampered", "missing_user", "disabled", "deleted"])
def test_me_rejects_invalid_or_no_longer_valid_identity(client, db, account, mode):
    registered = register(client, account)
    token = login(client, account).json()["access_token"]
    settings = client.app.state.settings
    if mode == "expired":
        token = jwt.encode({
            "sub": registered["id"], "iat": datetime.now(timezone.utc) - timedelta(minutes=2),
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
            "iss": settings.jwt_issuer, "aud": settings.jwt_audience, "token_type": "access",
        }, settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    elif mode == "tampered":
        head, body, signature = token.split(".")
        signature = ("a" if signature[0] != "a" else "b") + signature[1:]
        token = ".".join([head, body, signature])
    elif mode == "missing_user":
        token = create_access_token(uuid4(), settings)
    else:
        user = db.get(User, UUID(registered["id"]))
        if mode == "disabled":
            user.is_active = False
        else:
            # The new session and historical-event rows intentionally reference users.
            # Clear only this test's dependent rows to exercise a genuinely missing user.
            db.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
            db.execute(delete(SecurityEvent).where(SecurityEvent.actor_user_id == user.id))
            db.delete(user)
        db.commit()
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_me_returns_token_owner_only(client, account):
    first = register(client, account)
    token = login(client, account).json()["access_token"]
    register(client, {**account, "email": f"other-{uuid4()}@example.com"})
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["id"] == first["id"]


def test_unconfigured_auth_fails_closed(client, account):
    client.app.state.settings = Settings(_env_file=None, jwt_secret_key="")
    for path in ("/auth/register", "/auth/login"):
        response = client.post(path, json=account)
        assert response.status_code == 503
        assert response.json() == {"detail": "Authentication is not configured"}
    assert client.get("/health").status_code == 200
