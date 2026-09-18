"""Notification ownership, delivery, preferences, devices, and expiry jobs."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    Agent, AgentStatus, DeliveryChannel, DeliveryStatus, Device, DeviceStatus,
    Notification, NotificationDelivery, NotificationStatus, NotificationType, Permission,
)
from app.services.notification_delivery import process_notification_deliveries, process_permission_expiry_notifications

pytestmark = pytest.mark.skipif(os.getenv("RUN_DATABASE_TESTS") != "1", reason="Database tests disabled")


@pytest.fixture(scope="module")
def engine():
    value = create_database_engine(Settings())
    yield value
    value.dispose()


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
        _env_file=None, app_env="test", jwt_secret_key=secrets.token_urlsafe(48),
        postgres_user="", postgres_password="", email_provider="development",
        fcm_project_id="", fcm_access_token="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client: TestClient, name: str = "Inam"):
    email = f"notify-{uuid4()}@example.com"
    password = secrets.token_urlsafe(24)
    user = client.post("/auth/register", json={"email": email, "password": password, "full_name": name})
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert user.status_code == 201 and login.status_code == 200
    return user.json(), {"Authorization": f"Bearer {login.json()['access_token']}"}


def pending(client: TestClient, db: Session, headers: dict, amount: str = "420"):
    agent = client.post("/agents", headers=headers, json={"name": "Travel Assistant"}).json()
    stored = db.get(Agent, UUID(agent["id"]))
    stored.status = AgentStatus.ACTIVE
    db.commit()
    now = datetime.now(timezone.utc)
    permission = client.post("/permissions", headers=headers, json={
        "agent_id": agent["id"], "action": "purchase", "resource": "flight",
        "maximum_amount": "500", "currency": "USD", "requires_approval": True,
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
    }).json()
    result = client.post("/authorize", headers=headers, json={
        "agent_id": agent["agent_identifier"], "action": "purchase", "resource": "flight",
        "amount": amount, "currency": "USD",
    })
    assert result.status_code == 200 and result.json()["decision"] == "PENDING"
    return agent, permission, result.json()


def test_pending_creates_high_priority_notification_for_correct_user(client, db):
    user, headers = account(client)
    agent, _, result = pending(client, db, headers)
    item = db.scalar(select(Notification).where(Notification.type == NotificationType.AUTHORIZATION_PENDING))
    assert item.user_id == UUID(user["id"])
    assert item.related_agent_id == UUID(agent["id"])
    assert item.metadata_json["request_id"] == result["request_id"]
    assert item.priority.value == "high"
    deliveries = list(db.scalars(select(NotificationDelivery).where(NotificationDelivery.notification_id == item.id)))
    assert {delivery.channel for delivery in deliveries} == {DeliveryChannel.IN_APP, DeliveryChannel.PUSH}


def test_private_list_read_count_and_mark_read(client, db):
    _, owner_headers = account(client)
    pending(client, db, owner_headers)
    _, stranger_headers = account(client, "Stranger")
    listing = client.get("/notifications?page=1&page_size=1&unread=true", headers=owner_headers)
    assert listing.status_code == 200 and listing.json()["total"] >= 1
    notification_id = listing.json()["items"][0]["id"]
    assert client.get("/notifications", headers=stranger_headers).json()["total"] == 0
    assert client.post(f"/notifications/{notification_id}/read", headers=stranger_headers).status_code == 404
    assert client.get("/notifications/unread-count", headers=owner_headers).json()["count"] >= 1
    read = client.post(f"/notifications/{notification_id}/read", headers=owner_headers)
    assert read.status_code == 200 and read.json()["status"] == "read"
    assert client.post("/notifications/read-all", headers=owner_headers).json() == {"count": 0}


def test_filters_archive_and_pagination(client, db):
    _, headers = account(client)
    pending(client, db, headers, "410")
    listing = client.get(
        "/notifications?type=authorization_pending&priority=high&page=1&page_size=1", headers=headers,
    )
    assert listing.status_code == 200 and listing.json()["page_size"] == 1
    item_id = listing.json()["items"][0]["id"]
    archived = client.post(f"/notifications/{item_id}/archive", headers=headers)
    assert archived.status_code == 200 and archived.json()["status"] == "archived"
    assert client.get("/notifications", headers=headers).json()["total"] == 0


def test_preferences_disable_push_and_are_persisted(client, db):
    _, headers = account(client)
    changed = client.patch("/notification-preferences", headers=headers, json={
        "approval_push_enabled": False, "approval_email_enabled": True,
    })
    assert changed.status_code == 200 and changed.json()["approval_push_enabled"] is False
    pending(client, db, headers)
    notification = db.scalar(select(Notification).where(Notification.type == NotificationType.AUTHORIZATION_PENDING))
    channels = set(db.scalars(select(NotificationDelivery.channel).where(
        NotificationDelivery.notification_id == notification.id,
    )))
    assert DeliveryChannel.PUSH not in channels
    assert DeliveryChannel.EMAIL in channels


def test_device_registration_deduplicates_and_is_private(client, db):
    _, headers = account(client)
    token = "fcm-token-" + secrets.token_urlsafe(32)
    first = client.post("/devices", headers=headers, json={"push_token": token, "platform": "android"})
    second = client.post("/devices", headers=headers, json={"push_token": token, "platform": "android"})
    assert first.status_code == 201 and second.json()["id"] == first.json()["id"]
    assert first.json().get("push_token") is None
    _, other = account(client)
    assert client.post("/devices", headers=headers, json={
        "push_token": "other-" + secrets.token_urlsafe(32), "platform": "android",
        "user_id": str(uuid4()),
    }).status_code == 422
    assert client.post("/devices", headers=other, json={"push_token": token, "platform": "android"}).status_code == 409
    assert client.delete(f"/devices/{first.json()['id']}", headers=other).status_code == 404
    assert client.delete(f"/devices/{first.json()['id']}", headers=headers).status_code == 204
    assert db.get(Device, UUID(first.json()["id"])).status == DeviceStatus.REVOKED


def test_decision_creates_one_final_notification(client, db):
    _, headers = account(client)
    _, _, result = pending(client, db, headers)
    request_item = client.get("/authorization-requests?status=PENDING", headers=headers).json()["items"][0]
    assert client.post(f"/authorization-requests/{request_item['id']}/approve", headers=headers).status_code == 200
    final = list(db.scalars(select(Notification).where(
        Notification.type == NotificationType.AUTHORIZATION_APPROVED,
        Notification.related_request_id == UUID(request_item["id"]),
    )))
    assert len(final) == 1 and final[0].metadata_json["request_id"] == result["request_id"]


def test_delivery_failure_retries_with_safe_error(client, db):
    _, headers = account(client)
    _, _, _ = pending(client, db, headers)
    delivery = db.scalar(select(NotificationDelivery).where(
        NotificationDelivery.channel == DeliveryChannel.PUSH,
        NotificationDelivery.status == DeliveryStatus.PENDING,
    ))
    settings = Settings(
        _env_file=None, postgres_user="", postgres_password="", notification_retry_base_seconds=1,
        fcm_project_id="", fcm_access_token="",
    )
    process_notification_deliveries(db, settings)
    db.refresh(delivery)
    assert delivery.attempt_count == 1 and delivery.next_attempt_at is not None
    assert delivery.last_error == "No active push device"


def test_development_email_delivery_succeeds_without_credentials(client, db):
    _, headers = account(client)
    client.patch("/notification-preferences", headers=headers, json={"approval_email_enabled": True})
    pending(client, db, headers)
    settings = Settings(_env_file=None, app_env="test", postgres_user="", postgres_password="", email_provider="development")
    process_notification_deliveries(db, settings)
    email = db.scalar(select(NotificationDelivery).where(NotificationDelivery.channel == DeliveryChannel.EMAIL))
    assert email.status == DeliveryStatus.SENT and email.provider_message_id == "development-preview"


def test_permission_expiry_warning_and_expired_notifications_are_deduplicated(client, db):
    user, headers = account(client)
    agent = client.post("/agents", headers=headers, json={"name": "Travel Assistant"}).json()
    now = datetime.now(timezone.utc)
    permission = client.post("/permissions", headers=headers, json={
        "agent_id": agent["id"], "action": "purchase", "resource": "flight",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
    }).json()
    settings = Settings(_env_file=None, postgres_user="", postgres_password="", permission_expiry_warning_minutes=60)
    assert process_permission_expiry_notifications(db, settings, now) == 1
    assert process_permission_expiry_notifications(db, settings, now) == 0
    assert process_permission_expiry_notifications(db, settings, now + timedelta(hours=1)) == 1
    assert process_permission_expiry_notifications(db, settings, now + timedelta(hours=1)) == 0
    types = set(db.scalars(select(Notification.type).where(
        Notification.user_id == UUID(user["id"]), Notification.related_permission_id == UUID(permission["id"]),
    )))
    assert types == {NotificationType.PERMISSION_EXPIRING, NotificationType.PERMISSION_EXPIRED}


def test_expiry_preference_prevents_warning(client, db):
    _, headers = account(client)
    client.patch("/notification-preferences", headers=headers, json={"permission_expiry_enabled": False})
    agent = client.post("/agents", headers=headers, json={"name": "Quiet Agent"}).json()
    now = datetime.now(timezone.utc)
    client.post("/permissions", headers=headers, json={
        "agent_id": agent["id"], "action": "read", "resource": "calendar",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=15)).isoformat(),
    })
    settings = Settings(_env_file=None, postgres_user="", postgres_password="", permission_expiry_warning_minutes=60)
    assert process_permission_expiry_notifications(db, settings, now) == 0


def test_push_payload_links_to_exact_request(client, db, monkeypatch):
    _, headers = account(client)
    token = "fcm-token-" + secrets.token_urlsafe(32)
    client.post("/devices", headers=headers, json={"push_token": token, "platform": "android"})
    pending(client, db, headers)
    sent = []
    from app.services.notification_providers import DeliveryResult, FirebasePushProvider
    def fake_send(self, **payload):
        sent.append(payload)
        return DeliveryResult(message_id="fcm-message-1")
    monkeypatch.setattr(FirebasePushProvider, "send", fake_send)
    settings = Settings(_env_file=None, postgres_user="", postgres_password="", fcm_project_id="project", fcm_access_token="token")
    process_notification_deliveries(db, settings)
    request_record = db.scalar(select(Notification).where(Notification.type == NotificationType.AUTHORIZATION_PENDING))
    assert any(payload["data"]["request_id"] == str(request_record.related_request_id) for payload in sent)


def test_email_failure_is_safe_and_retryable(client, db):
    _, headers = account(client)
    client.patch("/notification-preferences", headers=headers, json={"approval_email_enabled": True})
    pending(client, db, headers)
    settings = Settings(
        _env_file=None,
        app_env="production",
        DATABASE_URL="postgresql://test:dummy@localhost/test?sslmode=require",
        jwt_secret_key="j" * 40,
        mfa_encryption_key=Fernet.generate_key().decode(),
        webhook_signing_key="w" * 40,
        metrics_auth_token="m" * 40,
        redis_url="redis://localhost:6379/0",
        redis_required=True,
        rate_limit_backend="redis",
        web_app_url="https://example.test",
        api_public_url="https://api.example.test",
        cors_allowed_origins="https://example.test",
        email_provider="disabled",
    )
    process_notification_deliveries(db, settings)
    delivery = db.scalar(select(NotificationDelivery).where(NotificationDelivery.channel == DeliveryChannel.EMAIL))
    assert delivery.status == DeliveryStatus.PENDING
    assert delivery.attempt_count == 1
    assert delivery.last_error == "Email provider is not configured"


def test_api_key_revocation_creates_security_notification(client, db):
    _, headers = account(client)
    created = client.post("/developer/api-keys", headers=headers, json={"name": "Worker key"})
    assert created.status_code == 201
    revoked = client.post(f"/developer/api-keys/{created.json()['id']}/revoke", headers=headers)
    assert revoked.status_code == 200
    item = db.scalar(select(Notification).where(Notification.type == NotificationType.API_KEY_REVOKED))
    assert item is not None and "Worker key" in item.message
