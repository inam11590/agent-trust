"""Small signed-webhook foundation with persisted delivery attempts."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import ipaddress
import secrets
import socket
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import logging
from app.core.observability import metrics
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuthorizationRequestRecord, Organization, WebhookDelivery, WebhookEndpoint, WebhookStatus
from app.services.organization_context import WorkspaceContext
from app.services.plan_limits import enforce_resource_limit


class WebhookConfigurationError(Exception):
    pass


def validate_webhook_url(settings: Settings, url: str) -> None:
    """Reject credentials and internal network targets outside local development."""
    parsed = urlsplit(url)
    if parsed.username or parsed.password or not parsed.hostname:
        raise WebhookConfigurationError("Webhook URL is not allowed")
    development_mode = settings.app_env in {"local", "test"}
    if not development_mode and parsed.scheme != "https":
        raise WebhookConfigurationError("Webhook URL must use HTTPS")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port)}
    except (OSError, ValueError):
        raise WebhookConfigurationError("Webhook host could not be resolved") from None
    if development_mode:
        return
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise WebhookConfigurationError("Webhook URL is not allowed")


def derive_webhook_secret(settings: Settings, organization_id: UUID) -> str:
    master = settings.webhook_signing_key.get_secret_value()
    if len(master.encode("utf-8")) < 32:
        raise WebhookConfigurationError("Webhook signing is not configured")
    digest = hmac.new(master.encode(), str(organization_id).encode(), hashlib.sha256).hexdigest()
    return f"whsec_{digest}"


def sign_webhook(secret: str, timestamp: int, payload: bytes) -> str:
    signed = str(timestamp).encode() + b"." + payload
    return hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


def verify_webhook_signature(
    secret: str,
    signature_header: str,
    payload: bytes,
    *,
    tolerance_seconds: int = 300,
    now: datetime | None = None,
) -> bool:
    """Verify integrity and reject signatures outside the replay window."""
    try:
        values = dict(part.split("=", 1) for part in signature_header.split(","))
        timestamp = int(values["t"])
        supplied = values["v1"]
    except (KeyError, ValueError):
        return False
    checked_at = int((now or datetime.now(timezone.utc)).timestamp())
    if abs(checked_at - timestamp) > tolerance_seconds:
        return False
    expected = sign_webhook(secret, timestamp, payload)
    return hmac.compare_digest(supplied, expected)


def configure_webhook(
    db: Session, settings: Settings, context: WorkspaceContext, organization_id: UUID, url: str,
) -> tuple[WebhookEndpoint, str]:
    validate_webhook_url(settings, url)
    context.require("manage_webhooks")
    enforce_resource_limit(db, organization_id, "webhooks")
    if context.organization_id != organization_id:
        raise WebhookConfigurationError("Organization not found")
    organization = db.scalar(select(Organization).where(
        Organization.id == organization_id,
        Organization.is_active.is_(True),
    ))
    if organization is None:
        raise WebhookConfigurationError("Organization not found")
    if db.scalar(select(WebhookEndpoint).where(WebhookEndpoint.organization_id == organization_id)):
        raise WebhookConfigurationError("Webhook already configured")
    secret = derive_webhook_secret(settings, organization_id)
    endpoint = WebhookEndpoint(
        organization_id=organization_id,
        url=url,
        secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    return endpoint, secret


def deliver_authorization_webhook(
    db: Session, record: AuthorizationRequestRecord, settings: Settings,
) -> None:
    is_test = getattr(record, "environment", "production") == "sandbox"
    deliver_decision_webhook(
        db, settings, record.agent.organization_id, record.request_id, record.status.value,
        is_test=is_test,
    )


def deliver_decision_webhook(
    db: Session,
    settings: Settings,
    organization_id: UUID | None,
    request_id: str,
    status: str,
    is_test: bool = False,
) -> WebhookDelivery | None:
    if organization_id is None:
        return None
    endpoint = db.scalar(select(WebhookEndpoint).where(
        WebhookEndpoint.organization_id == organization_id,
        WebhookEndpoint.status == WebhookStatus.ACTIVE,
    ))
    if endpoint is None:
        return None
    try:
        validate_webhook_url(settings, endpoint.url)
        secret = derive_webhook_secret(settings, organization_id)
    except WebhookConfigurationError:
        return None
    if not hmac.compare_digest(endpoint.secret_hash, hashlib.sha256(secret.encode()).hexdigest()):
        return None
    event = f"authorization.{status.lower()}"
    delivery = WebhookDelivery(
        webhook_endpoint_id=endpoint.id,
        request_id=request_id,
        event_type=event,
        is_test=is_test,
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    _send_delivery(db, settings, delivery, endpoint, secret)
    return delivery


def _send_delivery(db: Session, settings: Settings, delivery: WebhookDelivery, endpoint: WebhookEndpoint, secret: str) -> None:
    status = delivery.event_type.rsplit(".", 1)[-1].upper()
    body_data = {
        "event": delivery.event_type,
        "request_id": delivery.request_id,
        "status": status,
    }
    if delivery.is_test:
        body_data["test_mode"] = True
    payload = json.dumps(body_data, separators=(",", ":"), sort_keys=True).encode()
    timestamp = int(datetime.now(timezone.utc).timestamp())
    signature = sign_webhook(secret, timestamp, payload)
    try:
        response = httpx.post(
            endpoint.url,
            content=payload,
            headers={
                "Content-Type": "application/json",
                "AgentTrust-Signature": f"t={timestamp},v1={signature}",
            },
            timeout=settings.webhook_timeout_seconds,
        )
        delivery.response_status = getattr(response, "status_code", 200)
        delivery.response_body = str(getattr(response, "text", ""))[:2000]
        response.raise_for_status()
        delivery.status = "delivered"
        delivery.delivered_at = datetime.now(timezone.utc)
        delivery.last_error = None
    except httpx.HTTPError as exc:
        metrics.event("webhook_failure")
        logging.getLogger("agenttrust.webhook").warning(
            "webhook_delivery_failed",
            extra={"event": "webhook_failure", "request_id": delivery.request_id},
        )
        if hasattr(exc, "response") and exc.response is not None:
            delivery.response_status = exc.response.status_code
            delivery.response_body = exc.response.text[:2000]
        delivery.status = "failed" if delivery.attempt_count + 1 >= settings.notification_max_delivery_attempts else "pending"
        delivery.last_error = "Delivery failed"
        delivery.next_attempt_at = datetime.now(timezone.utc) + timedelta(seconds=settings.notification_retry_base_seconds * (2 ** delivery.attempt_count)) if delivery.status == "pending" else None
    delivery.attempt_count += 1
    db.commit()
    db.refresh(delivery)


def send_test_webhook(
    db: Session, settings: Settings, endpoint_id: UUID,
    event_type: str = "authorization.approved",
) -> WebhookDelivery:
    endpoint = db.get(WebhookEndpoint, endpoint_id)
    if endpoint is None or endpoint.status != WebhookStatus.ACTIVE:
        raise WebhookConfigurationError("Webhook endpoint not found or inactive")
    secret = derive_webhook_secret(settings, endpoint.organization_id)
    test_req_id = f"req_{secrets.token_hex(12)}"
    delivery = WebhookDelivery(
        webhook_endpoint_id=endpoint.id,
        request_id=test_req_id,
        event_type=event_type,
        is_test=True,
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    _send_delivery(db, settings, delivery, endpoint, secret)
    return delivery


def retry_sandbox_webhook(
    db: Session, settings: Settings, delivery_id: UUID, organization_id: UUID,
) -> WebhookDelivery:
    delivery = db.get(WebhookDelivery, delivery_id)
    if delivery is None:
        raise WebhookConfigurationError("Delivery not found")
    endpoint = db.get(WebhookEndpoint, delivery.webhook_endpoint_id)
    if endpoint is None or endpoint.organization_id != organization_id:
        raise WebhookConfigurationError("Delivery does not belong to organization")
    if not delivery.is_test and endpoint.environment != "sandbox":
        raise WebhookConfigurationError("Only sandbox webhook deliveries can be manually retried")
    secret = derive_webhook_secret(settings, endpoint.organization_id)
    _send_delivery(db, settings, delivery, endpoint, secret)
    return delivery


def process_webhook_deliveries(db: Session, settings: Settings) -> int:
    now = datetime.now(timezone.utc)
    deliveries = list(db.scalars(select(WebhookDelivery).where(
        WebhookDelivery.status == "pending",
        (WebhookDelivery.next_attempt_at.is_(None) | (WebhookDelivery.next_attempt_at <= now)),
    ).order_by(WebhookDelivery.created_at).limit(settings.notification_worker_batch_size).with_for_update(skip_locked=True)))
    for delivery in deliveries:
        endpoint = db.get(WebhookEndpoint, delivery.webhook_endpoint_id)
        if endpoint is None or endpoint.status != WebhookStatus.ACTIVE:
            delivery.status = "failed"; delivery.last_error = "Webhook endpoint unavailable"; continue
        try:
            validate_webhook_url(settings, endpoint.url)
            secret = derive_webhook_secret(settings, endpoint.organization_id)
            if not hmac.compare_digest(endpoint.secret_hash, hashlib.sha256(secret.encode()).hexdigest()): raise WebhookConfigurationError
        except WebhookConfigurationError:
            delivery.status = "failed"; delivery.last_error = "Webhook configuration invalid"; continue
        _send_delivery(db, settings, delivery, endpoint, secret)
    db.commit()
    return len(deliveries)
