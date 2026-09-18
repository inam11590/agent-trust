"""Billing-provider boundary. Production code is deliberately sandbox-only for Step 14."""

from dataclasses import dataclass
import hashlib
import hmac
import secrets
import time
from typing import Protocol
from urllib.parse import urlencode

import httpx

from app.core.config import Settings


class BillingProviderError(Exception):
    pass


@dataclass(frozen=True)
class CheckoutSession:
    id: str
    url: str


class BillingProvider(Protocol):
    def create_customer(self, email: str) -> str: ...
    def create_checkout(self, *, price_id: str, organization_id: str, plan_code: str, user_email: str) -> CheckoutSession: ...
    def create_portal(self, customer_id: str) -> str: ...
    def cancel_subscription(self, subscription_id: str) -> None: ...
    def resume_subscription(self, subscription_id: str) -> None: ...
    def verify_webhook(self, body: bytes, signature: str) -> bool: ...


def paddle_signature(secret: str, body: bytes, timestamp: int) -> str:
    return hmac.new(secret.encode(), str(timestamp).encode() + b":" + body, hashlib.sha256).hexdigest()


def verify_paddle_signature(secret: str, body: bytes, header: str, tolerance: int) -> bool:
    if not secret:
        return False
    values: dict[str, list[str]] = {}
    try:
        for part in header.split(";"):
            key, value = part.strip().split("=", 1)
            values.setdefault(key, []).append(value)
        timestamp = int(values["ts"][0])
    except (KeyError, ValueError, IndexError):
        return False
    if abs(int(time.time()) - timestamp) > tolerance:
        return False
    expected = paddle_signature(secret, body, timestamp)
    return any(hmac.compare_digest(expected, candidate) for candidate in values.get("h1", []))


class TestBillingProvider:
    def __init__(self, settings: Settings): self.settings = settings
    def create_customer(self, email: str) -> str: return "ctm_test_" + secrets.token_hex(12)
    def create_checkout(self, *, price_id: str, organization_id: str, plan_code: str, user_email: str) -> CheckoutSession:
        session_id = "txn_test_" + secrets.token_hex(12)
        query = urlencode({"test_checkout": session_id, "plan": plan_code})
        return CheckoutSession(session_id, f"{self.settings.web_app_url.rstrip('/')}/dashboard/billing?{query}")
    def create_portal(self, customer_id: str) -> str:
        return f"{self.settings.web_app_url.rstrip('/')}/dashboard/billing?test_portal=1"
    def cancel_subscription(self, subscription_id: str) -> None: return None
    def resume_subscription(self, subscription_id: str) -> None: return None
    def verify_webhook(self, body: bytes, signature: str) -> bool:
        return verify_paddle_signature(self.settings.billing_webhook_secret.get_secret_value(), body, signature, self.settings.billing_webhook_tolerance_seconds)


class PaddleSandboxProvider:
    """Minimal Paddle client locked to sandbox-api.paddle.com."""
    def __init__(self, settings: Settings):
        if settings.billing_paddle_api_url.rstrip("/") != "https://sandbox-api.paddle.com":
            raise BillingProviderError("Only Paddle sandbox is allowed")
        self.settings = settings
        self.base = settings.billing_paddle_api_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {settings.billing_secret_key.get_secret_value()}", "Content-Type": "application/json"}
    def _post(self, path: str, payload: dict) -> dict:
        try:
            response = httpx.post(self.base + path, headers=self.headers, json=payload, timeout=10)
            response.raise_for_status()
            return response.json()["data"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise BillingProviderError("Sandbox billing provider request failed") from exc
    def _patch(self, path: str, payload: dict) -> dict:
        try:
            response = httpx.patch(self.base + path, headers=self.headers, json=payload, timeout=10)
            response.raise_for_status(); return response.json()["data"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise BillingProviderError("Sandbox billing provider request failed") from exc
    def create_customer(self, email: str) -> str:
        return self._post("/customers", {"email": email})["id"]
    def create_checkout(self, *, price_id: str, organization_id: str, plan_code: str, user_email: str) -> CheckoutSession:
        data = self._post("/transactions", {"items": [{"price_id": price_id, "quantity": 1}], "collection_mode": "automatic", "custom_data": {"organization_id": organization_id, "plan_code": plan_code}})
        url = (data.get("checkout") or {}).get("url")
        if not url: raise BillingProviderError("Sandbox checkout URL was unavailable")
        return CheckoutSession(data["id"], url)
    def create_portal(self, customer_id: str) -> str:
        data = self._post(f"/customers/{customer_id}/portal-sessions", {})
        return data["urls"]["general"]["overview"]
    def cancel_subscription(self, subscription_id: str) -> None:
        self._post(f"/subscriptions/{subscription_id}/cancel", {"effective_from": "next_billing_period"})
    def resume_subscription(self, subscription_id: str) -> None:
        self._patch(f"/subscriptions/{subscription_id}", {"scheduled_change": None})
    def verify_webhook(self, body: bytes, signature: str) -> bool:
        return verify_paddle_signature(self.settings.billing_webhook_secret.get_secret_value(), body, signature, self.settings.billing_webhook_tolerance_seconds)


def provider_for(settings: Settings) -> BillingProvider:
    if settings.billing_provider == "paddle_sandbox": return PaddleSandboxProvider(settings)
    if settings.billing_provider == "test": return TestBillingProvider(settings)
    raise BillingProviderError("Billing checkout is disabled")
