"""Small, replaceable email and Firebase Cloud Messaging providers."""

from dataclasses import dataclass
import json
from urllib import error, request

from app.core.config import Settings


class DeliveryProviderError(Exception):
    """Safe provider failure; the message must never contain credentials or response bodies."""


@dataclass(frozen=True)
class DeliveryResult:
    message_id: str | None = None


class EmailProvider:
    def send(self, *, to: str, subject: str, body: str) -> DeliveryResult:
        raise NotImplementedError


class DevelopmentEmailProvider(EmailProvider):
    """Local preview provider. It performs no network call and logs no content."""

    def send(self, *, to: str, subject: str, body: str) -> DeliveryResult:
        return DeliveryResult(message_id="development-preview")


class DisabledEmailProvider(EmailProvider):
    def send(self, *, to: str, subject: str, body: str) -> DeliveryResult:
        raise DeliveryProviderError("Email provider is not configured")


class PushProvider:
    def send(self, *, token: str, title: str, body: str, data: dict[str, str]) -> DeliveryResult:
        raise NotImplementedError


class FirebasePushProvider(PushProvider):
    """FCM HTTP v1 transport using a short-lived access token supplied by the worker environment."""

    def __init__(self, settings: Settings):
        self.project_id = settings.fcm_project_id
        self.access_token = settings.fcm_access_token.get_secret_value()
        self.timeout = settings.notification_delivery_timeout_seconds

    def send(self, *, token: str, title: str, body: str, data: dict[str, str]) -> DeliveryResult:
        if not self.project_id or not self.access_token:
            raise DeliveryProviderError("Push provider is not configured")
        payload = json.dumps({"message": {
            "token": token,
            "notification": {"title": title, "body": body},
            "data": data,
            "android": {"priority": "high"},
            "apns": {"headers": {"apns-priority": "10"}},
        }}).encode()
        req = request.Request(
            f"https://fcm.googleapis.com/v1/projects/{self.project_id}/messages:send",
            data=payload, method="POST",
            headers={"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read(8192))
                return DeliveryResult(message_id=str(result.get("name")) if result.get("name") else None)
        except (error.URLError, TimeoutError, ValueError):
            raise DeliveryProviderError("Push provider request failed") from None


def email_provider(settings: Settings) -> EmailProvider:
    if settings.email_provider == "development" and settings.app_env != "production":
        return DevelopmentEmailProvider()
    return DisabledEmailProvider()
