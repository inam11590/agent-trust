"""Import all models so Alembic can discover their metadata."""

from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation, DelegationStatus
from app.models.agent_signing import AgentRequestNonce, AgentSigningKey, AgentSigningKeyStatus
from app.models.account_security import AuthSession, MFAChallenge, MFACredential, MFARecoveryCode
from app.models.enterprise_security import OrganizationSecurityPolicy, SSOConnection, SSOLoginAttempt, SSOLoginTicket
from app.models.audit_log import AuditDecision, AuditLog
from app.models.authorization_request import AuthorizationRequestRecord, AuthorizationRequestStatus
from app.models.developer import (
    APIKey,
    APIKeyStatus,
    DeveloperRequest,
    WebhookDelivery,
    WebhookEndpoint,
    WebhookStatus,
)
from app.models.organization import (
    InvitationStatus,
    MemberStatus,
    Organization,
    OrganizationInvitation,
    OrganizationMember,
    OrganizationRole,
    SecurityEvent,
)
from app.models.permission import Permission, PermissionStatus
from app.models.user import User
from app.models.notification import (
    DeliveryChannel,
    DeliveryStatus,
    Device,
    DevicePlatform,
    DeviceStatus,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationPriority,
    NotificationStatus,
    NotificationType,
)
from app.models.risk import RiskAction, RiskAssessment, RiskLevel, RiskPolicy
from app.models.billing import (
    BillingCheckout, BillingEvent, BillingEventStatus, OrganizationSubscription,
    SubscriptionPlan, SubscriptionStatus, UsageMetric, UsageRecord,
)

__all__ = [
    "Agent",
    "AgentStatus",
    "AgentDelegation",
    "DelegationStatus",
    "AgentSigningKey", "AgentSigningKeyStatus", "AgentRequestNonce",
    "AuthSession", "MFAChallenge", "MFACredential", "MFARecoveryCode",
    "OrganizationSecurityPolicy", "SSOConnection", "SSOLoginAttempt", "SSOLoginTicket",
    "AuditDecision",
    "AuditLog",
    "AuthorizationRequestRecord",
    "AuthorizationRequestStatus",
    "APIKey",
    "APIKeyStatus",
    "DeveloperRequest",
    "WebhookDelivery",
    "WebhookEndpoint",
    "WebhookStatus",
    "Organization",
    "OrganizationInvitation",
    "OrganizationMember",
    "OrganizationRole",
    "InvitationStatus",
    "MemberStatus",
    "SecurityEvent",
    "Permission",
    "PermissionStatus",
    "User",
    "DeliveryChannel", "DeliveryStatus", "Device", "DevicePlatform", "DeviceStatus",
    "Notification", "NotificationDelivery", "NotificationPreference", "NotificationPriority",
    "NotificationStatus", "NotificationType",
    "RiskAction", "RiskAssessment", "RiskLevel", "RiskPolicy",
    "BillingCheckout", "BillingEvent", "BillingEventStatus", "OrganizationSubscription",
    "SubscriptionPlan", "SubscriptionStatus", "UsageMetric", "UsageRecord",
]
