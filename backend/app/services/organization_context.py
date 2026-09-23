"""One tenant and role context shared by every authenticated resource route."""

from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import MemberStatus, MFACredential, Organization, OrganizationMember, OrganizationRole, OrganizationSecurityPolicy

Capability = Literal[
    "read", "manage_agents", "manage_permissions", "read_audit", "decide_requests",
    "manage_keys", "use_developer_tools", "manage_webhooks", "invite_members",
    "change_roles", "remove_members", "manage_organization",
    "manage_risk_policy",
    "view_billing", "manage_billing",
    "manage_security_policy", "manage_sso",
    "discovery.read", "discovery.sources.read", "discovery.sources.manage",
    "discovery.scan", "discovery.review", "discovery.match",
    "discovery.onboard", "discovery.ignore", "discovery.export",
]

ROLE_CAPABILITIES: dict[OrganizationRole, frozenset[Capability]] = {
    OrganizationRole.OWNER: frozenset({
        "read", "manage_agents", "manage_permissions", "read_audit", "decide_requests",
        "manage_keys", "use_developer_tools", "manage_webhooks", "invite_members",
        "change_roles", "remove_members", "manage_organization",
        "manage_risk_policy",
        "view_billing", "manage_billing",
        "manage_security_policy", "manage_sso",
        "discovery.read", "discovery.sources.read", "discovery.sources.manage",
        "discovery.scan", "discovery.review", "discovery.match",
        "discovery.onboard", "discovery.ignore", "discovery.export",
    }),
    OrganizationRole.ADMIN: frozenset({
        "read", "manage_agents", "manage_permissions", "read_audit", "decide_requests",
        "manage_keys", "use_developer_tools", "manage_webhooks", "invite_members",
        "change_roles", "remove_members",
        "manage_risk_policy",
        "view_billing", "manage_billing",
        "discovery.read", "discovery.sources.read", "discovery.sources.manage",
        "discovery.scan", "discovery.review", "discovery.match",
        "discovery.onboard", "discovery.ignore", "discovery.export",
    }),
    OrganizationRole.DEVELOPER: frozenset({
        "read", "read_audit", "manage_keys", "use_developer_tools", "view_billing",
        "discovery.read", "discovery.sources.read", "discovery.review",
        "discovery.match", "discovery.onboard",
    }),
    OrganizationRole.VIEWER: frozenset({
        "read", "read_audit", "view_billing",
        "discovery.read", "discovery.sources.read",
    }),
}



@dataclass(frozen=True)
class WorkspaceContext:
    user_id: UUID
    organization_id: UUID | None
    role: OrganizationRole
    member_id: UUID | None = None

    @property
    def is_personal(self) -> bool:
        return self.organization_id is None

    def can(self, capability: Capability) -> bool:
        return self.is_personal or capability in ROLE_CAPABILITIES[self.role]

    def require(self, capability: Capability) -> None:
        if not self.can(capability):
            raise HTTPException(status_code=403, detail="You do not have permission for this action")


def resolve_workspace(
    db: Session, user_id: UUID, organization_id: UUID | None,
) -> WorkspaceContext | None:
    if organization_id is None:
        return WorkspaceContext(user_id=user_id, organization_id=None, role=OrganizationRole.OWNER)
    organization = db.scalar(select(Organization).where(
        Organization.id == organization_id, Organization.is_active.is_(True),
    ))
    if organization is None:
        return None
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.organization_id == organization_id,
        OrganizationMember.user_id == user_id,
        OrganizationMember.status == MemberStatus.ACTIVE,
    ))
    if member is not None:
        return WorkspaceContext(user_id, organization_id, member.role, member.id)
    # Existing organizations created before Step 11 remain usable by their owner.
    if organization.owner_id == user_id:
        return WorkspaceContext(user_id, organization_id, OrganizationRole.OWNER)
    return None


def enforce_organization_policy(db: Session, user: CurrentUser, request: Request, context: WorkspaceContext) -> None:
    if context.organization_id is not None:
        policy = db.get(OrganizationSecurityPolicy, context.organization_id)
        if policy is not None:
            session = getattr(request.state, "auth_session", None)
            if policy.require_mfa:
                credential = db.get(MFACredential, user.id)
                if credential is None or credential.enabled_at is None or session is None or session.mfa_verified_at is None:
                    raise HTTPException(status_code=403, detail="This organization requires MFA. Set up or use two-factor authentication to continue")
            if policy.require_sso and context.role != OrganizationRole.OWNER:
                if session is None or session.auth_method != "oidc":
                    raise HTTPException(status_code=403, detail="This organization requires company SSO")
            if session is not None:
                from datetime import datetime, timedelta, timezone
                now = datetime.now(timezone.utc)
                previous = getattr(request.state, "previous_session_last_active", session.last_active_at)
                if previous < now - timedelta(minutes=policy.session_timeout_minutes) or session.created_at < now - timedelta(minutes=policy.max_session_lifetime_minutes):
                    session.revoked_at = now
                    db.commit()
                    raise HTTPException(status_code=401, detail="Session expired under organization policy")


def get_workspace_context(
    user: CurrentUser,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    organization_id: Annotated[UUID | None, Header(alias="X-Organization-ID")] = None,
) -> WorkspaceContext:
    context = resolve_workspace(db, user.id, organization_id)
    if context is None:
        # A uniform 404 avoids confirming that another tenant exists.
        raise HTTPException(status_code=404, detail="Organization not found")
    if organization_id is not None and getattr(request.state, "policy_checked_org_id", None) != organization_id:
        enforce_organization_policy(db, user, request, context)
    return context


CurrentWorkspace = Annotated[WorkspaceContext, Depends(get_workspace_context)]
