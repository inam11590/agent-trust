"""Organization membership and secure invitation lifecycle operations."""

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    InvitationStatus,
    MemberStatus,
    Organization,
    OrganizationInvitation,
    OrganizationMember,
    OrganizationRole,
    User,
    APIKey,
    APIKeyStatus,
    OrganizationSecurityPolicy,
)
from app.schemas.organization import InvitationCreate, OrganizationCreate
from app.services.organization_context import WorkspaceContext, resolve_workspace
from app.services.security_events import record_security_event
from app.services.notification_service import create_notification
from app.models import NotificationPriority, NotificationType
from app.services.plan_limits import attach_free_subscription, enforce_resource_limit


class OrganizationAccessError(Exception):
    pass


class OrganizationConflict(Exception):
    pass


class InvitationInvalid(Exception):
    pass


class InvitationExpired(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def invitation_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def organization_context(db: Session, user_id: UUID, organization_id: UUID) -> WorkspaceContext:
    context = resolve_workspace(db, user_id, organization_id)
    if context is None:
        raise OrganizationAccessError
    return context


def create_organization(db: Session, user_id: UUID, payload: OrganizationCreate) -> Organization:
    organization = Organization(name=payload.name, owner_id=user_id)
    db.add(organization)
    db.flush()
    db.add(OrganizationMember(
        organization_id=organization.id,
        user_id=user_id,
        role=OrganizationRole.OWNER,
        invited_by=None,
    ))
    attach_free_subscription(db, organization.id)
    record_security_event(
        db, user_id, "organization.created", organization_id=organization.id,
        description="Organization created", commit=False,
    )
    db.commit()
    db.refresh(organization)
    return organization


def list_user_organizations(db: Session, user_id: UUID) -> list[tuple[Organization, OrganizationRole, MemberStatus]]:
    memberships = db.execute(
        select(Organization, OrganizationMember.role, OrganizationMember.status)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == MemberStatus.ACTIVE,
            Organization.is_active.is_(True),
        )
        .order_by(Organization.name, Organization.id)
    ).all()
    found = {organization.id for organization, _, _ in memberships}
    legacy_owned = db.scalars(select(Organization).where(
        Organization.owner_id == user_id,
        Organization.is_active.is_(True),
        Organization.id.not_in(found) if found else True,
    ).order_by(Organization.name, Organization.id))
    output = list(memberships)
    output.extend((organization, OrganizationRole.OWNER, MemberStatus.ACTIVE) for organization in legacy_owned)
    return output


def list_members(db: Session, organization_id: UUID) -> list[tuple[OrganizationMember, User]]:
    return list(db.execute(
        select(OrganizationMember, User)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == organization_id)
        .order_by(OrganizationMember.created_at, OrganizationMember.id)
    ).all())


def create_invitation(
    db: Session,
    settings: Settings,
    context: WorkspaceContext,
    payload: InvitationCreate,
) -> tuple[OrganizationInvitation, str | None]:
    context.require("invite_members")
    enforce_resource_limit(db, context.organization_id, "team members")
    email = str(payload.email).lower()
    policy = db.get(OrganizationSecurityPolicy, context.organization_id)
    if policy is not None and policy.allowed_email_domains and email.rsplit("@", 1)[-1] not in policy.allowed_email_domains:
        raise OrganizationConflict("Email domain is not allowed by organization policy")
    existing_user = db.scalar(select(User).where(func.lower(User.email) == email))
    if existing_user is not None and db.scalar(select(OrganizationMember.id).where(
        OrganizationMember.organization_id == context.organization_id,
        OrganizationMember.user_id == existing_user.id,
        OrganizationMember.status == MemberStatus.ACTIVE,
    )) is not None:
        raise OrganizationConflict("User is already a member")
    pending = db.scalar(select(OrganizationInvitation).where(
        OrganizationInvitation.organization_id == context.organization_id,
        func.lower(OrganizationInvitation.email) == email,
        OrganizationInvitation.status == InvitationStatus.PENDING,
        OrganizationInvitation.expires_at > utc_now(),
    ))
    if pending is not None:
        raise OrganizationConflict("A pending invitation already exists")
    token = secrets.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=context.organization_id,
        email=email,
        role=payload.role,
        token_hash=invitation_hash(token),
        expires_at=utc_now() + timedelta(days=settings.invitation_expire_days),
        invited_by=context.user_id,
    )
    db.add(invitation)
    db.flush()
    if existing_user is not None:
        organization = db.get(Organization, context.organization_id)
        create_notification(
            db, user_id=existing_user.id, organization_id=context.organization_id,
            notification_type=NotificationType.TEAM_INVITATION,
            title="Team Invitation",
            message=f"You have been invited to join {organization.name} on AgentTrust as {payload.role.value}.",
            priority=NotificationPriority.HIGH,
            metadata={"invitation_id": str(invitation.id)},
            deduplication_key=f"team-invitation:{invitation.id}",
        )
    record_security_event(
        db, context.user_id, "member.invited", organization_id=context.organization_id,
        description=f"Role: {payload.role.value}", commit=False,
    )
    db.commit()
    db.refresh(invitation)
    visible_token = token if settings.app_env in {"local", "test"} else None
    return invitation, visible_token


def accept_invitation(
    db: Session, settings: Settings, user: User, raw_token: str,
) -> OrganizationMember:
    now = utc_now()
    invitation = db.scalar(select(OrganizationInvitation).where(
        OrganizationInvitation.token_hash == invitation_hash(raw_token),
    ).with_for_update())
    if invitation is None or invitation.status in {InvitationStatus.REVOKED, InvitationStatus.ACCEPTED}:
        raise InvitationInvalid
    if invitation.status == InvitationStatus.EXPIRED or invitation.expires_at <= now:
        invitation.status = InvitationStatus.EXPIRED
        db.commit()
        raise InvitationExpired
    if settings.invitation_bind_email and invitation.email.lower() != user.email.lower():
        raise InvitationInvalid
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.organization_id == invitation.organization_id,
        OrganizationMember.user_id == user.id,
    ).with_for_update())
    if member is None:
        member = OrganizationMember(
            organization_id=invitation.organization_id,
            user_id=user.id,
            role=invitation.role,
            invited_by=invitation.invited_by,
            joined_at=now,
        )
        db.add(member)
    else:
        member.role = invitation.role
        member.status = MemberStatus.ACTIVE
        member.invited_by = invitation.invited_by
        member.joined_at = now
    invitation.status = InvitationStatus.ACCEPTED
    invitation.accepted_at = now
    record_security_event(
        db, user.id, "member.joined", organization_id=invitation.organization_id,
        target_user_id=user.id, description=f"Role: {invitation.role.value}", commit=False,
    )
    db.commit()
    db.refresh(member)
    return member


def revoke_invitation(
    db: Session, context: WorkspaceContext, invitation_id: UUID,
) -> OrganizationInvitation | None:
    context.require("invite_members")
    invitation = db.scalar(select(OrganizationInvitation).where(
        OrganizationInvitation.id == invitation_id,
        OrganizationInvitation.organization_id == context.organization_id,
    ).with_for_update())
    if invitation is None:
        return None
    if invitation.status != InvitationStatus.PENDING:
        raise OrganizationConflict("Invitation is no longer pending")
    invitation.status = InvitationStatus.REVOKED
    record_security_event(
        db, context.user_id, "invitation.revoked", organization_id=context.organization_id,
        description=f"Invitation: {invitation.id}", commit=False,
    )
    db.commit()
    db.refresh(invitation)
    return invitation


def change_member_role(
    db: Session, context: WorkspaceContext, member_id: UUID, role: OrganizationRole,
) -> OrganizationMember | None:
    context.require("change_roles")
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.id == member_id,
        OrganizationMember.organization_id == context.organization_id,
        OrganizationMember.status == MemberStatus.ACTIVE,
    ).with_for_update())
    if member is None:
        return None
    if member.role == OrganizationRole.OWNER:
        raise OrganizationConflict("The organization owner role cannot be changed")
    if member.user_id == context.user_id:
        raise OrganizationConflict("You cannot change your own role")
    old_role = member.role
    member.role = role
    if role == OrganizationRole.VIEWER:
        for key in db.scalars(select(APIKey).where(
            APIKey.organization_id == context.organization_id,
            APIKey.created_by_user_id == member.user_id,
            APIKey.status == APIKeyStatus.ACTIVE,
        ).with_for_update()):
            key.status = APIKeyStatus.REVOKED
            key.revoked_at = utc_now()
    record_security_event(
        db, context.user_id, "member.role_changed", organization_id=context.organization_id,
        target_user_id=member.user_id,
        description=f"{old_role.value} to {role.value}", commit=False,
    )
    create_notification(
        db, user_id=member.user_id, organization_id=context.organization_id,
        notification_type=NotificationType.SECURITY_ALERT, title="Organization Role Changed",
        message=f"Your organization role changed from {old_role.value} to {role.value}.",
        priority=NotificationPriority.HIGH, deduplication_key=f"role-change:{member.id}:{role.value}",
    )
    db.commit()
    db.refresh(member)
    return member


def remove_member(
    db: Session, context: WorkspaceContext, member_id: UUID,
) -> OrganizationMember | None:
    context.require("remove_members")
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.id == member_id,
        OrganizationMember.organization_id == context.organization_id,
        OrganizationMember.status == MemberStatus.ACTIVE,
    ).with_for_update())
    if member is None:
        return None
    if member.role == OrganizationRole.OWNER:
        raise OrganizationConflict("The organization owner cannot be removed")
    if member.user_id == context.user_id:
        raise OrganizationConflict("You cannot remove yourself")
    member.status = MemberStatus.REMOVED
    for key in db.scalars(select(APIKey).where(
        APIKey.organization_id == context.organization_id,
        APIKey.created_by_user_id == member.user_id,
        APIKey.status == APIKeyStatus.ACTIVE,
    ).with_for_update()):
        key.status = APIKeyStatus.REVOKED
        key.revoked_at = utc_now()
    record_security_event(
        db, context.user_id, "member.removed", organization_id=context.organization_id,
        target_user_id=member.user_id, description=f"Role: {member.role.value}", commit=False,
    )
    db.commit()
    db.refresh(member)
    return member
