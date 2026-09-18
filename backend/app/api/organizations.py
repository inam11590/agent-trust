"""Organization workspaces, members, invitations, roles, and security events."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import OrganizationInvitation, OrganizationMember, User
from app.schemas.organization import (
    InvitationAccept,
    InvitationCreate,
    InvitationResponse,
    MemberResponse,
    MemberRoleUpdate,
    OrganizationCreate,
    OrganizationSummary,
    SecurityEventResponse,
)
from app.services.organizations import (
    InvitationExpired,
    InvitationInvalid,
    OrganizationAccessError,
    OrganizationConflict,
    accept_invitation,
    change_member_role,
    create_invitation,
    create_organization,
    list_members,
    list_user_organizations,
    organization_context,
    remove_member,
    revoke_invitation,
)
from app.services.security_events import list_security_events

router = APIRouter(tags=["organizations"])


def _member(member: OrganizationMember, user: User) -> MemberResponse:
    return MemberResponse(
        id=member.id,
        organization_id=member.organization_id,
        user_id=member.user_id,
        full_name=user.full_name,
        email=user.email,
        role=member.role,
        status=member.status,
        joined_at=member.joined_at,
        created_at=member.created_at,
    )


def _invitation(invitation: OrganizationInvitation, invitation_url: str | None = None) -> InvitationResponse:
    return InvitationResponse(
        id=invitation.id,
        organization_id=invitation.organization_id,
        email=invitation.email,
        role=invitation.role,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        accepted_at=invitation.accepted_at,
        invitation_url=invitation_url,
    )


def _context(db: Session, user_id: UUID, organization_id: UUID):
    try:
        return organization_context(db, user_id, organization_id)
    except OrganizationAccessError:
        raise HTTPException(status_code=404, detail="Organization not found") from None


@router.post("/organizations", response_model=OrganizationSummary, status_code=201)
def add_organization(
    payload: OrganizationCreate,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> OrganizationSummary:
    organization = create_organization(db, user.id, payload)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Location"] = f"/organizations/{organization.id}"
    return OrganizationSummary(
        id=organization.id, name=organization.name, role="owner", status="active",
        created_at=organization.created_at,
    )


@router.get("/organizations", response_model=list[OrganizationSummary])
def get_organizations(
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> list[OrganizationSummary]:
    response.headers["Cache-Control"] = "no-store"
    return [
        OrganizationSummary(
            id=organization.id, name=organization.name, role=role,
            status=status, created_at=organization.created_at,
        )
        for organization, role, status in list_user_organizations(db, user.id)
    ]


@router.get("/organizations/{organization_id}/members", response_model=list[MemberResponse])
def get_members(
    organization_id: UUID,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> list[MemberResponse]:
    context = _context(db, user.id, organization_id)
    context.require("read")
    response.headers["Cache-Control"] = "no-store"
    return [_member(member, member_user) for member, member_user in list_members(db, organization_id)]


@router.post(
    "/organizations/{organization_id}/invitations",
    response_model=InvitationResponse,
    status_code=201,
)
def invite_member(
    organization_id: UUID,
    payload: InvitationCreate,
    request: Request,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> InvitationResponse:
    context = _context(db, user.id, organization_id)
    try:
        invitation, token = create_invitation(db, request.app.state.settings, context, payload)
    except OrganizationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    link = None
    if token is not None:
        base = request.app.state.settings.web_app_url.rstrip("/")
        link = f"{base}/invite/accept?token={token}"
    response.headers["Cache-Control"] = "no-store"
    return _invitation(invitation, link)


@router.post("/invitations/accept", response_model=MemberResponse)
def accept_member_invitation(
    payload: InvitationAccept,
    request: Request,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> MemberResponse:
    try:
        member = accept_invitation(db, request.app.state.settings, user, payload.token)
    except InvitationExpired:
        raise HTTPException(status_code=410, detail="Invitation has expired") from None
    except InvitationInvalid:
        raise HTTPException(status_code=400, detail="Invitation is invalid") from None
    response.headers["Cache-Control"] = "no-store"
    return _member(member, user)


@router.post(
    "/organizations/{organization_id}/invitations/{invitation_id}/revoke",
    response_model=InvitationResponse,
)
def revoke_member_invitation(
    organization_id: UUID,
    invitation_id: UUID,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> InvitationResponse:
    context = _context(db, user.id, organization_id)
    try:
        invitation = revoke_invitation(db, context, invitation_id)
    except OrganizationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if invitation is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    response.headers["Cache-Control"] = "no-store"
    return _invitation(invitation)


@router.patch(
    "/organizations/{organization_id}/members/{member_id}",
    response_model=MemberResponse,
)
def update_member_role(
    organization_id: UUID,
    member_id: UUID,
    payload: MemberRoleUpdate,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> MemberResponse:
    context = _context(db, user.id, organization_id)
    try:
        member = change_member_role(db, context, member_id, payload.role)
    except OrganizationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    member_user = db.get(User, member.user_id)
    response.headers["Cache-Control"] = "no-store"
    return _member(member, member_user)


@router.delete("/organizations/{organization_id}/members/{member_id}", status_code=204)
def delete_member(
    organization_id: UUID,
    member_id: UUID,
    user: CurrentUser,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    context = _context(db, user.id, organization_id)
    try:
        member = remove_member(db, context, member_id)
    except OrganizationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


@router.get(
    "/organizations/{organization_id}/security-events",
    response_model=list[SecurityEventResponse],
)
def get_security_events(
    organization_id: UUID,
    user: CurrentUser,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> list[SecurityEventResponse]:
    context = _context(db, user.id, organization_id)
    context.require("read_audit")
    response.headers["Cache-Control"] = "no-store"
    return [SecurityEventResponse.model_validate(event) for event in list_security_events(db, organization_id)]
