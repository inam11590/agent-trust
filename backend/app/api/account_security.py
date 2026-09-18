"""Account MFA, revocable sessions, and private security history."""

from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import AuthSession, MFACredential, SecurityEvent, User
from app.schemas.account_security import (
    MFACodeInput, MFACredentialStatus, MFADisableInput, MFASetupResponse,
    PaginatedSecurityEvents, RecoveryCodesResponse, SecurityEventItem,
    SessionResponse, StepUpInput, PasswordChangeInput,
)
from app.services.mfa import (
    MFAError, confirm_setup, disable_mfa, mfa_status, regenerate_recovery_codes,
    require_factor, start_setup,
)
from app.core.security import hash_password, verify_password
from app.models import NotificationPriority, NotificationType
from app.services.notification_service import create_notification
from app.services.organization_context import resolve_workspace
from app.services.security_events import record_security_event
from app.services.sessions import revoke_session

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/mfa", response_model=MFACredentialStatus)
def get_mfa_status(user: CurrentUser, response: Response, db: Annotated[Session, Depends(get_db)]):
    response.headers["Cache-Control"] = "no-store"
    return mfa_status(db, user.id)


@router.post("/mfa/setup", response_model=MFASetupResponse)
def setup_mfa(user: CurrentUser, request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    require_recent_step_up(request)
    try:
        result = start_setup(db, user, request.app.state.settings)
    except MFAError as exc:
        raise HTTPException(status_code=409 if "already" in str(exc) else 503, detail=str(exc)) from None
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/mfa/confirm", response_model=RecoveryCodesResponse)
def confirm_mfa(payload: MFACodeInput, user: CurrentUser, request: Request, response: Response,
                db: Annotated[Session, Depends(get_db)]):
    if not request.app.state.auth_rate_limiter.allow(("mfa-setup", str(user.id)), request.app.state.settings.mfa_rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later")
    try:
        codes = confirm_setup(db, user, request.app.state.settings, payload.code.get_secret_value())
    except MFAError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    current = getattr(request.state, "auth_session", None)
    now = datetime.now(timezone.utc)
    for session in db.scalars(select(AuthSession).where(
        AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None),
    ).with_for_update()):
        if current is not None and session.id == current.id:
            session.mfa_verified_at = now
            session.step_up_at = now
        else:
            session.revoked_at = now
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesResponse)
def regenerate_codes(payload: MFACodeInput, user: CurrentUser, request: Request, response: Response,
                     db: Annotated[Session, Depends(get_db)]):
    try:
        codes = regenerate_recovery_codes(db, user, payload.code.get_secret_value(), request.app.state.settings)
    except MFAError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/disable", status_code=204)
def remove_mfa(payload: MFADisableInput, user: CurrentUser, request: Request,
               db: Annotated[Session, Depends(get_db)]):
    try:
        disable_mfa(db, user, payload.password.get_secret_value(), payload.code.get_secret_value(), request.app.state.settings)
    except MFAError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None
    current = getattr(request.state, "auth_session", None)
    now = datetime.now(timezone.utc)
    for session in db.scalars(select(AuthSession).where(
        AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None),
    ).with_for_update()):
        if current is not None and session.id == current.id:
            session.mfa_verified_at = None
        else:
            session.revoked_at = now
    db.commit()


@router.post("/step-up")
def step_up(payload: StepUpInput, user: CurrentUser, request: Request,
            db: Annotated[Session, Depends(get_db)]):
    session: AuthSession | None = getattr(request.state, "auth_session", None)
    if session is None:
        raise HTTPException(status_code=401, detail="A current session is required")
    if not request.app.state.auth_rate_limiter.allow(("step-up", str(user.id)), 5):
        raise HTTPException(status_code=429, detail="Too many verification attempts")
    if not verify_password(payload.password.get_secret_value(), user.hashed_password):
        raise HTTPException(status_code=401, detail="Strong verification failed")
    credential = db.get(MFACredential, user.id)
    if credential is not None and credential.enabled_at is not None:
        if payload.code is None:
            raise HTTPException(status_code=401, detail="Authenticator code required")
        try:
            require_factor(db, user.id, payload.code.get_secret_value(), request.app.state.settings)
        except MFAError:
            raise HTTPException(status_code=401, detail="Strong verification failed") from None
    session.step_up_at = datetime.now(timezone.utc)
    db.commit()
    return {"verified": True}


@router.post("/password", status_code=204)
def change_password(payload: PasswordChangeInput, user: CurrentUser, request: Request,
                    db: Annotated[Session, Depends(get_db)]) -> None:
    if not request.app.state.auth_rate_limiter.allow(("password-change", str(user.id)), 5):
        raise HTTPException(status_code=429, detail="Too many verification attempts")
    current_password = payload.current_password.get_secret_value()
    new_password = payload.new_password.get_secret_value()
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Strong verification failed")
    if current_password == new_password:
        raise HTTPException(status_code=400, detail="Choose a different password")
    credential = db.get(MFACredential, user.id)
    if credential is not None and credential.enabled_at is not None:
        if payload.code is None:
            raise HTTPException(status_code=401, detail="Authenticator code required")
        try:
            require_factor(db, user.id, payload.code.get_secret_value(), request.app.state.settings)
        except MFAError:
            raise HTTPException(status_code=401, detail="Strong verification failed") from None
    current = getattr(request.state, "auth_session", None)
    now = datetime.now(timezone.utc)
    user.hashed_password = hash_password(new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    for session in db.scalars(select(AuthSession).where(
        AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None),
    ).with_for_update()):
        if current is not None and session.id == current.id:
            session.step_up_at = now
        else:
            session.revoked_at = now
    record_security_event(db, user.id, "password_changed", description="Account password changed", severity="warning", commit=False)
    create_notification(db, user_id=user.id, notification_type=NotificationType.SECURITY_ALERT,
        title="Password Changed", message="Your AgentTrust password was changed.", priority=NotificationPriority.HIGH)
    db.commit()


def require_recent_step_up(request: Request) -> None:
    session: AuthSession | None = getattr(request.state, "auth_session", None)
    if session is None or session.step_up_at is None or session.step_up_at < datetime.now(timezone.utc) - timedelta(minutes=5):
        raise HTTPException(status_code=403, detail="Please verify your identity again")


@router.get("/sessions", response_model=list[SessionResponse])
def sessions(user: CurrentUser, request: Request, response: Response, db: Annotated[Session, Depends(get_db)]):
    now = datetime.now(timezone.utc)
    current = getattr(request.state, "auth_session", None)
    records = db.scalars(select(AuthSession).where(
        AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None), AuthSession.expires_at > now,
    ).order_by(AuthSession.created_at.desc()).limit(100))
    response.headers["Cache-Control"] = "no-store"
    return [SessionResponse(id=item.id, device_type=item.device_type,
        user_agent_summary=item.user_agent_summary, auth_method=item.auth_method,
        created_at=item.created_at, last_active_at=item.last_active_at,
        expires_at=item.expires_at, current=bool(current and current.id == item.id)) for item in records]


@router.post("/sessions/revoke-others")
def revoke_others(user: CurrentUser, request: Request, db: Annotated[Session, Depends(get_db)]):
    current = getattr(request.state, "auth_session", None)
    if current is None:
        raise HTTPException(status_code=401, detail="A current session is required")
    records = list(db.scalars(select(AuthSession).where(
        AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None),
        AuthSession.id != current.id).with_for_update()))
    for item in records:
        item.revoked_at = datetime.now(timezone.utc)
    record_security_event(db, user.id, "sessions_revoked", description="Other sessions signed out", severity="warning", commit=False)
    db.commit()
    return {"revoked": len(records)}


@router.post("/sessions/{session_id}/revoke", status_code=204)
def revoke_one(session_id: UUID, user: CurrentUser, db: Annotated[Session, Depends(get_db)]):
    session = db.scalar(select(AuthSession).where(AuthSession.id == session_id, AuthSession.user_id == user.id).with_for_update())
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    revoke_session(db, session)
    record_security_event(db, user.id, "session_revoked", description="Session signed out", severity="warning")


@router.get("/events", response_model=PaginatedSecurityEvents)
def events(user: CurrentUser, response: Response, db: Annotated[Session, Depends(get_db)],
           organization_id: Annotated[UUID | None, Query()] = None,
           event_type: Annotated[str | None, Query(max_length=80)] = None,
           severity: Annotated[str | None, Query(pattern="^(info|warning|critical)$")] = None,
           actor_user_id: Annotated[UUID | None, Query()] = None,
           from_date: Annotated[datetime | None, Query()] = None,
           to_date: Annotated[datetime | None, Query()] = None,
           page: Annotated[int, Query(ge=1)] = 1,
           page_size: Annotated[int, Query(ge=1, le=100)] = 20):
    if organization_id is None:
        if actor_user_id is not None and actor_user_id != user.id:
            raise HTTPException(status_code=403, detail="Not allowed")
        conditions = [SecurityEvent.actor_user_id == user.id, SecurityEvent.organization_id.is_(None)]
    else:
        workspace = resolve_workspace(db, user.id, organization_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Organization not found")
        if workspace.role.value not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Not allowed")
        conditions = [SecurityEvent.organization_id == organization_id]
    if event_type: conditions.append(SecurityEvent.event_type == event_type)
    if severity: conditions.append(SecurityEvent.severity == severity)
    if actor_user_id: conditions.append(SecurityEvent.actor_user_id == actor_user_id)
    if from_date: conditions.append(SecurityEvent.created_at >= from_date)
    if to_date: conditions.append(SecurityEvent.created_at <= to_date)
    total = db.scalar(select(func.count()).select_from(SecurityEvent).where(*conditions)) or 0
    items = db.execute(select(SecurityEvent, User.full_name).outerjoin(
        User, User.id == SecurityEvent.actor_user_id,
    ).where(*conditions).order_by(
        SecurityEvent.created_at.desc(), SecurityEvent.id.desc(),
    ).offset((page - 1) * page_size).limit(page_size))
    response.headers["Cache-Control"] = "no-store"
    return PaginatedSecurityEvents(items=[SecurityEventItem.model_validate(item, from_attributes=True).model_copy(update={"actor_name": name}) for item, name in items],
        page=page, page_size=page_size, total=total)
