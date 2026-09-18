"""Reusable bearer-token protection for user API routes."""

from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import decode_access_claims
from app.database.session import get_db
from app.models import User
from app.services.sessions import active_session
from datetime import datetime, timedelta, timezone
from uuid import UUID

bearer = HTTPBearer(auto_error=False)


def get_auth_settings(request: Request) -> Settings:
    settings = request.app.state.settings
    if not settings.jwt_secret_key.get_secret_value():
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    return settings


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    settings: Annotated[Settings, Depends(get_auth_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    unauthorized = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    try:
        user_id, session_nonce = decode_access_claims(credentials.credentials, settings)
    except InvalidTokenError:
        raise unauthorized from None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized
    if session_nonce is None:
        # Only pre-Step-16 local tokens remain accepted until their short JWT expiry.
        if settings.app_env not in {"local", "development", "test"}:
            raise unauthorized
        request.state.auth_session = None
    else:
        session = active_session(db, user_id, session_nonce)
        if session is None:
            raise unauthorized
        request.state.auth_session = session
        request.state.previous_session_last_active = session.last_active_at
        now = datetime.now(timezone.utc)
        if session.last_active_at < now - timedelta(minutes=1):
            session.last_active_at = now
            db.commit()
    raw_organization_id = request.path_params.get("organization_id") or request.headers.get("X-Organization-ID")
    if raw_organization_id:
        try:
            organization_id = UUID(str(raw_organization_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid organization ID") from None
        from app.services.organization_context import enforce_organization_policy, resolve_workspace
        context = resolve_workspace(db, user.id, organization_id)
        if context is not None:
            enforce_organization_policy(db, user, request, context)
            request.state.policy_checked_org_id = organization_id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
