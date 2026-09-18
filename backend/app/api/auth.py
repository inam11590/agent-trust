"""Registration and JSON login routes."""

from typing import Annotated

import hashlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from uuid import UUID
from urllib.parse import urlencode
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, get_auth_settings
from app.core.config import Settings
from app.models import MFACredential, SSOConnection
from app.database.session import get_db
from app.schemas.auth import LoginRequest, MFARequiredResponse, MFAVerifyRequest, RegisterRequest, TokenResponse
from app.schemas.enterprise_security import SSOTicketExchange
from app.schemas.user import UserResponse
from app.services.auth import (
    EmailAlreadyRegistered,
    InvalidCredentials,
    authenticate_user,
    register_user,
)
from app.services.mfa import MFAError, create_challenge, verify_challenge
from app.services.sessions import issue_session, revoke_session, token_hash
from app.services.security_events import record_security_event
from app.services.sso import SSOError, complete_login, redeem_ticket, start_login

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register", response_model=UserResponse, status_code=201,
    dependencies=[Depends(get_auth_settings)],
)
def register(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> UserResponse:
    client_address = request.client.host if request.client else "unknown"
    limiter = request.app.state.auth_rate_limiter
    if not limiter.allow(("register", client_address), request.app.state.settings.auth_register_rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
    try:
        user = register_user(db, payload)
    except EmailAlreadyRegistered:
        raise HTTPException(status_code=409, detail="Email is already registered") from None
    response.headers["Cache-Control"] = "no-store"
    return UserResponse.model_validate(user)


@router.post("/login", response_model=TokenResponse | MFARequiredResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_auth_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse | MFARequiredResponse:
    client_address = request.client.host if request.client else "unknown"
    email_key = hashlib.sha256(str(payload.email).lower().encode()).hexdigest()
    limiter = request.app.state.auth_rate_limiter
    if not limiter.allow(("login", client_address, email_key), settings.auth_login_rate_limit_per_minute):
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
    try:
        user = authenticate_user(db, payload.email, payload.password.get_secret_value(), settings)
    except InvalidCredentials:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    credential = db.get(MFACredential, user.id)
    if credential is not None and credential.enabled_at is not None:
        challenge = create_challenge(db, user.id, settings)
        response.headers["Cache-Control"] = "no-store"
        return MFARequiredResponse(challenge_token=challenge, expires_in=settings.mfa_challenge_expire_minutes * 60)
    token = issue_session(db, user, settings, request, auth_method="password")
    record_security_event(db, user.id, "login_success", description="Password sign-in", commit=True)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/mfa/verify", response_model=TokenResponse)
def verify_mfa_login(
    payload: MFAVerifyRequest,
    request: Request,
    response: Response,
    settings: Annotated[Settings, Depends(get_auth_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    nonce = payload.challenge_token.get_secret_value()
    client_address = request.client.host if request.client else "unknown"
    if not request.app.state.auth_rate_limiter.allow(
        ("mfa", client_address, token_hash(nonce)), settings.mfa_rate_limit_per_minute,
    ):
        raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later")
    try:
        user, _ = verify_challenge(db, nonce, payload.code.get_secret_value(), settings)
    except MFAError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    token = issue_session(db, user, settings, request, auth_method="password+mfa", mfa_verified=True)
    record_security_event(db, user.id, "login_success", description="Two-factor sign-in", commit=True)
    response.headers["Cache-Control"] = "no-store"
    return TokenResponse(access_token=token, expires_in=settings.jwt_access_token_expire_minutes * 60)


@router.post("/logout", status_code=204)
def logout(user: CurrentUser, request: Request, db: Annotated[Session, Depends(get_db)]) -> None:
    session = getattr(request.state, "auth_session", None)
    if session is not None:
        revoke_session(db, session)
        record_security_event(db, user.id, "session_revoked", description="Signed out", commit=True)


@router.get("/sso/{organization_id}/start")
def sso_start(organization_id: UUID, request: Request, db: Annotated[Session, Depends(get_db)],
              connection_id: UUID | None = Query(default=None)):
    conditions = [SSOConnection.organization_id == organization_id, SSOConnection.status == "active"]
    if connection_id is not None:
        conditions.append(SSOConnection.id == connection_id)
    connection = db.scalar(select(SSOConnection).where(*conditions).order_by(SSOConnection.created_at.desc()))
    if connection is None:
        raise HTTPException(status_code=404, detail="Active SSO connection not found")
    try:
        location = start_login(db, connection, request.app.state.settings)
    except SSOError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    return RedirectResponse(location, status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@router.get("/sso/callback")
def sso_callback(request: Request, db: Annotated[Session, Depends(get_db)],
                 state: str = Query(min_length=40, max_length=200), code: str = Query(min_length=1, max_length=4096)):
    try:
        ticket = complete_login(db, state, code, request.app.state.settings)
    except SSOError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    location = f"{request.app.state.settings.web_app_url.rstrip('/')}/sso/callback?{urlencode({'ticket': ticket, 'state': state})}"
    return RedirectResponse(location, status_code=302, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


@router.post("/sso/exchange", response_model=TokenResponse)
def sso_exchange(payload: SSOTicketExchange, request: Request, response: Response,
                 db: Annotated[Session, Depends(get_db)]):
    try:
        user, mfa_verified = redeem_ticket(db, payload.ticket)
    except SSOError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    token = issue_session(db, user, request.app.state.settings, request, auth_method="oidc", mfa_verified=mfa_verified)
    record_security_event(db, user.id, "login_success", description="Company SSO sign-in", commit=True)
    response.headers["Cache-Control"] = "no-store"
    return TokenResponse(access_token=token, expires_in=request.app.state.settings.jwt_access_token_expire_minutes * 60)
