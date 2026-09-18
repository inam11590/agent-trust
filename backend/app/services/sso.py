"""OIDC authorization-code flow with PKCE and verified identity tokens."""

import base64
import hashlib
import hmac
import ipaddress
import secrets
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit
from uuid import UUID

import httpx
import jwt
from authlib.oidc.core import CodeIDToken
from joserfc.errors import JoseError
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import MemberStatus, OrganizationMember, OrganizationSecurityPolicy, SSOConnection, SSOLoginAttempt, SSOLoginTicket, User
from app.services.sessions import token_hash


class SSOError(Exception):
    pass


def _cipher(settings: Settings) -> Fernet:
    key = settings.mfa_encryption_key.get_secret_value()
    if not key:
        raise SSOError("Security encryption is not configured")
    return Fernet(key.encode())


def encrypt_provider_secret(settings: Settings, secret: str) -> str:
    return _cipher(settings).encrypt(secret.encode()).decode()


def check_provider_url(value: str, settings: Settings) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise SSOError("Invalid SSO provider URL") from None
    local_test = settings.app_env == "test" and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
    if not local_test and parsed.scheme != "https":
        raise SSOError("SSO provider URLs must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise SSOError("Invalid SSO provider URL")
    if local_test:
        return
    try:
        addresses = socket.getaddrinfo(parsed.hostname, port or 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise SSOError("SSO provider must have a public address")
    except (OSError, ValueError) as exc:
        raise SSOError("SSO provider address could not be verified") from exc


def fetch_discovery(connection: SSOConnection, settings: Settings) -> dict:
    check_provider_url(connection.discovery_url, settings)
    try:
        with httpx.Client(timeout=5, follow_redirects=False) as client:
            response = client.get(connection.discovery_url)
            response.raise_for_status()
            metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SSOError("SSO discovery failed") from exc
    if not isinstance(metadata, dict):
        raise SSOError("SSO discovery is incomplete")
    if metadata.get("issuer") != connection.issuer:
        raise SSOError("SSO issuer does not match")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = metadata.get(field)
        if not isinstance(value, str):
            raise SSOError("SSO discovery is incomplete")
        check_provider_url(value, settings)
    if not isinstance(metadata.get("response_types_supported"), list) or "code" not in metadata["response_types_supported"]:
        raise SSOError("SSO provider does not support authorization code")
    if not isinstance(metadata.get("code_challenge_methods_supported"), list) or "S256" not in metadata["code_challenge_methods_supported"]:
        raise SSOError("SSO provider does not support PKCE S256")
    methods = metadata.get("token_endpoint_auth_methods_supported")
    if methods is not None and (not isinstance(methods, list) or not {"client_secret_basic", "client_secret_post"}.intersection(methods)):
        raise SSOError("SSO token authentication method is unsupported")
    return metadata


def _redirect_uri(settings: Settings) -> str:
    value = f"{settings.api_public_url.rstrip('/')}/auth/sso/callback"
    parsed = urlsplit(value)
    if settings.app_env in {"staging", "production"} and parsed.scheme != "https":
        raise SSOError("API_PUBLIC_URL must use HTTPS")
    return value


def start_login(db: Session, connection: SSOConnection, settings: Settings) -> str:
    if connection.status != "active":
        raise SSOError("SSO connection is disabled")
    metadata = fetch_discovery(connection, settings)
    random_state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    state = f"{random_state}.{nonce}"
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    db.add(SSOLoginAttempt(connection_id=connection.id, state_hash=token_hash(state), nonce_hash=token_hash(nonce),
        encrypted_code_verifier=_cipher(settings).encrypt(verifier.encode()).decode(),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
    db.commit()
    query = urlencode({"response_type": "code", "client_id": connection.client_id,
        "redirect_uri": _redirect_uri(settings), "scope": "openid email profile", "state": state,
        "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
    return f"{metadata['authorization_endpoint']}?{query}"


def _validated_claims(id_token: str, connection: SSOConnection, nonce: str, jwks: dict) -> dict:
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise SSOError("SSO signing keys are invalid")
    try:
        header = jwt.get_unverified_header(id_token)
        if header.get("alg") not in {"RS256", "PS256", "ES256"} or not header.get("kid"):
            raise SSOError("Unsupported SSO identity signature")
        selected = next((item for item in jwks.get("keys", []) if item.get("kid") == header["kid"]), None)
        if selected is None or selected.get("kty") not in {"RSA", "EC"}:
            raise SSOError("SSO signing key not found")
        key = jwt.PyJWK.from_dict(selected, algorithm=header["alg"])
        claims = jwt.decode(id_token, key.key, algorithms=[header["alg"]],
            issuer=connection.issuer, audience=connection.client_id,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]}, leeway=60)
    except jwt.PyJWTError as exc:
        raise SSOError("SSO identity verification failed") from exc
    try:
        CodeIDToken(claims, header, params={"nonce": nonce, "client_id": connection.client_id}).validate(leeway=60)
    except JoseError as exc:
        raise SSOError("SSO identity claims are invalid") from exc
    if isinstance(claims.get("aud"), list) and len(claims["aud"]) > 1 and claims.get("azp") != connection.client_id:
        raise SSOError("SSO authorized party does not match")
    if claims.get("email_verified") is not True or not isinstance(claims.get("email"), str):
        raise SSOError("SSO verified email is required")
    return claims


def complete_login(db: Session, state: str, code: str, settings: Settings) -> str:
    now = datetime.now(timezone.utc)
    attempt = db.scalar(select(SSOLoginAttempt).where(SSOLoginAttempt.state_hash == token_hash(state)).with_for_update())
    if attempt is None or attempt.used_at is not None or attempt.expires_at <= now or "." not in state:
        raise SSOError("SSO state is invalid or expired")
    nonce = state.rsplit(".", 1)[1]
    if not hmac.compare_digest(attempt.nonce_hash, token_hash(nonce)):
        raise SSOError("SSO state is invalid")
    attempt.used_at = now
    db.commit()  # Burn the state before contacting the provider.
    connection = db.get(SSOConnection, attempt.connection_id)
    if connection is None or connection.status != "active":
        raise SSOError("SSO connection is disabled")
    metadata = fetch_discovery(connection, settings)
    try:
        verifier = _cipher(settings).decrypt(attempt.encrypted_code_verifier.encode()).decode()
        client_secret = _cipher(settings).decrypt(connection.encrypted_client_secret.encode()).decode()
    except (InvalidToken, UnicodeDecodeError):
        raise SSOError("SSO connection secret is unavailable") from None
    try:
        with httpx.Client(timeout=5, follow_redirects=False) as client:
            methods = metadata.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
            basic = "client_secret_basic" in methods
            token_response = client.post(metadata["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": _redirect_uri(settings),
                "client_id": connection.client_id,
                **({} if basic else {"client_secret": client_secret}),
                "code_verifier": verifier,
            }, auth=httpx.BasicAuth(connection.client_id, client_secret) if basic else None)
            token_response.raise_for_status()
            token_data = token_response.json()
            jwks_response = client.get(metadata["jwks_uri"])
            jwks_response.raise_for_status()
            jwks = jwks_response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SSOError("SSO provider verification failed") from exc
    if not isinstance(token_data, dict) or not isinstance(token_data.get("id_token"), str):
        raise SSOError("SSO identity token is missing")
    claims = _validated_claims(token_data["id_token"], connection, nonce, jwks)
    email = claims["email"].lower()
    if connection.allowed_domains and email.rsplit("@", 1)[-1] not in connection.allowed_domains:
        raise SSOError("SSO identity is not allowed for this organization")
    policy = db.get(OrganizationSecurityPolicy, connection.organization_id)
    if policy is not None and policy.allowed_email_domains and email.rsplit("@", 1)[-1] not in policy.allowed_email_domains:
        raise SSOError("SSO identity is not allowed for this organization")
    user = db.scalar(select(User).join(OrganizationMember, OrganizationMember.user_id == User.id).where(
        func.lower(User.email) == email, User.is_active.is_(True),
        OrganizationMember.organization_id == connection.organization_id,
        OrganizationMember.status == MemberStatus.ACTIVE))
    if user is None:
        raise SSOError("SSO identity is not an active organization member")
    ticket = secrets.token_urlsafe(32)
    amr = claims.get("amr")
    mfa_verified = isinstance(amr, list) and any(value in {"mfa", "otp", "hwk", "fido"} for value in amr)
    db.add(SSOLoginTicket(user_id=user.id, organization_id=connection.organization_id,
        token_hash=token_hash(ticket), mfa_verified=mfa_verified, expires_at=now + timedelta(seconds=60)))
    db.commit()
    return ticket


def redeem_ticket(db: Session, ticket: str) -> tuple[User, bool]:
    now = datetime.now(timezone.utc)
    record = db.scalar(select(SSOLoginTicket).where(SSOLoginTicket.token_hash == token_hash(ticket)).with_for_update())
    if record is None or record.used_at is not None or record.expires_at <= now:
        raise SSOError("SSO ticket is invalid or expired")
    user = db.get(User, record.user_id)
    member = db.scalar(select(OrganizationMember.id).where(
        OrganizationMember.organization_id == record.organization_id,
        OrganizationMember.user_id == record.user_id,
        OrganizationMember.status == MemberStatus.ACTIVE))
    if user is None or not user.is_active or member is None:
        raise SSOError("SSO organization access is no longer active")
    record.used_at = now
    db.commit()
    return user, record.mfa_verified
