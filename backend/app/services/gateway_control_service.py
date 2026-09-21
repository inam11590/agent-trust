"""Control Plane service for Enterprise Gateways and Signed Configuration Bundles (Step 23).

Handles:
- Secure one-time enrollment token lifecycle
- Gateway public key binding
- Mutual cryptographic authentication (Heartbeats and Config verification)
- Versioned, signed configuration bundle publisher (monotonically ordered)
- Anti-rollback enforcement
- Emergency revocation and suspension
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.cross_organization_trust import (
    OrganizationTrustPolicy,
    OrganizationTrustRelationship,
    TargetOrganizationPolicy,
    TrustStatus,
)
from app.models.enterprise_gateway import (
    EnterpriseGateway,
    GatewayConfigBundle,
    GatewayDeploymentType,
    GatewayEnvironment,
    GatewayOfflinePolicy,
    GatewayStatus,
    generate_enrollment_token,
    generate_gateway_id,
)
from app.models.organization import Organization, SecurityEvent
from app.models.trust_registry import (
    AgentCredential,
    CredentialIssuer,
    CredentialStatus,
    IssuerKeyStatus,
    IssuerSigningKey,
    IssuerStatus,
)
from app.schemas.enterprise_gateways import (
    GatewayEnrollRequest,
    GatewayHeartbeatRequest,
    GatewayPublishConfigRequest,
    GatewayRegistrationRequest,
    GatewayRollbackRequest,
)

CONFIG_SIGNING_VERSION = "AGENTTRUST-CONFIG/1"
HEARTBEAT_SIGNING_VERSION = "AGENTTRUST-HEARTBEAT/1"
CONTROL_PLANE_KEY_ID = "cp_key_primary"

_KEY_DIR = Path(__file__).resolve().parents[2] / ".control_plane_keys"
_KEY_FILE = _KEY_DIR / "control_plane_ed25519.pem"

_cp_private_key: Optional[Ed25519PrivateKey] = None
_cp_public_key: Optional[Ed25519PublicKey] = None


class GatewayControlError(Exception):
    def __init__(self, message: str, code: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def _ensure_control_plane_keys() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Retrieve or generate Control Plane Ed25519 keypair for signing configuration bundles."""
    global _cp_private_key, _cp_public_key
    if _cp_private_key is not None and _cp_public_key is not None:
        return _cp_private_key, _cp_public_key

    # Check env var first
    env_pem = os.environ.get("CONTROL_PLANE_PRIVATE_KEY_PEM")
    if env_pem:
        try:
            priv = load_pem_private_key(env_pem.encode("utf-8"), password=None)
            if isinstance(priv, Ed25519PrivateKey):
                _cp_private_key = priv
                _cp_public_key = priv.public_key()
                return _cp_private_key, _cp_public_key
        except Exception:
            pass

    # Check on-disk protected key
    if _KEY_FILE.exists():
        try:
            pem_bytes = _KEY_FILE.read_bytes()
            priv = load_pem_private_key(pem_bytes, password=None)
            if isinstance(priv, Ed25519PrivateKey):
                _cp_private_key = priv
                _cp_public_key = priv.public_key()
                return _cp_private_key, _cp_public_key
        except Exception:
            pass

    # Generate new keypair
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem_bytes = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    _KEY_FILE.write_bytes(pem_bytes)
    try:
        os.chmod(_KEY_FILE, 0o600)
    except OSError:
        pass

    _cp_private_key = priv
    _cp_public_key = pub
    return _cp_private_key, _cp_public_key


def get_control_plane_public_key_b64() -> Tuple[str, str]:
    """Return Base64-encoded Control Plane public key and key_id."""
    _, pub = _ensure_control_plane_keys()
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii"), CONTROL_PLANE_KEY_ID


def register_enterprise_gateway(
    db: Session,
    org_id: UUID,
    req: GatewayRegistrationRequest,
) -> Tuple[EnterpriseGateway, str, str]:
    """
    Register a new Enterprise Gateway or Sidecar.
    Returns (gateway, raw_enrollment_token, enrollment_command).
    Only the SHA-256 hash of the enrollment token is persisted.
    """
    org = db.get(Organization, org_id)
    if not org or not org.is_active:
        raise GatewayControlError("Organization not found or inactive.", code="ORGANIZATION_NOT_FOUND", status_code=404)

    raw_token = generate_enrollment_token()
    token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    gateway = EnterpriseGateway(
        gateway_id=generate_gateway_id(),
        organization_id=org_id,
        name=req.name.strip(),
        deployment_type=req.deployment_type,
        environment=req.environment,
        status=GatewayStatus.ENROLLING.value,
        enrollment_token_hash=token_hash,
        enrollment_token_expires_at=expires_at,
        labels=req.labels or {},
        offline_policy=req.offline_policy,
    )
    db.add(gateway)
    db.commit()
    db.refresh(gateway)

    enrollment_cmd = (
        f"agenttrust gateway enroll "
        f"--gateway-id {gateway.gateway_id} "
        f"--token {raw_token} "
        f"--environment {gateway.environment}"
    )

    db.add(SecurityEvent(
        organization_id=org_id,
        event_type="gateway_registered",
        severity="info",
        description=f"Registered enterprise gateway '{gateway.name}' ({gateway.gateway_id}).",
        details={"gateway_id": gateway.gateway_id, "deployment_type": gateway.deployment_type},
    ))
    db.commit()

    return gateway, raw_token, enrollment_cmd


def enroll_enterprise_gateway(
    db: Session,
    gateway_id_str: str,
    req: GatewayEnrollRequest,
) -> Dict[str, Any]:
    """
    Process enrollment from a self-hosted Gateway.
    Verifies the one-time token, stores the Gateway's locally generated Ed25519 public key,
    activates the Gateway, and returns the Control Plane's public key.
    """
    gateway = db.execute(
        select(EnterpriseGateway).where(EnterpriseGateway.gateway_id == gateway_id_str)
    ).scalar_one_or_none()

    if not gateway:
        raise GatewayControlError(
            f"Gateway '{gateway_id_str}' not found.",
            code="GATEWAY_NOT_FOUND",
            status_code=404,
        )

    if gateway.status in (GatewayStatus.REVOKED.value, GatewayStatus.SUSPENDED.value):
        raise GatewayControlError(
            f"Gateway '{gateway_id_str}' has been {gateway.status.lower()} and cannot be enrolled.",
            code="GATEWAY_REVOKED",
            status_code=403,
        )

    now_utc = datetime.now(timezone.utc)
    if not gateway.enrollment_token_hash or not gateway.enrollment_token_expires_at:
        raise GatewayControlError(
            "Enrollment token already consumed or invalid.",
            code="ENROLLMENT_TOKEN_INVALID",
            status_code=401,
        )

    if gateway.enrollment_token_expires_at < now_utc:
        raise GatewayControlError(
            "Enrollment token has expired. Generate a new token in the Control Plane.",
            code="ENROLLMENT_TOKEN_EXPIRED",
            status_code=401,
        )

    provided_hash = hashlib.sha256(req.enrollment_token.strip().encode("ascii")).hexdigest()
    if not secrets.compare_digest(provided_hash, gateway.enrollment_token_hash):
        db.add(SecurityEvent(
            organization_id=gateway.organization_id,
            event_type="gateway_enrollment_failed",
            severity="warning",
            description=f"Invalid enrollment token presented for gateway '{gateway_id_str}'.",
            details={"gateway_id": gateway_id_str},
        ))
        db.commit()
        raise GatewayControlError(
            "Invalid enrollment token.",
            code="ENROLLMENT_TOKEN_INVALID",
            status_code=401,
        )

    # Validate Ed25519 public key
    try:
        raw_pub = base64.b64decode(req.public_key.strip())
        if len(raw_pub) != 32:
            raise ValueError("Key must be 32 raw bytes.")
        Ed25519PublicKey.from_public_bytes(raw_pub)
    except Exception as exc:
        raise GatewayControlError(
            f"Invalid Ed25519 public key: {exc}",
            code="INVALID_PUBLIC_KEY",
            status_code=400,
        )

    fingerprint = hashlib.sha256(raw_pub).hexdigest()

    # Consume single-use token and activate gateway
    gateway.public_key = req.public_key.strip()
    gateway.fingerprint = fingerprint
    gateway.status = GatewayStatus.ACTIVE.value
    gateway.version = req.version or gateway.version
    gateway.enrollment_token_hash = None
    gateway.enrollment_token_expires_at = None
    gateway.last_seen_at = now_utc
    if req.labels:
        merged_labels = dict(gateway.labels or {})
        merged_labels.update(req.labels)
        gateway.labels = merged_labels

    db.add(SecurityEvent(
        organization_id=gateway.organization_id,
        event_type="gateway_enrolled",
        severity="info",
        description=f"Enterprise gateway '{gateway_id_str}' enrolled successfully.",
        details={"gateway_id": gateway_id_str, "fingerprint": fingerprint},
    ))
    db.commit()
    db.refresh(gateway)

    cp_pub_b64, cp_key_id = get_control_plane_public_key_b64()

    # Check or generate initial config
    latest_bundle = db.execute(
        select(GatewayConfigBundle)
        .where(
            GatewayConfigBundle.organization_id == gateway.organization_id,
            GatewayConfigBundle.environment == gateway.environment.lower(),
        )
        .order_by(GatewayConfigBundle.config_version.desc())
    ).scalars().first()

    initial_ver = latest_bundle.config_version if latest_bundle else 0

    return {
        "status": "ACTIVE",
        "gateway_id": gateway.gateway_id,
        "organization_id": str(gateway.organization_id),
        "environment": gateway.environment,
        "control_plane_public_key": cp_pub_b64,
        "control_plane_signing_key_id": cp_key_id,
        "initial_config_version": initial_ver,
    }


def verify_gateway_heartbeat(
    db: Session,
    gateway_id_str: str,
    req: GatewayHeartbeatRequest,
) -> Dict[str, Any]:
    """
    Process periodic heartbeat sent by an active Gateway.
    Verifies the gateway's cryptographic signature on the heartbeat,
    updates health telemetry and timestamps, and returns sync indicators.
    """
    gateway = db.execute(
        select(EnterpriseGateway).where(EnterpriseGateway.gateway_id == gateway_id_str)
    ).scalar_one_or_none()

    if not gateway:
        raise GatewayControlError(f"Gateway '{gateway_id_str}' not found.", code="GATEWAY_NOT_FOUND", status_code=404)

    if gateway.status == GatewayStatus.REVOKED.value:
        raise GatewayControlError(f"Gateway '{gateway_id_str}' has been revoked.", code="GATEWAY_REVOKED", status_code=403)

    if gateway.status == GatewayStatus.SUSPENDED.value:
        raise GatewayControlError(f"Gateway '{gateway_id_str}' is suspended.", code="GATEWAY_SUSPENDED", status_code=403)

    if not gateway.public_key:
        raise GatewayControlError("Gateway has not completed enrollment.", code="GATEWAY_NOT_ENROLLED", status_code=400)

    # 1. Clock skew check (300 seconds)
    now_utc = datetime.now(timezone.utc)
    try:
        hb_ts_str = req.timestamp.strip()
        if hb_ts_str.endswith("Z"):
            hb_ts_str = hb_ts_str[:-1] + "+00:00"
        hb_time = datetime.fromisoformat(hb_ts_str)
        if hb_time.tzinfo is None:
            hb_time = hb_time.replace(tzinfo=timezone.utc)
        skew = abs((now_utc - hb_time).total_seconds())
        if skew > 300:
            raise ValueError(f"Clock skew ({skew:.1f}s) exceeds 300s.")
    except Exception as exc:
        raise GatewayControlError(f"Invalid heartbeat timestamp: {exc}", code="INVALID_TIMESTAMP", status_code=400)

    # 2. Cryptographic signature check
    canon_bytes = f"{HEARTBEAT_SIGNING_VERSION}\n{gateway_id_str}\n{req.config_version}\n{req.timestamp}\n".encode("utf-8")
    try:
        pub_raw = base64.b64decode(gateway.public_key)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig_raw = base64.b64decode(req.signature)
        pub_key.verify(sig_raw, canon_bytes)
    except (InvalidSignature, Exception) as exc:
        db.add(SecurityEvent(
            organization_id=gateway.organization_id,
            event_type="gateway_heartbeat_signature_invalid",
            severity="warning",
            description=f"Heartbeat signature failed verification for gateway '{gateway_id_str}'.",
            details={"gateway_id": gateway_id_str},
        ))
        db.commit()
        raise GatewayControlError(
            "Heartbeat Ed25519 cryptographic signature invalid.",
            code="INVALID_SIGNATURE",
            status_code=401,
        ) from exc

    # 3. Update gateway telemetry
    gateway.last_seen_at = now_utc
    gateway.last_heartbeat_data = req.health
    gateway.config_version = req.config_version
    gateway.version = req.version
    if gateway.status in (GatewayStatus.OFFLINE.value, GatewayStatus.DEGRADED.value):
        gateway.status = GatewayStatus.ACTIVE.value

    db.commit()

    # 4. Check if newer config version is available
    latest_bundle = db.execute(
        select(GatewayConfigBundle)
        .where(
            GatewayConfigBundle.organization_id == gateway.organization_id,
            GatewayConfigBundle.environment == gateway.environment.lower(),
        )
        .order_by(GatewayConfigBundle.config_version.desc())
    ).scalars().first()

    latest_ver = latest_bundle.config_version if latest_bundle else 0
    sync_required = latest_ver > req.config_version

    return {
        "status": gateway.status,
        "latest_config_version": latest_ver,
        "sync_required": sync_required,
        "control_plane_time": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_and_publish_config(
    db: Session,
    org_id: UUID,
    req: GatewayPublishConfigRequest,
    user_id: Optional[UUID] = None,
) -> GatewayConfigBundle:
    """
    Compile, monotonically order, cryptographically sign, and publish a configuration bundle.
    """
    env = req.environment.lower()
    now_utc = datetime.now(timezone.utc)
    validity_hours = req.validity_hours or 24
    expires_at = now_utc + timedelta(hours=validity_hours)

    # 1. Monotonic version calculation
    latest_bundle = db.execute(
        select(GatewayConfigBundle)
        .where(
            GatewayConfigBundle.organization_id == org_id,
            GatewayConfigBundle.environment == env,
        )
        .order_by(GatewayConfigBundle.config_version.desc())
    ).scalars().first()

    new_version = (latest_bundle.config_version + 1) if latest_bundle else 1

    # 2. Gather authoritative configuration components
    policies = req.policies or []
    if not policies:
        # Default policies from database
        target_policy = db.execute(
            select(TargetOrganizationPolicy).where(TargetOrganizationPolicy.organization_id == org_id)
        ).scalar_one_or_none()
        if target_policy:
            policies.append({
                "allowed_actions": target_policy.allowed_actions,
                "allowed_resources": target_policy.allowed_resources,
                "required_credential_types": target_policy.required_credential_types or [],
            })

        # Include active published APL/1.0 policies
        try:
            from app.models.policy import Policy, PolicyVersion
            published_apl = db.execute(
                select(PolicyVersion)
                .join(Policy, PolicyVersion.policy_id == Policy.id)
                .where(
                    Policy.organization_id == org_id,
                    PolicyVersion.is_active.is_(True),
                )
            ).scalars().all()
            for pv in published_apl:
                if isinstance(pv.compiled_ast, dict):
                    policies.append(pv.compiled_ast)
        except Exception:
            pass

    trusted_issuers = req.trusted_issuers or []
    if not trusted_issuers:
        issuers = db.scalars(
            select(CredentialIssuer).where(
                CredentialIssuer.organization_id == org_id,
                CredentialIssuer.status == IssuerStatus.ACTIVE.value,
            )
        ).all()
        for iss in issuers:
            # Include active public keys
            keys = db.scalars(
                select(IssuerSigningKey).where(
                    IssuerSigningKey.issuer_id == iss.id,
                    IssuerSigningKey.status == IssuerKeyStatus.ACTIVE.value,
                )
            ).all()
            trusted_issuers.append({
                "issuer_id": iss.issuer_id,
                "name": iss.name,
                "signing_keys": [
                    {
                        "key_id": k.key_id,
                        "algorithm": k.algorithm,
                        "public_key": k.public_key,
                        "fingerprint": k.fingerprint,
                    }
                    for k in keys
                ],
            })

    credential_requirements = req.credential_requirements or []
    revocations = req.revocations or []
    if not revocations:
        # Include revoked credentials
        rev_creds = db.scalars(
            select(AgentCredential.credential_id).where(
                AgentCredential.organization_id == org_id,
                AgentCredential.status == CredentialStatus.REVOKED.value,
            )
        ).all()
        revocations.extend([{"type": "credential", "id": cid} for cid in rev_creds])

    routing = req.routing or {"allowed_peer_gateways": ["*"], "privacy_mode": "DIRECT_PRIVATE"}

    bundle_dict = {
        "policies": policies,
        "trusted_issuers": trusted_issuers,
        "credential_requirements": credential_requirements,
        "revocations": revocations,
        "routing": routing,
    }

    # 3. Canonical hash and signature
    bundle_json_str = json.dumps(bundle_dict, sort_keys=True, separators=(",", ":"))
    bundle_sha256 = hashlib.sha256(bundle_json_str.encode("utf-8")).hexdigest()

    issued_at_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at_iso = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    canon_to_sign = (
        f"{CONFIG_SIGNING_VERSION}\n"
        f"{new_version}\n"
        f"{str(org_id)}\n"
        f"{env}\n"
        f"{issued_at_iso}\n"
        f"{expires_at_iso}\n"
        f"{bundle_sha256}\n"
    ).encode("utf-8")

    cp_priv, _ = _ensure_control_plane_keys()
    sig_bytes = cp_priv.sign(canon_to_sign)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    bundle_record = GatewayConfigBundle(
        organization_id=org_id,
        environment=env,
        config_version=new_version,
        bundle_json=bundle_dict,
        bundle_sha256=bundle_sha256,
        signature=sig_b64,
        signing_key_id=CONTROL_PLANE_KEY_ID,
        published_by_user_id=user_id,
        created_at=now_utc,
        expires_at=expires_at,
    )
    db.add(bundle_record)
    db.commit()
    db.refresh(bundle_record)

    db.add(SecurityEvent(
        organization_id=org_id,
        event_type="gateway_config_published",
        severity="info",
        description=f"Published signed configuration bundle version {new_version} for environment '{env}'.",
        details={"config_version": new_version, "bundle_sha256": bundle_sha256},
    ))
    db.commit()

    return bundle_record


def rollback_gateway_config(
    db: Session,
    org_id: UUID,
    req: GatewayRollbackRequest,
    user_id: Optional[UUID] = None,
) -> GatewayConfigBundle:
    """
    Roll back configuration to an earlier version by publishing its contents
    under a strictly NEW, higher monotonic version number.
    Preserves anti-rollback security invariant.
    """
    target_bundle = db.execute(
        select(GatewayConfigBundle).where(
            GatewayConfigBundle.organization_id == org_id,
            GatewayConfigBundle.config_version == req.target_version,
        )
    ).scalar_one_or_none()

    if not target_bundle:
        raise GatewayControlError(
            f"Historical configuration version {req.target_version} not found.",
            code="CONFIG_VERSION_NOT_FOUND",
            status_code=404,
        )

    # Publish target content under new monotonic version
    pub_req = GatewayPublishConfigRequest(
        environment=target_bundle.environment,
        policies=target_bundle.bundle_json.get("policies"),
        trusted_issuers=target_bundle.bundle_json.get("trusted_issuers"),
        credential_requirements=target_bundle.bundle_json.get("credential_requirements"),
        revocations=target_bundle.bundle_json.get("revocations"),
        routing=target_bundle.bundle_json.get("routing"),
    )
    new_bundle = build_and_publish_config(db, org_id, pub_req, user_id=user_id)

    db.add(SecurityEvent(
        organization_id=org_id,
        event_type="gateway_config_rolled_back",
        severity="warning",
        description=(
            f"Rolled back configuration: content from version {req.target_version} "
            f"re-published as new monotonic version {new_bundle.config_version}."
        ),
        details={"source_version": req.target_version, "new_version": new_bundle.config_version},
    ))
    db.commit()

    return new_bundle


def get_signed_config_bundle(
    db: Session,
    gateway_id_str: str,
    client_version: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Retrieve latest signed configuration bundle for an enterprise gateway.
    Returns None if client already has the latest version (ETag/304 equivalent).
    """
    gateway = db.execute(
        select(EnterpriseGateway).where(EnterpriseGateway.gateway_id == gateway_id_str)
    ).scalar_one_or_none()

    if not gateway:
        raise GatewayControlError(f"Gateway '{gateway_id_str}' not found.", code="GATEWAY_NOT_FOUND", status_code=404)

    if gateway.status in (GatewayStatus.REVOKED.value, GatewayStatus.SUSPENDED.value):
        raise GatewayControlError(
            f"Gateway '{gateway_id_str}' is {gateway.status.lower()} and cannot receive configuration.",
            code="GATEWAY_REVOKED",
            status_code=403,
        )

    latest_bundle = db.execute(
        select(GatewayConfigBundle)
        .where(
            GatewayConfigBundle.organization_id == gateway.organization_id,
            GatewayConfigBundle.environment == gateway.environment.lower(),
        )
        .order_by(GatewayConfigBundle.config_version.desc())
    ).scalars().first()

    if not latest_bundle:
        # Auto-create version 1 default configuration bundle
        pub_req = GatewayPublishConfigRequest(environment=gateway.environment.lower())
        latest_bundle = build_and_publish_config(db, gateway.organization_id, pub_req)

    if client_version is not None and client_version >= latest_bundle.config_version:
        return None  # Up to date

    return {
        "config_version": latest_bundle.config_version,
        "organization_id": str(latest_bundle.organization_id),
        "environment": latest_bundle.environment,
        "issued_at": latest_bundle.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": latest_bundle.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bundle": latest_bundle.bundle_json,
        "bundle_sha256": latest_bundle.bundle_sha256,
        "signature": latest_bundle.signature,
        "signing_key_id": latest_bundle.signing_key_id,
    }


def suspend_enterprise_gateway(db: Session, gateway_id_str: str, org_id: UUID) -> EnterpriseGateway:
    """Suspend gateway operations."""
    gw = db.execute(
        select(EnterpriseGateway).where(
            EnterpriseGateway.gateway_id == gateway_id_str,
            EnterpriseGateway.organization_id == org_id,
        )
    ).scalar_one_or_none()
    if not gw:
        raise GatewayControlError(f"Gateway '{gateway_id_str}' not found.", code="GATEWAY_NOT_FOUND", status_code=404)

    gw.status = GatewayStatus.SUSPENDED.value
    gw.suspended_at = datetime.now(timezone.utc)
    db.add(SecurityEvent(
        organization_id=org_id,
        event_type="gateway_suspended",
        severity="warning",
        description=f"Enterprise gateway '{gateway_id_str}' suspended.",
        details={"gateway_id": gateway_id_str},
    ))
    db.commit()
    db.refresh(gw)
    return gw


def revoke_enterprise_gateway(db: Session, gateway_id_str: str, org_id: UUID) -> EnterpriseGateway:
    """Permanently revoke gateway identity."""
    gw = db.execute(
        select(EnterpriseGateway).where(
            EnterpriseGateway.gateway_id == gateway_id_str,
            EnterpriseGateway.organization_id == org_id,
        )
    ).scalar_one_or_none()
    if not gw:
        raise GatewayControlError(f"Gateway '{gateway_id_str}' not found.", code="GATEWAY_NOT_FOUND", status_code=404)

    gw.status = GatewayStatus.REVOKED.value
    gw.revoked_at = datetime.now(timezone.utc)
    gw.public_key = None
    gw.enrollment_token_hash = None
    db.add(SecurityEvent(
        organization_id=org_id,
        event_type="gateway_revoked",
        severity="critical",
        description=f"Enterprise gateway '{gateway_id_str}' permanently revoked.",
        details={"gateway_id": gateway_id_str},
    ))
    db.commit()
    db.refresh(gw)
    return gw
