"""AgentTrust Verifiable Credentials Service & Verification Engine (Step 22).

Enforces authority bounds, signature verification, temporal bounds, revocation,
key rotation, and environment isolation for ATC/1.0 credentials.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

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

from app.models.agent import Agent, AgentStatus
from app.models.agenttrust_protocol import AgentCapability
from app.models.organization import Organization
from app.models.trust_registry import (
    AgentCredential,
    CredentialIssuer,
    CredentialRevocationReason,
    CredentialStatus,
    IssuerKeyStatus,
    IssuerSigningKey,
    IssuerStatus,
    generate_credential_id,
    generate_issuer_id,
    generate_issuer_key_id,
)
from app.services.atc_canonical import (
    ATC_SIGNING_VERSION,
    ATC_VERSION,
    build_atc_canonical_bytes,
    compute_claims_sha256,
)

# Keystore directory for protected issuer private keys
_KEY_DIR = Path(__file__).resolve().parents[2] / ".issuer_keys"

# In-memory public key cache: key_id -> (public_key_bytes, expires_monotonic)
_KEY_CACHE: Dict[str, Tuple[bytes, float]] = {}
_CACHE_TTL_SECONDS = 60.0


class CredentialVerificationError(Exception):
    """Raised when credential verification fails with a stable machine-readable error code."""

    def __init__(self, message: str, code: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def _store_issuer_private_key(key_id: str, priv_key: Ed25519PrivateKey) -> None:
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    key_path = _KEY_DIR / f"{key_id}.pem"
    pem_bytes = priv_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_path.write_bytes(pem_bytes)


def _load_issuer_private_key(key_id: str) -> Ed25519PrivateKey:
    # Check env var first
    env_pem = os.environ.get(f"ISSUER_KEY_{key_id}") or os.environ.get("ISSUER_PRIVATE_KEY_PEM")
    if env_pem:
        try:
            priv = load_pem_private_key(env_pem.encode("utf-8"), password=None)
            if isinstance(priv, Ed25519PrivateKey):
                return priv
        except Exception:
            pass

    key_path = _KEY_DIR / f"{key_id}.pem"
    if not key_path.exists():
        raise CredentialVerificationError(
            f"Private signing key for '{key_id}' not found in secure storage.",
            code="ISSUER_KEY_NOT_FOUND",
            status_code=500,
        )
    pem_bytes = key_path.read_bytes()
    priv = load_pem_private_key(pem_bytes, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise CredentialVerificationError(
            "Invalid key type in keystore.",
            code="INVALID_KEY_TYPE",
            status_code=500,
        )
    return priv


def create_credential_issuer(
    db: Session,
    organization_id: UUID,
    name: str,
) -> Tuple[CredentialIssuer, IssuerSigningKey]:
    """Create a new CredentialIssuer with an active initial Ed25519 keypair."""
    org = db.execute(select(Organization).where(Organization.id == organization_id)).scalar_one_or_none()
    if not org:
        raise CredentialVerificationError("Organization not found.", code="ORGANIZATION_NOT_FOUND", status_code=404)

    issuer_id = generate_issuer_id()
    issuer = CredentialIssuer(
        issuer_id=issuer_id,
        organization_id=organization_id,
        name=name,
        status=IssuerStatus.ACTIVE.value,
    )
    db.add(issuer)
    db.flush()

    # Generate initial signing key
    key_id = generate_issuer_key_id()
    priv = Ed25519PrivateKey.generate()
    _store_issuer_private_key(key_id, priv)

    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    fp = hashlib.sha256(pub_bytes).hexdigest()

    signing_key = IssuerSigningKey(
        key_id=key_id,
        issuer_id=issuer.id,
        algorithm="Ed25519",
        public_key=pub_b64,
        fingerprint=fp,
        status=IssuerKeyStatus.ACTIVE.value,
    )
    db.add(signing_key)
    db.commit()
    db.refresh(issuer)
    db.refresh(signing_key)
    return issuer, signing_key


def rotate_issuer_signing_key(
    db: Session,
    issuer_id: str,
    revoke_old_key: bool = False,
) -> IssuerSigningKey:
    """Rotate the issuer's active signing key. Creates a new active key and marks prior active key as ROTATED or REVOKED."""
    issuer = db.execute(select(CredentialIssuer).where(CredentialIssuer.issuer_id == issuer_id)).scalar_one_or_none()
    if not issuer:
        raise CredentialVerificationError("Issuer not found.", code="CREDENTIAL_ISSUER_UNKNOWN", status_code=404)
    if issuer.status != IssuerStatus.ACTIVE.value:
        raise CredentialVerificationError(f"Issuer is {issuer.status}.", code="CREDENTIAL_ISSUER_NOT_ACTIVE", status_code=400)

    now = datetime.now(timezone.utc)
    old_key = db.execute(
        select(IssuerSigningKey).where(
            IssuerSigningKey.issuer_id == issuer.id,
            IssuerSigningKey.status == IssuerKeyStatus.ACTIVE.value,
        )
    ).scalar_one_or_none()

    old_key_id = None
    if old_key:
        old_key_id = old_key.key_id
        if revoke_old_key:
            old_key.status = IssuerKeyStatus.REVOKED.value
            old_key.revoked_at = now
        else:
            old_key.status = IssuerKeyStatus.ROTATED.value

    # Invalidate cache
    if old_key_id and old_key_id in _KEY_CACHE:
        _KEY_CACHE.pop(old_key_id, None)

    # Generate new key
    new_key_id = generate_issuer_key_id()
    priv = Ed25519PrivateKey.generate()
    _store_issuer_private_key(new_key_id, priv)

    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    fp = hashlib.sha256(pub_bytes).hexdigest()

    new_key = IssuerSigningKey(
        key_id=new_key_id,
        issuer_id=issuer.id,
        algorithm="Ed25519",
        public_key=pub_b64,
        fingerprint=fp,
        status=IssuerKeyStatus.ACTIVE.value,
        rotated_from_key_id=old_key_id,
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    return new_key


def issue_agent_credential(
    db: Session,
    issuer_id_str: str,
    subject_agent_id_str: str,
    credential_type: str,
    claims: Optional[Dict[str, Any]] = None,
    validity_days: Optional[int] = None,
    not_before: Optional[datetime] = None,
    environment: str = "production",
) -> Dict[str, Any]:
    """
    Issue a cryptographically verifiable ATC/1.0 credential.
    Validates issuer authority, agent status, and registered capabilities.
    """
    # 1. Resolve issuer
    issuer = db.execute(
        select(CredentialIssuer).where(CredentialIssuer.issuer_id == issuer_id_str)
    ).scalar_one_or_none()
    if not issuer:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id_str}' not found.",
            code="CREDENTIAL_ISSUER_UNKNOWN",
            status_code=404,
        )
    if issuer.status == IssuerStatus.SUSPENDED.value:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id_str}' is suspended.",
            code="CREDENTIAL_ISSUER_SUSPENDED",
            status_code=403,
        )
    if issuer.status == IssuerStatus.REVOKED.value:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id_str}' is revoked.",
            code="CREDENTIAL_ISSUER_REVOKED",
            status_code=403,
        )

    # 2. Resolve Subject Agent
    agent: Optional[Agent] = None
    try:
        agent_uuid = UUID(subject_agent_id_str)
        agent = db.execute(select(Agent).where(Agent.id == agent_uuid)).scalar_one_or_none()
    except (ValueError, TypeError):
        pass
    if not agent:
        agent = db.execute(select(Agent).where(Agent.agent_identifier == subject_agent_id_str)).scalar_one_or_none()

    if not agent:
        raise CredentialVerificationError(
            f"Subject agent '{subject_agent_id_str}' not found.",
            code="CREDENTIAL_SUBJECT_INVALID",
            status_code=404,
        )

    # Authority rule: Issuer can only issue credentials for agents of its own organization
    if agent.organization_id != issuer.organization_id:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id_str}' cannot issue credentials for agent '{subject_agent_id_str}' belonging to another organization.",
            code="CREDENTIAL_CLAIM_INVALID",
            status_code=403,
        )

    if agent.status != AgentStatus.ACTIVE:
        raise CredentialVerificationError(
            f"Subject agent '{subject_agent_id_str}' is not active (status: {agent.status}).",
            code="CREDENTIAL_SUBJECT_INVALID",
            status_code=400,
        )

    # Resolve organization
    org = db.execute(select(Organization).where(Organization.id == issuer.organization_id)).scalar_one()

    # 3. Resolve active signing key
    signing_key = db.execute(
        select(IssuerSigningKey).where(
            IssuerSigningKey.issuer_id == issuer.id,
            IssuerSigningKey.status == IssuerKeyStatus.ACTIVE.value,
        )
    ).scalar_one_or_none()
    if not signing_key:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id_str}' has no active signing key.",
            code="CREDENTIAL_SIGNING_KEY_REVOKED",
            status_code=500,
        )

    # 4. Prepare claims based on credential_type
    final_claims: Dict[str, Any] = {}
    now = datetime.now(timezone.utc)
    if credential_type == "AgentIdentityCredential":
        days = validity_days if validity_days is not None else 30
        if days > 90:
            days = 90
        final_claims = {
            "organization_membership": True,
            "agent_identifier": agent.agent_identifier,
        }
        if claims and isinstance(claims, dict):
            # Allow safe additional public claims (avoiding sensitive keys)
            for k, v in claims.items():
                if k not in ("billing", "internal_risk", "api_key", "secrets", "user_id"):
                    final_claims[k] = v
    elif credential_type == "AgentCapabilityCredential":
        days = validity_days if validity_days is not None else 7
        if days > 30:
            days = 30
        req_caps = (claims or {}).get("capabilities", [])
        if not req_caps:
            raise CredentialVerificationError(
                "AgentCapabilityCredential requires non-empty 'capabilities' list.",
                code="CREDENTIAL_CLAIM_INVALID",
                status_code=400,
            )
        # Validate capabilities are registered for the agent
        cap_rows = db.execute(
            select(AgentCapability.name, AgentCapability.version).where(
                AgentCapability.agent_id == agent.id,
                AgentCapability.is_active.is_(True),
            )
        ).all()
        registered_caps = {f"{r[0]}@{r[1]}" for r in cap_rows} | {r[0] for r in cap_rows}
        for cap in req_caps:
            if registered_caps and cap not in registered_caps:
                raise CredentialVerificationError(
                    f"Agent '{agent.agent_identifier}' is not registered for capability '{cap}'.",
                    code="CREDENTIAL_CLAIM_INVALID",
                    status_code=400,
                )
        final_claims = {
            "capabilities": sorted(list(set(req_caps))),
        }
    else:
        raise CredentialVerificationError(
            f"Unsupported credential type '{credential_type}'.",
            code="CREDENTIAL_SCHEMA_UNSUPPORTED",
            status_code=400,
        )

    expires_at = now + timedelta(days=days)
    issued_at_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at_iso = expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_before_iso = not_before.strftime("%Y-%m-%dT%H:%M:%SZ") if not_before else issued_at_iso

    claims_hash = compute_claims_sha256(final_claims)
    cred_id = generate_credential_id()

    # 5. Sign credential
    canonical_bytes = build_atc_canonical_bytes(
        credential_version=ATC_VERSION,
        credential_id=cred_id,
        issuer_id=issuer.issuer_id,
        subject_org_id=org.name,  # Bind canonical org name / slug
        subject_agent_id=agent.agent_identifier,
        credential_type=credential_type,
        issued_at=issued_at_iso,
        not_before=not_before_iso,
        expires_at=expires_at_iso,
        environment=environment,
        claims_sha256=claims_hash,
    )

    priv_key = _load_issuer_private_key(signing_key.key_id)
    sig_bytes = priv_key.sign(canonical_bytes)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    # 6. Persist AgentCredential
    db_cred = AgentCredential(
        credential_id=cred_id,
        issuer_id=issuer.id,
        subject_agent_id=agent.id,
        organization_id=org.id,
        credential_type=credential_type,
        schema_version=ATC_VERSION,
        environment=environment,
        issued_at=now,
        not_before=not_before or now,
        expires_at=expires_at,
        status=CredentialStatus.ACTIVE.value,
        signing_key_id=signing_key.key_id,
        claims_json=final_claims,
        claims_hash=claims_hash,
        signature_value=sig_b64,
    )
    db.add(db_cred)
    db.commit()
    db.refresh(db_cred)

    return {
        "credential_version": ATC_VERSION,
        "credential_id": cred_id,
        "credential_type": credential_type,
        "issuer": issuer.issuer_id,
        "subject": {
            "organization_id": org.name,
            "agent_id": agent.agent_identifier,
        },
        "environment": environment,
        "issued_at": issued_at_iso,
        "not_before": not_before_iso,
        "expires_at": expires_at_iso,
        "claims": final_claims,
        "proof": {
            "type": ATC_SIGNING_VERSION,
            "algorithm": "Ed25519",
            "key_id": signing_key.key_id,
            "signature": sig_b64,
        },
    }


def parse_timestamp(ts_str: str) -> datetime:
    cleaned = ts_str.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def verify_agent_credential(
    db: Session,
    credential: Dict[str, Any],
    expected_environment: str = "production",
    check_agent_active: bool = True,
) -> Dict[str, Any]:
    """
    Comprehensive, zero-trust verification of an ATC/1.0 credential.
    Returns safe verification summary or raises CredentialVerificationError with stable error code.
    """
    # 1. Version & Type Validation
    version = credential.get("credential_version")
    if version != ATC_VERSION:
        raise CredentialVerificationError(
            f"Unsupported credential version '{version}'. Expected '{ATC_VERSION}'.",
            code="CREDENTIAL_SCHEMA_UNSUPPORTED",
            status_code=400,
        )

    cred_id = credential.get("credential_id")
    cred_type = credential.get("credential_type")
    issuer_id = credential.get("issuer")
    subject = credential.get("subject") or {}
    subj_org = subject.get("organization_id")
    subj_agt = subject.get("agent_id")
    env = credential.get("environment", "production")
    issued_at_str = credential.get("issued_at")
    not_before_str = credential.get("not_before")
    expires_at_str = credential.get("expires_at")
    claims = credential.get("claims")
    proof = credential.get("proof") or {}

    if not all([cred_id, cred_type, issuer_id, subj_org, subj_agt, issued_at_str, expires_at_str, proof]):
        raise CredentialVerificationError(
            "Malformed credential envelope: missing required fields.",
            code="CREDENTIAL_INVALID",
            status_code=400,
        )

    # 2. Environment Binding Check
    if env == "sandbox" and expected_environment == "production":
        raise CredentialVerificationError(
            "Sandbox credential cannot be presented in a production context.",
            code="SANDBOX_CREDENTIAL_IN_PRODUCTION",
            status_code=403,
        )

    # 3. Temporal Bounds Check
    now = datetime.now(timezone.utc)
    try:
        exp_dt = parse_timestamp(expires_at_str)
        if now > exp_dt + timedelta(seconds=30):
            raise CredentialVerificationError(
                f"Credential '{cred_id}' expired at {expires_at_str}.",
                code="CREDENTIAL_EXPIRED",
                status_code=401,
            )

        if not_before_str:
            nb_dt = parse_timestamp(not_before_str)
            if now < nb_dt - timedelta(seconds=30):
                raise CredentialVerificationError(
                    f"Credential '{cred_id}' not valid before {not_before_str}.",
                    code="CREDENTIAL_NOT_YET_VALID",
                    status_code=401,
                )
    except CredentialVerificationError:
        raise
    except Exception as exc:
        raise CredentialVerificationError(
            f"Invalid timestamp in credential: {exc}",
            code="CREDENTIAL_INVALID",
            status_code=400,
        )

    # 4. Issuer Lookup & Status
    issuer = db.execute(
        select(CredentialIssuer).where(CredentialIssuer.issuer_id == issuer_id)
    ).scalar_one_or_none()
    if not issuer:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id}' is unknown in Trust Registry.",
            code="CREDENTIAL_ISSUER_UNKNOWN",
            status_code=401,
        )

    if issuer.status == IssuerStatus.SUSPENDED.value:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id}' is suspended.",
            code="CREDENTIAL_ISSUER_SUSPENDED",
            status_code=403,
        )
    if issuer.status == IssuerStatus.REVOKED.value:
        raise CredentialVerificationError(
            f"Issuer '{issuer_id}' is revoked.",
            code="CREDENTIAL_ISSUER_REVOKED",
            status_code=403,
        )

    # 5. Signing Key Verification
    proof_type = proof.get("type")
    algorithm = proof.get("algorithm")
    key_id = proof.get("key_id")
    sig_value = proof.get("signature")

    if proof_type != ATC_SIGNING_VERSION or algorithm != "Ed25519" or not key_id or not sig_value:
        raise CredentialVerificationError(
            "Invalid proof structure or unsupported algorithm.",
            code="CREDENTIAL_INVALID",
            status_code=400,
        )

    signing_key = db.execute(
        select(IssuerSigningKey).where(
            IssuerSigningKey.key_id == key_id,
            IssuerSigningKey.issuer_id == issuer.id,
        )
    ).scalar_one_or_none()

    if not signing_key:
        raise CredentialVerificationError(
            f"Signing key '{key_id}' not found for issuer '{issuer_id}'.",
            code="CREDENTIAL_SIGNING_KEY_REVOKED",
            status_code=401,
        )

    if signing_key.status == IssuerKeyStatus.REVOKED.value:
        raise CredentialVerificationError(
            f"Signing key '{key_id}' has been revoked.",
            code="CREDENTIAL_SIGNING_KEY_REVOKED",
            status_code=401,
        )

    # 6. Cryptographic Signature Verification
    claims_sha = compute_claims_sha256(claims)
    canonical_bytes = build_atc_canonical_bytes(
        credential_version=version,
        credential_id=cred_id,
        issuer_id=issuer_id,
        subject_org_id=subj_org,
        subject_agent_id=subj_agt,
        credential_type=cred_type,
        issued_at=issued_at_str,
        not_before=not_before_str,
        expires_at=expires_at_str,
        environment=env,
        claims_sha256=claims_sha,
    )

    try:
        pub_raw = base64.b64decode(signing_key.public_key)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig_raw = base64.b64decode(sig_value)
        pub_key.verify(sig_raw, canonical_bytes)
    except (InvalidSignature, Exception) as exc:
        raise CredentialVerificationError(
            "Credential Ed25519 cryptographic signature verification failed.",
            code="CREDENTIAL_SIGNATURE_INVALID",
            status_code=401,
        ) from exc

    # 7. Authoritative Credential Status Registry Check
    db_cred = db.execute(
        select(AgentCredential).where(AgentCredential.credential_id == cred_id)
    ).scalar_one_or_none()

    if db_cred:
        if db_cred.status == CredentialStatus.REVOKED.value:
            raise CredentialVerificationError(
                f"Credential '{cred_id}' was revoked (reason: {db_cred.revocation_reason_code}).",
                code="CREDENTIAL_REVOKED",
                status_code=401,
            )
        if db_cred.status == CredentialStatus.EXPIRED.value:
            raise CredentialVerificationError(
                f"Credential '{cred_id}' has expired.",
                code="CREDENTIAL_EXPIRED",
                status_code=401,
            )

    # 8. Subject Agent Verification (if checking registered agents)
    if check_agent_active:
        agent = db.execute(
            select(Agent).where(
                or_(Agent.agent_identifier == subj_agt, Agent.name == subj_agt)
            )
        ).scalar_one_or_none()
        if agent and agent.status != AgentStatus.ACTIVE:
            raise CredentialVerificationError(
                f"Subject agent '{subj_agt}' is inactive (status: {agent.status}).",
                code="CREDENTIAL_SUBJECT_INVALID",
                status_code=403,
            )

    return {
        "verified": True,
        "credential_id": cred_id,
        "credential_type": cred_type,
        "issuer": issuer_id,
        "subject_organization_id": subj_org,
        "subject_agent_id": subj_agt,
        "environment": env,
        "expires_at": expires_at_str,
        "claims": claims,
    }


def revoke_agent_credential(
    db: Session,
    credential_id: str,
    reason_code: str = "ISSUER_ACTION",
) -> AgentCredential:
    """Revoke an issued credential immediately."""
    cred = db.execute(
        select(AgentCredential).where(AgentCredential.credential_id == credential_id)
    ).scalar_one_or_none()
    if not cred:
        raise CredentialVerificationError("Credential not found.", code="CREDENTIAL_NOT_FOUND", status_code=404)

    now = datetime.now(timezone.utc)
    cred.status = CredentialStatus.REVOKED.value
    cred.revoked_at = now
    cred.revocation_reason_code = reason_code
    db.commit()
    db.refresh(cred)
    return cred
