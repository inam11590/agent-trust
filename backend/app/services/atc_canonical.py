"""Canonicalization and Hashing Engine for AgentTrust Credentials (ATC/1.0).

Enforces deterministic, cross-language byte representation for ATC-SIG/1 signature verification.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

ATC_VERSION = "ATC/1.0"
ATC_SIGNING_VERSION = "ATC-SIG/1"


class ATCValidationError(ValueError):
    """Raised when credential format or fields fail canonicalization validation."""
    pass


def compute_claims_sha256(claims: Any) -> str:
    """
    Compute canonical SHA-256 hex digest of a JSON-serializable claims dictionary.
    Uses sorted keys, UTF-8 encoding, and separators=(',', ':') with no whitespace.
    """
    if claims is None:
        canonical_json = b"{}"
    elif isinstance(claims, bytes):
        canonical_json = claims
    elif isinstance(claims, str):
        try:
            parsed = json.loads(claims)
            canonical_json = json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except Exception:
            canonical_json = claims.encode("utf-8")
    else:
        canonical_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    
    return hashlib.sha256(canonical_json).hexdigest()


def build_atc_canonical_ascii(
    credential_version: str,
    credential_id: str,
    issuer_id: str,
    subject_org_id: str,
    subject_agent_id: str,
    credential_type: str,
    issued_at: str,
    not_before: Optional[str],
    expires_at: str,
    environment: str,
    claims_sha256: str,
) -> str:
    """
    Build canonical ASCII string for ATC-SIG/1 signature generation and verification.
    Lines are separated by LF and end with a trailing LF.
    """
    lines = [
        ATC_SIGNING_VERSION,
        credential_version.strip(),
        credential_id.strip(),
        issuer_id.strip(),
        subject_org_id.strip(),
        subject_agent_id.strip(),
        credential_type.strip(),
        issued_at.strip(),
        (not_before or "").strip(),
        expires_at.strip(),
        environment.strip(),
        claims_sha256.strip(),
    ]
    return "\n".join(lines) + "\n"


def build_atc_canonical_bytes(
    credential_version: str,
    credential_id: str,
    issuer_id: str,
    subject_org_id: str,
    subject_agent_id: str,
    credential_type: str,
    issued_at: str,
    not_before: Optional[str],
    expires_at: str,
    environment: str,
    claims_sha256: str,
) -> bytes:
    """Build canonical ASCII string as bytes."""
    return build_atc_canonical_ascii(
        credential_version=credential_version,
        credential_id=credential_id,
        issuer_id=issuer_id,
        subject_org_id=subject_org_id,
        subject_agent_id=subject_agent_id,
        credential_type=credential_type,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        environment=environment,
        claims_sha256=claims_sha256,
    ).encode("ascii")
