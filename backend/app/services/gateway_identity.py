"""Gateway Ed25519 Identity and Short-Lived Attestation Service (Step 21).

The Gateway signs an attestation token (X-ATP-Gateway-Attestation) for all routed requests,
allowing receiving agents to cryptographically verify that the request passed through
the AgentTrust Gateway and was authenticated, authorized, and policy-checked.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

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

GATEWAY_KEY_ID = "gateway_key_primary"
GATEWAY_ISSUER = "agenttrust-gateway"
DEFAULT_ATTESTATION_TTL_SECONDS = 60

_KEY_DIR = Path(__file__).resolve().parents[2] / ".gateway_keys"
_KEY_FILE = _KEY_DIR / "gateway_ed25519.pem"

_gateway_private_key: Optional[Ed25519PrivateKey] = None
_gateway_public_key: Optional[Ed25519PublicKey] = None


class GatewayAttestationError(ValueError):
    """Raised when attestation creation or verification fails."""
    pass


def _ensure_gateway_keys() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    global _gateway_private_key, _gateway_public_key
    if _gateway_private_key is not None and _gateway_public_key is not None:
        return _gateway_private_key, _gateway_public_key

    # Check environment variable first
    env_pem = os.environ.get("GATEWAY_PRIVATE_KEY_PEM")
    if env_pem:
        try:
            priv = load_pem_private_key(env_pem.encode("utf-8"), password=None)
            if isinstance(priv, Ed25519PrivateKey):
                _gateway_private_key = priv
                _gateway_public_key = priv.public_key()
                return _gateway_private_key, _gateway_public_key
        except Exception:
            pass

    # Check key file on disk
    if _KEY_FILE.exists():
        try:
            pem_bytes = _KEY_FILE.read_bytes()
            priv = load_pem_private_key(pem_bytes, password=None)
            if isinstance(priv, Ed25519PrivateKey):
                _gateway_private_key = priv
                _gateway_public_key = priv.public_key()
                return _gateway_private_key, _gateway_public_key
        except Exception:
            pass

    # Generate new keypair and persist
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pem_bytes = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    _KEY_FILE.write_bytes(pem_bytes)
    _gateway_private_key = priv
    _gateway_public_key = priv.public_key()
    return _gateway_private_key, _gateway_public_key


def get_gateway_key_id() -> str:
    return GATEWAY_KEY_ID


def get_gateway_public_key_base64() -> str:
    _, pub = _ensure_gateway_keys()
    raw_bytes = pub.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return base64.b64encode(raw_bytes).decode("ascii")


def get_gateway_public_key_pem() -> str:
    _, pub = _ensure_gateway_keys()
    pem_bytes = pub.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


def create_gateway_attestation(
    source_address: str,
    target_address: str,
    capability: str,
    message_id: str,
    payload_sha256: str,
    ttl_seconds: int = DEFAULT_ATTESTATION_TTL_SECONDS,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate an Ed25519-signed Gateway Attestation string:
    Format: atp_attest_<base64_claims>.<base64_signature>
    """
    priv, _ = _ensure_gateway_keys()
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": GATEWAY_ISSUER,
        "kid": GATEWAY_KEY_ID,
        "src": source_address,
        "tgt": target_address,
        "cap": capability,
        "mid": message_id,
        "hsh": payload_sha256,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if extra_claims:
        claims.update(extra_claims)

    claims_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    claims_b64 = base64.urlsafe_b64encode(claims_json).decode("ascii").rstrip("=")
    
    # Sign claims bytes
    sig = priv.sign(claims_json)
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")

    return f"atp_attest_{claims_b64}.{sig_b64}"


def verify_gateway_attestation(
    attestation_token: str,
    gateway_public_key_b64: Optional[str] = None,
    clock_skew_seconds: int = 15,
) -> Dict[str, Any]:
    """
    Verify a Gateway Attestation token using the Gateway's public key.
    Validates token format, Ed25519 signature, expiration, and issuer.
    """
    if not attestation_token or not attestation_token.startswith("atp_attest_"):
        raise GatewayAttestationError("Invalid attestation token prefix. Expected 'atp_attest_'.")

    token_body = attestation_token[len("atp_attest_"):]
    parts = token_body.split(".")
    if len(parts) != 2:
        raise GatewayAttestationError("Invalid attestation token format. Expected '<claims>.<sig>'.")

    claims_b64, sig_b64 = parts[0], parts[1]

    # Re-pad base64
    def _pad_b64(val: str) -> bytes:
        missing = len(val) % 4
        if missing != 0:
            val += "=" * (4 - missing)
        return base64.urlsafe_b64decode(val.encode("ascii"))

    try:
        claims_json = _pad_b64(claims_b64)
        sig_bytes = _pad_b64(sig_b64)
    except Exception as exc:
        raise GatewayAttestationError(f"Failed to base64 decode attestation: {exc}") from exc

    # Load public key
    if gateway_public_key_b64:
        try:
            pub_bytes = base64.b64decode(gateway_public_key_b64)
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as exc:
            raise GatewayAttestationError(f"Invalid verification public key: {exc}") from exc
    else:
        _, pub = _ensure_gateway_keys()

    # Verify signature
    try:
        pub.verify(sig_bytes, claims_json)
    except InvalidSignature as exc:
        raise GatewayAttestationError("Gateway attestation signature is invalid.") from exc

    try:
        claims: Dict[str, Any] = json.loads(claims_json.decode("utf-8"))
    except Exception as exc:
        raise GatewayAttestationError(f"Attestation claims JSON decode error: {exc}") from exc

    # Validate timestamps
    now = int(time.time())
    if claims.get("iss") != GATEWAY_ISSUER:
        raise GatewayAttestationError(f"Invalid attestation issuer '{claims.get('iss')}'.")

    exp = claims.get("exp")
    if exp is None or not isinstance(exp, (int, float)):
        raise GatewayAttestationError("Attestation missing valid 'exp' claim.")

    if now > exp + clock_skew_seconds:
        raise GatewayAttestationError(f"Gateway attestation expired at {exp} (current time: {now}).")

    return claims
