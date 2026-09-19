"""Local cryptographic operations for AgentTrust Sidecar (Step 23).

Ensures:
- Gateway private key is generated locally and NEVER transmitted to the Control Plane
- Safe local key persistence with 0600 file permissions
- Heartbeat signing with local Ed25519 private key
- Control Plane configuration signature verification
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
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

from sidecar.config import config

CONFIG_SIGNING_VERSION = "AGENTTRUST-CONFIG/1"
HEARTBEAT_SIGNING_VERSION = "AGENTTRUST-HEARTBEAT/1"

_local_private_key: Optional[Ed25519PrivateKey] = None
_local_public_key: Optional[Ed25519PublicKey] = None


def get_or_create_local_keypair() -> Tuple[Ed25519PrivateKey, str, str]:
    """
    Load or generate local Ed25519 keypair for the Sidecar.
    Returns (private_key, public_key_base64, fingerprint).
    Private key NEVER leaves the local machine.
    """
    global _local_private_key, _local_public_key

    if _local_private_key is not None and _local_public_key is not None:
        raw_pub = _local_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        pub_b64 = base64.b64encode(raw_pub).decode("ascii")
        fingerprint = hashlib.sha256(raw_pub).hexdigest()
        return _local_private_key, pub_b64, fingerprint

    keys_dir = Path(config.keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_file = keys_dir / "gateway_ed25519.pem"

    if key_file.exists():
        try:
            pem_bytes = key_file.read_bytes()
            priv = load_pem_private_key(pem_bytes, password=None)
            if isinstance(priv, Ed25519PrivateKey):
                _local_private_key = priv
                _local_public_key = priv.public_key()
                raw_pub = _local_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                pub_b64 = base64.b64encode(raw_pub).decode("ascii")
                fingerprint = hashlib.sha256(raw_pub).hexdigest()
                return _local_private_key, pub_b64, fingerprint
        except Exception:
            pass

    # Generate fresh keypair locally
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem_bytes = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_file.write_bytes(pem_bytes)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass

    _local_private_key = priv
    _local_public_key = pub
    raw_pub = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")
    fingerprint = hashlib.sha256(raw_pub).hexdigest()
    return _local_private_key, pub_b64, fingerprint


def sign_heartbeat(gateway_id: str, config_version: int, timestamp: str) -> str:
    """Sign a heartbeat envelope using the local Ed25519 private key."""
    priv, _, _ = get_or_create_local_keypair()
    canon_bytes = f"{HEARTBEAT_SIGNING_VERSION}\n{gateway_id}\n{config_version}\n{timestamp}\n".encode("utf-8")
    sig_bytes = priv.sign(canon_bytes)
    return base64.b64encode(sig_bytes).decode("ascii")


def compute_bundle_sha256(bundle_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 of configuration bundle."""
    bundle_json_str = json.dumps(bundle_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(bundle_json_str.encode("utf-8")).hexdigest()


def verify_control_plane_config(
    config_bundle_data: Dict[str, Any],
    control_plane_public_key_b64: str,
) -> bool:
    """
    Verify Control Plane cryptographic signature on a configuration bundle.
    Checks:
    1. Bundle SHA-256 matches bundle content
    2. Ed25519 signature verifies against Control Plane public key
    """
    config_version = config_bundle_data.get("config_version")
    org_id = config_bundle_data.get("organization_id")
    env = config_bundle_data.get("environment")
    issued_at = config_bundle_data.get("issued_at")
    expires_at = config_bundle_data.get("expires_at")
    bundle = config_bundle_data.get("bundle") or {}
    bundle_sha256 = config_bundle_data.get("bundle_sha256")
    sig_b64 = config_bundle_data.get("signature")

    if not all([config_version, org_id, env, issued_at, expires_at, bundle_sha256, sig_b64]):
        return False

    # 1. Verify bundle SHA-256
    computed_sha = compute_bundle_sha256(bundle)
    if computed_sha != bundle_sha256:
        return False

    # 2. Verify signature
    canon_to_verify = (
        f"{CONFIG_SIGNING_VERSION}\n"
        f"{config_version}\n"
        f"{org_id}\n"
        f"{env}\n"
        f"{issued_at}\n"
        f"{expires_at}\n"
        f"{bundle_sha256}\n"
    ).encode("utf-8")

    try:
        cp_raw = base64.b64decode(control_plane_public_key_b64)
        cp_pub = Ed25519PublicKey.from_public_bytes(cp_raw)
        sig_bytes = base64.b64decode(sig_b64)
        cp_pub.verify(sig_bytes, canon_to_verify)
        return True
    except (InvalidSignature, Exception):
        return False
