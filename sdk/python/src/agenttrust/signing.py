"""AgentTrust v1 Ed25519 request signing. Private keys stay on the developer machine."""

import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_request(method: str, path: str, agent_id: str, key_id: str,
                      timestamp: str, nonce: str, body: bytes) -> bytes:
    return ("\n".join(("v1", method.upper(), path, agent_id, key_id, timestamp,
                       nonce, hashlib.sha256(body).hexdigest())) + "\n").encode("ascii")


def canonical_cross_org_request_v2(
    method: str,
    path: str,
    source_org_id: str,
    target_org_id: str,
    source_agent_id: str,
    target_agent_id: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """ASCII metadata binding source/target org and agents with body SHA-256 for v2 signing."""
    return ("\n".join((
        "v2",
        method.upper(),
        path,
        str(source_org_id),
        str(target_org_id),
        str(source_agent_id),
        str(target_agent_id),
        key_id,
        timestamp,
        nonce,
        hashlib.sha256(body).hexdigest(),
    )) + "\n").encode("ascii")


class AgentSigner:
    def __init__(self, agent_id: str, key_id: str, private_key_path: str | Path):
        value = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
        if not isinstance(value, Ed25519PrivateKey):
            raise ValueError("An Ed25519 private key is required")
        self.agent_id = agent_id
        self.key_id = key_id
        self._private_key = value

    def headers(self, method: str, path: str, body: bytes, *, timestamp: str | None = None,
                nonce: str | None = None) -> dict[str, str]:
        timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = nonce or f"nonce_{secrets.token_hex(16)}"
        canonical = canonical_request(method, path, self.agent_id, self.key_id, timestamp, nonce, body)
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Key-ID": self.key_id,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": base64.b64encode(self._private_key.sign(canonical)).decode("ascii"),
            "X-Agent-Signature-Version": "v1",
        }

    def cross_org_headers(
        self,
        method: str,
        path: str,
        body: bytes,
        source_org_id: str,
        target_org_id: str,
        target_agent_id: str,
        *,
        timestamp: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, str]:
        timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        nonce = nonce or f"nonce_{secrets.token_hex(16)}"
        canonical = canonical_cross_org_request_v2(
            method,
            path,
            source_org_id=source_org_id,
            target_org_id=target_org_id,
            source_agent_id=self.agent_id,
            target_agent_id=target_agent_id,
            key_id=self.key_id,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-Key-ID": self.key_id,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": base64.b64encode(self._private_key.sign(canonical)).decode("ascii"),
            "X-Agent-Signature-Version": "v2",
            "X-Source-Org-ID": str(source_org_id),
            "X-Target-Org-ID": str(target_org_id),
            "X-Target-Agent-ID": str(target_agent_id),
        }

    def sign_atp_envelope(
        self,
        *,
        source_org_id: str,
        target_org_id: str,
        target_agent_id: str,
        capability: str,
        payload: Any,
        message_id: str | None = None,
        timestamp: str | None = None,
        nonce: str | None = None,
        credentials: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Sign and construct an ATP/1.0 request envelope using ATP-SIG/1 profile."""
        msg_id = message_id or f"msg_{secrets.token_hex(16)}"
        ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        n = nonce or f"nonce_{secrets.token_hex(16)}"

        # Compute payload hash
        if payload is None:
            canon_json = b"{}"
        elif isinstance(payload, bytes):
            canon_json = payload
        else:
            canon_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_sha256 = hashlib.sha256(canon_json).hexdigest()

        # Build canonical bytes
        canon_ascii = "\n".join([
            "ATP-SIG/1",
            msg_id,
            "request",
            source_org_id,
            self.agent_id,
            target_org_id,
            target_agent_id,
            capability,
            ts,
            n,
            payload_sha256,
        ]) + "\n"
        sig_bytes = self._private_key.sign(canon_ascii.encode("utf-8"))
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

        envelope = {
            "protocol": "ATP/1.0",
            "message_id": msg_id,
            "message_type": "request",
            "source": {
                "organization_id": source_org_id,
                "agent_id": self.agent_id,
                "address": f"atp://{source_org_id}/{self.agent_id}",
            },
            "target": {
                "organization_id": target_org_id,
                "agent_id": target_agent_id,
                "address": f"atp://{target_org_id}/{target_agent_id}",
            },
            "capability": capability,
            "timestamp": ts,
            "nonce": n,
            "payload": payload,
            "payload_sha256": payload_sha256,
            "signature": {
                "version": "ATP-SIG/1",
                "key_id": self.key_id,
                "value": sig_b64,
            },
        }
        if credentials:
            envelope["credentials"] = credentials
        return envelope


def canonical_atc_credential(
    credential_version: str,
    credential_id: str,
    issuer_id: str,
    subject_org_id: str,
    subject_agent_id: str,
    credential_type: str,
    issued_at: str,
    not_before: str | None,
    expires_at: str,
    environment: str,
    claims: dict[str, Any],
) -> tuple[bytes, str]:
    """Compute canonical ASCII bytes and claims SHA-256 for an ATC/1.0 credential."""
    claims_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    claims_sha256 = hashlib.sha256(claims_json).hexdigest()
    lines = [
        "ATC-SIG/1",
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
    canonical_ascii = "\n".join(lines) + "\n"
    return canonical_ascii.encode("ascii"), claims_sha256


def verify_atc_credential_offline(credential: dict[str, Any], issuer_public_key_b64: str) -> bool:
    """Verify an ATC/1.0 credential offline using a known issuer public key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    proof = credential.get("proof") or {}
    sig_b64 = proof.get("signature")
    if not sig_b64:
        return False

    subj = credential.get("subject") or {}
    canon_bytes, _ = canonical_atc_credential(
        credential_version=credential.get("credential_version", ""),
        credential_id=credential.get("credential_id", ""),
        issuer_id=credential.get("issuer", ""),
        subject_org_id=subj.get("organization_id", ""),
        subject_agent_id=subj.get("agent_id", ""),
        credential_type=credential.get("credential_type", ""),
        issued_at=credential.get("issued_at", ""),
        not_before=credential.get("not_before"),
        expires_at=credential.get("expires_at", ""),
        environment=credential.get("environment", "production"),
        claims=credential.get("claims") or {},
    )

    try:
        pub_bytes = base64.b64decode(issuer_public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(sig_b64)
        pub_key.verify(sig_bytes, canon_bytes)
        return True
    except (InvalidSignature, Exception):
        return False


