"""AgentTrust v1 Ed25519 request signing. Private keys stay on the developer machine."""

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_request(method: str, path: str, agent_id: str, key_id: str,
                      timestamp: str, nonce: str, body: bytes) -> bytes:
    return ("\n".join(("v1", method.upper(), path, agent_id, key_id, timestamp,
                       nonce, hashlib.sha256(body).hexdigest())) + "\n").encode("ascii")


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
