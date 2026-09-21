"""Cryptographic Key Lifecycle and KMS/HSM Foundation for AgentTrust.

Invariants:
1. Private key material is never exported via status() or public APIs.
2. Keys marked COMPROMISED immediately halt signing and fail all verification.
3. Key purposes are segregated: AGENT_SIGNING, GATEWAY_SIGNING, CONTROL_PLANE_SIGNING,
   CREDENTIAL_ISSUER_SIGNING, WEBHOOK_SIGNING, APPROVAL_SIGNING.
4. Local and mock KMS providers are explicitly labeled as TEST / MOCK ONLY.
"""

from abc import ABC, abstractmethod
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import threading
from typing import Dict, List, Optional
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyPurpose(str, Enum):
    AGENT_SIGNING = "AGENT_SIGNING"
    GATEWAY_SIGNING = "GATEWAY_SIGNING"
    CONTROL_PLANE_SIGNING = "CONTROL_PLANE_SIGNING"
    CREDENTIAL_ISSUER_SIGNING = "CREDENTIAL_ISSUER_SIGNING"
    WEBHOOK_SIGNING = "WEBHOOK_SIGNING"
    APPROVAL_SIGNING = "APPROVAL_SIGNING"


class KeyStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"
    COMPROMISED = "COMPROMISED"


class KeySecurityError(Exception):
    """Base exception for cryptographic key lifecycle errors."""
    pass


class KeyCompromisedError(KeySecurityError):
    """Raised when an operation is attempted using a compromised cryptographic key."""
    pass


class KeyRevokedError(KeySecurityError):
    """Raised when an operation is attempted using a revoked cryptographic key."""
    pass


class AlgorithmConfusionError(KeySecurityError):
    """Raised when a signature specifies an unexpected or mismatched algorithm."""
    pass


@dataclass
class KeyMetadata:
    """Public metadata representation of a cryptographic key.
    
    CRITICAL INVARIANT: Private key bytes are NEVER included in this model.
    """
    key_id: str
    purpose: KeyPurpose
    status: KeyStatus
    algorithm: str
    public_key: str
    created_at: datetime
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "purpose": self.purpose.value,
            "status": self.status.value,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "created_at": self.created_at.isoformat(),
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
        }


class KeyProvider(ABC):
    """Abstract interface for KMS/HSM-backed key lifecycle management."""

    @abstractmethod
    def sign(self, data: bytes, key_id: str) -> bytes:
        """Sign payload using key identified by key_id without exporting private key."""
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify signature for payload using public key corresponding to key_id."""
        pass

    @abstractmethod
    def get_public_key(self, key_id: str) -> str:
        """Retrieve the public key in standard PEM or Base64 format."""
        pass

    @abstractmethod
    def rotate(self, key_id: str) -> KeyMetadata:
        """Issue a new key replacing key_id, setting old key to ROTATING."""
        pass

    @abstractmethod
    def revoke(self, key_id: str, reason: str, compromised: bool = False) -> None:
        """Revoke key. If compromised=True, status becomes COMPROMISED."""
        pass

    @abstractmethod
    def status(self, key_id: str) -> KeyMetadata:
        """Return public metadata for the key."""
        pass

    @abstractmethod
    def list_keys(self, purpose: Optional[KeyPurpose] = None) -> List[KeyMetadata]:
        """List public metadata for all managed keys."""
        pass


class LocalKeyProvider(KeyProvider):
    """Local software-based key manager for development and testing.
    
    LABEL: TEST / MOCK ONLY (Software-backed Ed25519 keys)
    """

    def __init__(self):
        self._private_keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self._metadata: Dict[str, KeyMetadata] = {}
        self._lock = threading.Lock()

    def create_key(self, purpose: KeyPurpose, algorithm: str = "Ed25519") -> KeyMetadata:
        if algorithm != "Ed25519":
            raise AlgorithmConfusionError(f"Unsupported algorithm '{algorithm}'. Only Ed25519 is supported.")
        key_id = f"key-{purpose.value.lower()}-{uuid.uuid4().hex[:8]}"
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
        meta = KeyMetadata(
            key_id=key_id,
            purpose=purpose,
            status=KeyStatus.ACTIVE,
            algorithm=algorithm,
            public_key=pub_b64,
            created_at=datetime.now(timezone.utc),
        )
        with self._lock:
            self._private_keys[key_id] = priv
            self._metadata[key_id] = meta
        return meta

    def sign(self, data: bytes, key_id: str) -> bytes:
        with self._lock:
            meta = self._metadata.get(key_id)
            if not meta:
                raise KeyError(f"Key '{key_id}' not found")
            if meta.status == KeyStatus.COMPROMISED:
                raise KeyCompromisedError(f"Key '{key_id}' is marked COMPROMISED. Signing refused.")
            if meta.status in (KeyStatus.REVOKED, KeyStatus.RETIRED):
                raise KeyRevokedError(f"Key '{key_id}' is {meta.status.value}. Signing refused.")
            priv = self._private_keys[key_id]
        return priv.sign(data)

    def verify(self, data: bytes, signature: bytes, key_id: str) -> bool:
        with self._lock:
            meta = self._metadata.get(key_id)
            if not meta:
                raise KeyError(f"Key '{key_id}' not found")
            if meta.status == KeyStatus.COMPROMISED:
                return False
            if meta.status == KeyStatus.REVOKED:
                return False
            priv = self._private_keys.get(key_id)
            pub = priv.public_key() if priv else None
        if pub is None:
            return False
        try:
            pub.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    def get_public_key(self, key_id: str) -> str:
        meta = self.status(key_id)
        return meta.public_key

    def rotate(self, key_id: str) -> KeyMetadata:
        with self._lock:
            old_meta = self._metadata.get(key_id)
            if not old_meta:
                raise KeyError(f"Key '{key_id}' not found")
            old_meta.status = KeyStatus.ROTATING
            old_meta.rotated_at = datetime.now(timezone.utc)
            purpose = old_meta.purpose
            algo = old_meta.algorithm
        new_meta = self.create_key(purpose=purpose, algorithm=algo)
        return new_meta

    def revoke(self, key_id: str, reason: str, compromised: bool = False) -> None:
        with self._lock:
            meta = self._metadata.get(key_id)
            if not meta:
                raise KeyError(f"Key '{key_id}' not found")
            now = datetime.now(timezone.utc)
            meta.status = KeyStatus.COMPROMISED if compromised else KeyStatus.REVOKED
            meta.revoked_at = now
            meta.revocation_reason = reason

    def status(self, key_id: str) -> KeyMetadata:
        with self._lock:
            meta = self._metadata.get(key_id)
            if not meta:
                raise KeyError(f"Key '{key_id}' not found")
            # Return copy of metadata
            return KeyMetadata(
                key_id=meta.key_id,
                purpose=meta.purpose,
                status=meta.status,
                algorithm=meta.algorithm,
                public_key=meta.public_key,
                created_at=meta.created_at,
                rotated_at=meta.rotated_at,
                revoked_at=meta.revoked_at,
                revocation_reason=meta.revocation_reason,
            )

    def list_keys(self, purpose: Optional[KeyPurpose] = None) -> List[KeyMetadata]:
        with self._lock:
            keys = list(self._metadata.values())
        if purpose:
            keys = [k for k in keys if k.purpose == purpose]
        return keys


class MockKmsKeyProvider(LocalKeyProvider):
    """Mock KMS Provider simulating AWS KMS / GCP Cloud KMS semantics.
    
    LABEL: TEST / MOCK ONLY (Emulates hardware KMS API without real HSM)
    """

    def __init__(self, key_ring_id: str = "agenttrust-test-keyring"):
        super().__init__()
        self.key_ring_id = key_ring_id
        self.compliance_label = "TEST / MOCK ONLY (Cloud KMS Mock)"


_global_key_provider: Optional[KeyProvider] = None
_key_provider_lock = threading.Lock()


def get_key_provider() -> KeyProvider:
    global _global_key_provider
    with _key_provider_lock:
        if _global_key_provider is None:
            provider = LocalKeyProvider()
            # Seed default keys for standard purposes
            for p in KeyPurpose:
                provider.create_key(purpose=p)
            _global_key_provider = provider
        return _global_key_provider


def set_key_provider(provider: KeyProvider) -> None:
    global _global_key_provider
    with _key_provider_lock:
        _global_key_provider = provider
