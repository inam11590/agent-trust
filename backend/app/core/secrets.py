"""Central Secret Management abstraction and providers for AgentTrust."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import os
import threading
from typing import Any, Dict, Optional


class SecretClassification(str, Enum):
    APPLICATION_SECRET = "APPLICATION_SECRET"
    SERVICE_CREDENTIAL = "SERVICE_CREDENTIAL"
    CRYPTOGRAPHIC_PRIVATE_KEY = "CRYPTOGRAPHIC_PRIVATE_KEY"
    BOOTSTRAP_SECRET = "BOOTSTRAP_SECRET"
    TEST_SECRET = "TEST_SECRET"
    PUBLIC_KEY = "PUBLIC_KEY"
    PUBLIC_CONFIGURATION = "PUBLIC_CONFIGURATION"


@dataclass
class SecretMetadata:
    name: str
    version: str
    classification: SecretClassification
    created_at: datetime
    expires_at: Optional[datetime] = None


class SecretCache:
    """Thread-safe in-memory secret cache with TTL.
    
    Invariants:
    1. Zero disk writes: cached secret values reside strictly in process memory.
    2. Explicit invalidation via evict() or refresh().
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl_seconds = ttl_seconds
        self._cache: Dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def get(self, name: str) -> Optional[str]:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            if name in self._cache:
                val, expires = self._cache[name]
                if now < expires:
                    return val
                del self._cache[name]
        return None

    def set(self, name: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl_seconds
        expires = datetime.now(timezone.utc).timestamp() + ttl
        with self._lock:
            self._cache[name] = (value, expires)

    def evict(self, name: str) -> None:
        with self._lock:
            self._cache.pop(name, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class SecretProvider(ABC):
    """Abstract interface for central secret management."""

    @abstractmethod
    def get_secret(self, name: str) -> str:
        """Fetch the current version of the named secret."""
        pass

    @abstractmethod
    def get_secret_version(self, name: str, version: str) -> str:
        """Fetch a specific historical version of the secret."""
        pass

    @abstractmethod
    def refresh_secret(self, name: str) -> None:
        """Invalidate cached copy and reload secret from backend."""
        pass

    @abstractmethod
    def health(self) -> Dict[str, Any]:
        """Check health and connectivity of secret store."""
        pass


class EnvSecretProvider(SecretProvider):
    """Environment-based secret provider for Local and Development environments.
    
    Retrieves secrets from OS environment variables.
    """

    def __init__(self, cache_ttl_seconds: int = 300):
        self._cache = SecretCache(ttl_seconds=cache_ttl_seconds)

    def get_secret(self, name: str) -> str:
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        val = os.getenv(name, "")
        if val:
            self._cache.set(name, val)
        return val

    def get_secret_version(self, name: str, version: str) -> str:
        # Env provider does not track historical versions; return current
        return self.get_secret(name)

    def refresh_secret(self, name: str) -> None:
        self._cache.evict(name)

    def health(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "provider": "EnvSecretProvider",
            "mode": "ENVIRONMENT",
            "cached_entries": len(self._cache._cache),
        }


class VaultKmsSecretProvider(SecretProvider):
    """Pluggable production secret provider foundation (HashiCorp Vault / Cloud Secrets).
    
    In local/test environments this operates as a mock provider when configured.
    """

    def __init__(self, endpoint_url: str = "", cache_ttl_seconds: int = 300):
        self.endpoint_url = endpoint_url
        self._cache = SecretCache(ttl_seconds=cache_ttl_seconds)
        self._secrets: Dict[str, str] = {}
        self._versions: Dict[str, Dict[str, str]] = {}

    def set_mock_secret(self, name: str, value: str, version: str = "v1") -> None:
        self._secrets[name] = value
        if name not in self._versions:
            self._versions[name] = {}
        self._versions[name][version] = value

    def get_secret(self, name: str) -> str:
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        val = self._secrets.get(name, os.getenv(name, ""))
        if val:
            self._cache.set(name, val)
        return val

    def get_secret_version(self, name: str, version: str) -> str:
        versions = self._versions.get(name, {})
        return versions.get(version, self.get_secret(name))

    def refresh_secret(self, name: str) -> None:
        self._cache.evict(name)

    def health(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY" if self.endpoint_url or self._secrets else "DEGRADED",
            "provider": "VaultKmsSecretProvider",
            "mode": "PRODUCTION_PLUGGABLE",
            "endpoint": self.endpoint_url or "internal-vault-bridge",
        }


_global_secret_provider: Optional[SecretProvider] = None
_secret_provider_lock = threading.Lock()


def get_secret_provider() -> SecretProvider:
    global _global_secret_provider
    with _secret_provider_lock:
        if _global_secret_provider is None:
            _global_secret_provider = EnvSecretProvider()
        return _global_secret_provider


def set_secret_provider(provider: SecretProvider) -> None:
    global _global_secret_provider
    with _secret_provider_lock:
        _global_secret_provider = provider
