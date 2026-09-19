"""Thread-safe runtime state container for AgentTrust Sidecar (Step 23)."""

from __future__ import annotations

from datetime import datetime, timezone
import threading
from typing import Any, Dict, Optional, Set, Tuple


class SidecarState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.gateway_id: Optional[str] = None
        self.organization_id: Optional[str] = None
        self.environment: str = "PRODUCTION"
        self.status: str = "ENROLLING"
        self.version: str = "1.0.0"
        self.applied_config_version: int = 0
        self.active_config: Dict[str, Any] = {
            "policies": [],
            "trusted_issuers": [],
            "credential_requirements": [],
            "revocations": [],
            "routing": {"allowed_peer_gateways": ["*"], "privacy_mode": "DIRECT_PRIVATE"},
        }
        self.config_expires_at: Optional[datetime] = None
        self.control_plane_public_key: Optional[str] = None
        self.control_plane_signing_key_id: Optional[str] = None
        self.control_plane_reachable: bool = True
        self.last_sync_time: Optional[datetime] = None
        self.last_heartbeat_time: Optional[datetime] = None
        
        # Local nonces: (nonce_hash, expires_monotonic)
        self.processed_nonces: Dict[str, float] = {}

        # Safe runtime metrics (never contains payloads)
        self.metrics: Dict[str, int] = {
            "total_requests": 0,
            "approved_requests": 0,
            "rejected_requests": 0,
            "offline_requests": 0,
            "error_count": 0,
        }

    def update_config(
        self,
        new_version: int,
        config_bundle: Dict[str, Any],
        expires_at: datetime,
    ) -> None:
        """Atomically activate new verified configuration."""
        with self._lock:
            self.applied_config_version = new_version
            self.active_config = config_bundle
            self.config_expires_at = expires_at
            self.last_sync_time = datetime.now(timezone.utc)

    def is_config_expired(self) -> bool:
        with self._lock:
            if not self.config_expires_at:
                return True
            return datetime.now(timezone.utc) > self.config_expires_at

    def record_request(self, result: str, was_offline: bool = False) -> None:
        with self._lock:
            self.metrics["total_requests"] += 1
            if was_offline:
                self.metrics["offline_requests"] += 1
            if result in ("LOCAL_APPROVED", "APPROVED"):
                self.metrics["approved_requests"] += 1
            elif result in ("REJECTED", "FAIL_CLOSED"):
                self.metrics["rejected_requests"] += 1
            elif result == "ERROR":
                self.metrics["error_count"] += 1

    def get_health_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "gateway_id": self.gateway_id,
                "status": self.status,
                "version": self.version,
                "config_version": self.applied_config_version,
                "config_expired": self.is_config_expired(),
                "control_plane_reachable": self.control_plane_reachable,
                "last_sync": self.last_sync_time.isoformat() if self.last_sync_time else None,
                "last_heartbeat": self.last_heartbeat_time.isoformat() if self.last_heartbeat_time else None,
                "metrics": dict(self.metrics),
            }


# Global singleton instance
state = SidecarState()
