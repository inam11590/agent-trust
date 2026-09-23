"""Base Discovery Connector Interface and Normalized Resource Schema (Step 29).

Enforces:
- Read-only least-privilege operations
- Zero secret value collection (safe env var names only)
- Zero code execution / container execution
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DiscoveredResource:
    """Standardized representation of an infrastructure resource inspected during discovery."""
    external_reference: str
    candidate_type: str  # WORKLOAD, SERVICE, CONTAINER, REPOSITORY, PIPELINE, RUNTIME_PROCESS
    display_name: str
    environment: str = "unknown"
    location_reference: str = ""
    dependencies: List[str] = field(default_factory=list)
    env_var_names: List[str] = field(default_factory=list)  # VARIABLE NAMES ONLY; NEVER VALUES
    labels: Dict[str, str] = field(default_factory=dict)
    image_name: Optional[str] = None
    telemetry_signals: List[str] = field(default_factory=list)
    suggested_owner: Optional[Dict[str, Any]] = None
    relationships: List[Dict[str, Any]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseDiscoveryConnector(ABC):
    """Abstract connector for infrastructure discovery sources."""

    def __init__(self, configuration: Dict[str, Any], credential_value: Optional[str] = None):
        self.config = configuration or {}
        self.credential = credential_value  # Provided in-memory from SecretProvider; never persisted

    @abstractmethod
    def scan(self) -> List[DiscoveredResource]:
        """Execute a read-only discovery inspection returning normalized resources."""
        pass

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Validate read-only connectivity and permissions."""
        pass

    def health(self) -> Dict[str, Any]:
        """Basic health check of connector."""
        return {
            "status": "HEALTHY",
            "connector": self.__class__.__name__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
