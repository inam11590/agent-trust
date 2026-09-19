"""Configuration management for AgentTrust Sidecar (Step 23)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class SidecarConfig(BaseModel):
    control_plane_url: str = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_CONTROL_PLANE_URL", "http://127.0.0.1:8000")
    )
    gateway_id: Optional[str] = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_GATEWAY_ID", None)
    )
    gateway_name: str = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_GATEWAY_NAME", "Local Sidecar")
    )
    environment: str = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_ENVIRONMENT", "PRODUCTION").upper()
    )
    deployment_type: str = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_DEPLOYMENT_TYPE", "SIDECAR").upper()
    )
    offline_policy: str = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_OFFLINE_POLICY", "FAIL_CLOSED").upper()
    )
    sync_interval_seconds: int = Field(
        default_factory=lambda: int(os.environ.get("AGENTTRUST_SYNC_INTERVAL_SECONDS", "30"))
    )
    heartbeat_interval_seconds: int = Field(
        default_factory=lambda: int(os.environ.get("AGENTTRUST_HEARTBEAT_INTERVAL_SECONDS", "30"))
    )
    host: str = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_HOST", "127.0.0.1")
    )
    port: int = Field(
        default_factory=lambda: int(os.environ.get("AGENTTRUST_PORT", "8080"))
    )
    keys_dir: Path = Field(
        default_factory=lambda: Path(os.environ.get("AGENTTRUST_KEYS_DIR", ".sidecar_keys"))
    )
    cache_dir: Path = Field(
        default_factory=lambda: Path(os.environ.get("AGENTTRUST_CACHE_DIR", ".sidecar_cache"))
    )
    allow_private_ips: bool = Field(
        default_factory=lambda: os.environ.get("AGENTTRUST_ALLOW_PRIVATE_IPS", "false").lower() in ("true", "1")
    )


# Singleton instance
config = SidecarConfig()
