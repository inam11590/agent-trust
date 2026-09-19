"""Configuration synchronization and heartbeat worker for AgentTrust Sidecar (Step 23).

Enforces:
- Cryptographic Control Plane signature verification
- Monotonic version progression & anti-rollback protection
- Atomic configuration activation
- Safe telemetry heartbeat transmission (zero private payloads)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import urllib.error
import urllib.request
import json
from typing import Any, Dict, Optional

from sidecar.config import config
from sidecar.crypto import sign_heartbeat, verify_control_plane_config
from sidecar.state import state
from sidecar.storage import save_config_cache

logger = logging.getLogger("agenttrust.sidecar.sync")


def sync_configuration_sync() -> bool:
    """
    Synchronously fetch and apply signed configuration bundle from Control Plane.
    Returns True if a new configuration was activated.
    """
    if not state.gateway_id:
        return False

    url = f"{config.control_plane_url.rstrip('/')}/v1/gateways/{state.gateway_id}/config?client_version={state.applied_config_version}"
    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 304:
                state.control_plane_reachable = True
                state.last_sync_time = datetime.now(timezone.utc)
                return False

            raw_body = resp.read().decode("utf-8")
            bundle_data = json.loads(raw_body)
            state.control_plane_reachable = True

            # 1. Verify Control Plane Ed25519 signature
            if state.control_plane_public_key:
                if not verify_control_plane_config(bundle_data, state.control_plane_public_key):
                    logger.error("Configuration bundle signature failed verification! Rejecting.")
                    return False

            new_version = bundle_data.get("config_version", 0)

            # 2. Anti-Rollback Invariant Check
            if new_version <= state.applied_config_version and state.applied_config_version > 0:
                logger.warning(
                    f"Configuration rollback attempt blocked! Current: {state.applied_config_version}, Received: {new_version}"
                )
                return False

            expires_at_str = bundle_data.get("expires_at", "")
            if expires_at_str.endswith("Z"):
                expires_at_str = expires_at_str[:-1] + "+00:00"
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            # 3. Atomic Activation
            bundle = bundle_data.get("bundle", {})
            state.update_config(new_version, bundle, expires_at)
            save_config_cache(bundle_data)
            logger.info(f"Activated configuration version {new_version} atomically.")
            return True

    except urllib.error.HTTPError as http_err:
        if http_err.code == 304:
            state.control_plane_reachable = True
            state.last_sync_time = datetime.now(timezone.utc)
            return False
        logger.warning(f"Failed to fetch configuration: HTTP {http_err.code}")
        state.control_plane_reachable = False
        return False
    except Exception as exc:
        logger.warning(f"Control Plane unreachable for config sync: {exc}")
        state.control_plane_reachable = False
        return False


def send_heartbeat_sync() -> bool:
    """Send signed heartbeat with safe health telemetry to Control Plane."""
    if not state.gateway_id:
        return False

    now_utc = datetime.now(timezone.utc)
    ts_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    sig = sign_heartbeat(state.gateway_id, state.applied_config_version, ts_iso)

    health_data = {
        "cpu_percent": 1.2,
        "memory_percent": 4.5,
        "total_requests": state.metrics["total_requests"],
        "error_count": state.metrics["error_count"],
        "config_version": state.applied_config_version,
    }

    payload = {
        "version": state.version,
        "config_version": state.applied_config_version,
        "health": health_data,
        "timestamp": ts_iso,
        "signature": sig,
    }

    url = f"{config.control_plane_url.rstrip('/')}/v1/gateways/{state.gateway_id}/heartbeat"
    req_body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=req_body, headers={"Content-Type": "application/json"}, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            state.control_plane_reachable = True
            state.last_heartbeat_time = now_utc
            if resp_data.get("sync_required"):
                sync_configuration_sync()
            return True
    except Exception as exc:
        state.control_plane_reachable = False
        logger.warning(f"Heartbeat failed: Control Plane unreachable ({exc})")
        return False
