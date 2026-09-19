"""Persistent local storage and cache for AgentTrust Sidecar (Step 23)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from sidecar.config import config
from sidecar.crypto import verify_control_plane_config
from sidecar.state import state


def save_config_cache(bundle_data: Dict[str, Any]) -> None:
    """Save verified signed configuration bundle to persistent local cache."""
    cache_dir = Path(config.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "config_cache.json"

    temp_file = cache_dir / "config_cache.tmp"
    temp_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")
    try:
        os.chmod(temp_file, 0o600)
    except OSError:
        pass

    temp_file.replace(cache_file)


def load_config_cache() -> bool:
    """
    Load cached configuration bundle from disk on startup.
    Validates signature and expiration before activating.
    """
    cache_dir = Path(config.cache_dir)
    cache_file = cache_dir / "config_cache.json"
    if not cache_file.exists():
        return False

    try:
        content = cache_file.read_text(encoding="utf-8")
        bundle_data = json.loads(content)
        
        # Verify Control Plane signature if public key is known
        if state.control_plane_public_key:
            if not verify_control_plane_config(bundle_data, state.control_plane_public_key):
                return False

        version = bundle_data.get("config_version", 0)
        expires_at_str = bundle_data.get("expires_at")
        if not expires_at_str:
            return False

        if expires_at_str.endswith("Z"):
            expires_at_str = expires_at_str[:-1] + "+00:00"
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        bundle = bundle_data.get("bundle", {})
        state.update_config(version, bundle, expires_at)
        return True
    except Exception:
        return False
