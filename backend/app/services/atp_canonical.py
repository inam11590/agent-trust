"""ATP/1.0 Canonicalization, Hash, and Addressing Utilities (Step 21).

Specification: ATP-SIG/1
Canonical String:
ATP-SIG/1\\n
<message_id>\\n
<message_type>\\n
<source.organization_id>\\n
<source.agent_id>\\n
<target.organization_id>\\n
<target.agent_id>\\n
<capability>\\n
<timestamp>\\n
<nonce>\\n
<payload_sha256>\\n
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Tuple

PROTOCOL_VERSION = "ATP/1.0"
SIGNING_VERSION = "ATP-SIG/1"

ADDRESS_PATTERN = re.compile(r"^atp://([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)$")
MESSAGE_ID_PATTERN = re.compile(r"^msg_[a-zA-Z0-9_-]{12,64}$")
NONCE_PATTERN = re.compile(r"^nonce_[0-9a-f]{24,64}$")
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


class ATPAddressError(ValueError):
    """Raised when an ATP address does not conform to atp://<org_id>/<agent_id>."""
    pass


def parse_agent_address(address: str) -> Tuple[str, str]:
    """Parse 'atp://<org_id>/<agent_id>' into (org_id, agent_id)."""
    if not address or not isinstance(address, str):
        raise ATPAddressError("Agent address must be a non-empty string.")
    
    match = ADDRESS_PATTERN.match(address.strip())
    if not match:
        raise ATPAddressError(f"Invalid ATP agent address format: '{address}'. Expected 'atp://<org_id>/<agent_id>'.")
    
    return match.group(1), match.group(2)


def format_agent_address(org_id: str, agent_id: str) -> str:
    """Format organization and agent identifiers into an ATP address."""
    return f"atp://{org_id.strip()}/{agent_id.strip()}"


def compute_payload_sha256(payload: Any) -> str:
    """
    Compute canonical SHA-256 hex digest of a JSON-serializable payload.
    Uses sorted keys, UTF-8 encoding, and separators=(',', ':') with no whitespace.
    """
    if payload is None:
        canonical_json = b"{}"
    elif isinstance(payload, bytes):
        canonical_json = payload
    elif isinstance(payload, str):
        try:
            parsed = json.loads(payload)
            canonical_json = json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except Exception:
            canonical_json = payload.encode("utf-8")
    else:
        canonical_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    
    return hashlib.sha256(canonical_json).hexdigest()


def build_canonical_request_ascii(
    message_id: str,
    message_type: str,
    source_org_id: str,
    source_agent_id: str,
    target_org_id: str,
    target_agent_id: str,
    capability: str,
    timestamp: str,
    nonce: str,
    payload_sha256: str,
) -> str:
    """
    Build canonical string for ATP-SIG/1 signature verification.
    Lines separated by LF, ending with LF.
    """
    lines = [
        SIGNING_VERSION,
        message_id.strip(),
        message_type.strip(),
        source_org_id.strip(),
        source_agent_id.strip(),
        target_org_id.strip(),
        target_agent_id.strip(),
        capability.strip(),
        timestamp.strip(),
        nonce.strip(),
        payload_sha256.strip(),
    ]
    return "\n".join(lines) + "\n"


def build_canonical_bytes(
    message_id: str,
    message_type: str,
    source_org_id: str,
    source_agent_id: str,
    target_org_id: str,
    target_agent_id: str,
    capability: str,
    timestamp: str,
    nonce: str,
    payload_sha256: str,
) -> bytes:
    """Get canonical bytes encoded as UTF-8 / ASCII."""
    ascii_str = build_canonical_request_ascii(
        message_id=message_id,
        message_type=message_type,
        source_org_id=source_org_id,
        source_agent_id=source_agent_id,
        target_org_id=target_org_id,
        target_agent_id=target_agent_id,
        capability=capability,
        timestamp=timestamp,
        nonce=nonce,
        payload_sha256=payload_sha256,
    )
    return ascii_str.encode("utf-8")
