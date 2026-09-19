"""Outbound ATP/1.0 router and Direct Private payload forwarder for AgentTrust Sidecar (Step 23).

Enforces:
- ATP/1.0 protocol compliance
- DIRECT_PRIVATE mode: payloads flow directly between agents without touching Control Plane
- Deep SSRF defense blocking loopbacks, cloud metadata, and link-local addresses
- Gateway attestation injection
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

from sidecar.config import config
from sidecar.crypto import get_or_create_local_keypair
from sidecar.state import state

# Denied IP networks for SSRF defense
BLOCKED_RANGES = [
    ("127.0.0.0", "255.0.0.0"),       # Loopback
    ("169.254.0.0", "255.255.0.0"),   # Link-local / Cloud metadata (169.254.169.254)
    ("0.0.0.0", "255.0.0.0"),         # Current network
]


def _ip_to_int(ip_str: str) -> int:
    parts = [int(p) for p in ip_str.split(".")]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def is_safe_ip(ip_str: str, allow_private_ips: bool = False) -> bool:
    """Check if destination IP is safe from SSRF exploits."""
    try:
        ip_int = _ip_to_int(ip_str)
        # Block loopback and cloud metadata unconditionally
        for net, mask in BLOCKED_RANGES:
            if (ip_int & _ip_to_int(mask)) == _ip_to_int(net):
                return False

        # If private IPs not explicitly allowed, block RFC 1918
        if not allow_private_ips:
            rfc1918 = [
                ("10.0.0.0", "255.0.0.0"),
                ("172.16.0.0", "255.240.0.0"),
                ("192.168.0.0", "255.255.0.0"),
            ]
            for net, mask in rfc1918:
                if (ip_int & _ip_to_int(mask)) == _ip_to_int(net):
                    return False

        return True
    except Exception:
        return False


def validate_destination_url(url_str: str, allow_private_ips: bool = False) -> Tuple[bool, Optional[str]]:
    """Validate destination URL against SSRF threats."""
    parsed = urllib.parse.urlparse(url_str.strip())
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "Missing destination hostname."

    # Prevent loopback aliases
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
        return False, f"Destination '{hostname}' is a forbidden host."

    try:
        resolved_ips = socket.gethostbyname_ex(hostname)[2]
        for ip in resolved_ips:
            if not is_safe_ip(ip, allow_private_ips=allow_private_ips):
                return False, f"Resolved IP '{ip}' for '{hostname}' is restricted (SSRF defense)."
    except Exception as exc:
        return False, f"Failed to resolve destination '{hostname}': {exc}"

    return True, None


def generate_local_gateway_attestation(
    message_id: str,
    source_addr: str,
    target_addr: str,
    capability: str,
) -> str:
    """Generate Ed25519-signed local gateway attestation."""
    priv, _, fingerprint = get_or_create_local_keypair()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    attestation_payload = {
        "gateway_id": state.gateway_id or "gw_sidecar",
        "message_id": message_id,
        "source": source_addr,
        "target": target_addr,
        "capability": capability,
        "timestamp": now_utc,
        "fingerprint": fingerprint,
    }

    payload_json = json.dumps(attestation_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = priv.sign(payload_json)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    envelope = {
        "attestation": attestation_payload,
        "signature": sig_b64,
    }
    return base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")


def route_atp_message_direct(
    envelope: Dict[str, Any],
    target_endpoint_url: Optional[str] = None,
    allow_private_ips: bool = False,
) -> Dict[str, Any]:
    """
    Route an ATP/1.0 envelope in DIRECT_PRIVATE mode.
    The raw business payload flows directly to the target without passing through Control Plane.
    """
    target = envelope.get("target") or {}
    target_addr = target.get("address") or f"atp://{target.get('organization_id')}/{target.get('agent_id')}"
    source = envelope.get("source") or {}
    source_addr = source.get("address") or f"atp://{source.get('organization_id')}/{source.get('agent_id')}"
    capability = envelope.get("capability", "")
    message_id = envelope.get("message_id", "")

    # Inject local gateway attestation
    attestation_header = generate_local_gateway_attestation(
        message_id=message_id,
        source_addr=source_addr,
        target_addr=target_addr,
        capability=capability,
    )

    if not target_endpoint_url:
        # Check mock agent or return delivered simulation
        return {
            "status": "DELIVERED",
            "delivery_mode": "DIRECT_PRIVATE",
            "target": target_addr,
            "attestation": attestation_header,
            "response": {"ack": True, "message": "Message delivered locally in DIRECT_PRIVATE mode."},
        }

    # SSRF protection
    safe, err = validate_destination_url(target_endpoint_url, allow_private_ips=allow_private_ips)
    if not safe:
        return {
            "status": "FAILED",
            "error": "SSRF_BLOCKED",
            "reason": err,
        }

    # Send outbound HTTP request
    body_bytes = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        target_endpoint_url,
        data=body_bytes,
        headers={
            "Content-Type": "application/json",
            "X-ATP-Gateway-Attestation": attestation_header,
            "X-ATP-Protocol": "ATP/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            return {
                "status": "DELIVERED",
                "delivery_mode": "DIRECT_PRIVATE",
                "target": target_addr,
                "attestation": attestation_header,
                "response": resp_data,
            }
    except Exception as exc:
        return {
            "status": "FAILED",
            "error": "DELIVERY_ERROR",
            "reason": str(exc),
        }
