"""Deterministic Mock Agents for Sandbox & Playground (Step 21).

Provides built-in simulated target agents:
- Hotel Agent: atp://org_hotelcorp/agt_hotel
  Capabilities: hotel.reserve@1.0, hotel.search@1.0, hotel.cancel@1.0
- Payment Agent: atp://org_payco/agt_payment
  Capabilities: payment.charge@1.0, payment.refund@1.0
- Calendar Agent: atp://org_workplace/agt_calendar
  Capabilities: calendar.event.create@1.0, calendar.availability@1.0
"""

from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.services.atp_canonical import (
    build_canonical_bytes,
    compute_payload_sha256,
    format_agent_address,
)

# Deterministic private keys for mock agents so their signatures are reproducible
_MOCK_HOTEL_PRIV_SEED = hashlib.sha256(b"agenttrust_mock_hotelcorp_hotel").digest()
_MOCK_HOTEL_PRIV = Ed25519PrivateKey.from_private_bytes(_MOCK_HOTEL_PRIV_SEED)

_MOCK_PAYMENT_PRIV_SEED = hashlib.sha256(b"agenttrust_mock_payco_payment").digest()
_MOCK_PAYMENT_PRIV = Ed25519PrivateKey.from_private_bytes(_MOCK_PAYMENT_PRIV_SEED)

_MOCK_CALENDAR_PRIV_SEED = hashlib.sha256(b"agenttrust_mock_workplace_calendar").digest()
_MOCK_CALENDAR_PRIV = Ed25519PrivateKey.from_private_bytes(_MOCK_CALENDAR_PRIV_SEED)

MOCK_AGENTS: Dict[str, Dict[str, Any]] = {
    "atp://org_hotelcorp/agt_hotel": {
        "org_id": "org_hotelcorp",
        "agent_id": "agt_hotel",
        "name": "Grand Hyatt Concierge AI",
        "capabilities": ["hotel.reserve@1.0", "hotel.search@1.0", "hotel.cancel@1.0"],
        "priv_key": _MOCK_HOTEL_PRIV,
        "key_id": "key_agt_hotel_mock",
    },
    "atp://org_payco/agt_payment": {
        "org_id": "org_payco",
        "agent_id": "agt_payment",
        "name": "PayCo Autonomous Clearing",
        "capabilities": ["payment.charge@1.0", "payment.refund@1.0"],
        "priv_key": _MOCK_PAYMENT_PRIV,
        "key_id": "key_agt_payment_mock",
    },
    "atp://org_workplace/agt_calendar": {
        "org_id": "org_workplace",
        "agent_id": "agt_calendar",
        "name": "Workplace Schedule Assistant",
        "capabilities": ["calendar.event.create@1.0", "calendar.availability@1.0"],
        "priv_key": _MOCK_CALENDAR_PRIV,
        "key_id": "key_agt_calendar_mock",
    },
}


def is_sandbox_mock_agent(address: str) -> bool:
    return address.strip() in MOCK_AGENTS


def get_sandbox_mock_agent_public_key_base64(address: str) -> Optional[str]:
    agent_info = MOCK_AGENTS.get(address.strip())
    if not agent_info:
        return None
    pub = agent_info["priv_key"].public_key()
    raw_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw_bytes).decode("ascii")


def execute_sandbox_mock_agent(
    target_address: str,
    capability: str,
    payload: Dict[str, Any],
    source_address: str,
    original_message_id: str,
) -> Dict[str, Any]:
    """
    Execute simulated business logic for a sandbox mock agent.
    Returns a signed ATP response envelope.
    """
    agent_info = MOCK_AGENTS.get(target_address)
    if not agent_info:
        raise ValueError(f"Unknown sandbox mock agent: {target_address}")

    if capability not in agent_info["capabilities"]:
        raise ValueError(f"Mock agent {target_address} does not support capability {capability}")

    # Generate capability-specific response payload
    resp_payload: Dict[str, Any] = {}
    if capability == "hotel.reserve@1.0":
        hotel_id = payload.get("hotel_id", "hotel_grand_hyatt")
        amount = payload.get("amount", 450)
        currency = payload.get("currency", "USD")
        resp_payload = {
            "status": "CONFIRMED",
            "reservation_id": f"res_{uuid4().hex[:12]}",
            "hotel_id": hotel_id,
            "amount": amount,
            "currency": currency,
            "confirmation_code": f"HTL-{uuid4().hex[:6].upper()}",
            "check_in": payload.get("check_in", "2026-10-01"),
            "check_out": payload.get("check_out", "2026-10-05"),
            "message": "Hotel reservation confirmed by Grand Hyatt Concierge AI.",
        }
    elif capability == "hotel.search@1.0":
        city = payload.get("city", "New York")
        resp_payload = {
            "query_city": city,
            "results": [
                {
                    "hotel_id": "hotel_grand_hyatt",
                    "name": "Grand Hyatt Central",
                    "rate_per_night": 450,
                    "currency": "USD",
                    "rating": 4.8,
                },
                {
                    "hotel_id": "hotel_park_regis",
                    "name": "Park Regis",
                    "rate_per_night": 320,
                    "currency": "USD",
                    "rating": 4.5,
                },
            ],
        }
    elif capability == "hotel.cancel@1.0":
        res_id = payload.get("reservation_id", "unknown")
        resp_payload = {
            "status": "CANCELLED",
            "reservation_id": res_id,
            "refund_amount": payload.get("refund_amount", 450),
            "fee": 0,
            "message": "Reservation successfully cancelled.",
        }
    elif capability == "payment.charge@1.0":
        resp_payload = {
            "status": "SUCCEEDED",
            "charge_id": f"ch_{uuid4().hex[:14]}",
            "amount": payload.get("amount", 100),
            "currency": payload.get("currency", "USD"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    elif capability == "payment.refund@1.0":
        resp_payload = {
            "status": "REFUNDED",
            "refund_id": f"ref_{uuid4().hex[:14]}",
            "original_charge_id": payload.get("charge_id", "ch_mock"),
            "amount": payload.get("amount", 100),
        }
    elif capability == "calendar.event.create@1.0":
        resp_payload = {
            "status": "CREATED",
            "event_id": f"evt_{uuid4().hex[:12]}",
            "title": payload.get("title", "Autonomous Agent Meeting"),
            "start": payload.get("start", datetime.now(timezone.utc).isoformat()),
        }
    elif capability == "calendar.availability@1.0":
        resp_payload = {
            "available": True,
            "slots": ["09:00Z", "11:00Z", "14:00Z", "16:00Z"],
        }
    else:
        resp_payload = {"status": "OK", "capability": capability, "result": "mock_success"}

    # Build response envelope
    resp_msg_id = f"msg_resp_{uuid4().hex[:16]}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = f"nonce_{uuid4().hex}"
    payload_sha256 = compute_payload_sha256(resp_payload)

    # Parse target and source addresses
    src_org, src_agt = agent_info["org_id"], agent_info["agent_id"]
    from app.services.atp_canonical import parse_agent_address
    dst_org, dst_agt = parse_agent_address(source_address)

    # Sign canonical response
    canon_bytes = build_canonical_bytes(
        message_id=resp_msg_id,
        message_type="response",
        source_org_id=src_org,
        source_agent_id=src_agt,
        target_org_id=dst_org,
        target_agent_id=dst_agt,
        capability=capability,
        timestamp=now_iso,
        nonce=nonce,
        payload_sha256=payload_sha256,
    )
    sig = agent_info["priv_key"].sign(canon_bytes)
    sig_b64 = base64.b64encode(sig).decode("ascii")

    return {
        "protocol": "ATP/1.0",
        "message_id": resp_msg_id,
        "message_type": "response",
        "reply_to": original_message_id,
        "source": {
            "organization_id": src_org,
            "agent_id": src_agt,
            "address": target_address,
        },
        "target": {
            "organization_id": dst_org,
            "agent_id": dst_agt,
            "address": source_address,
        },
        "capability": capability,
        "timestamp": now_iso,
        "nonce": nonce,
        "payload": resp_payload,
        "payload_sha256": payload_sha256,
        "signature": {
            "version": "ATP-SIG/1",
            "key_id": agent_info["key_id"],
            "value": sig_b64,
        },
        "gateway_routed": True,
    }
