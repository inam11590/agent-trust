"""AgentTrust Sidecar and Enterprise Data Plane Service (Step 23).

Binds to 127.0.0.1:8080 by default (localhost only for security).
Executes local authorization, credential checks, risk scoring, and DIRECT_PRIVATE routing.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from sidecar.config import config
from sidecar.crypto import get_or_create_local_keypair
from sidecar.evaluator import evaluate_local_request
from sidecar.router import route_atp_message_direct
from sidecar.state import state
from sidecar.storage import load_config_cache
from sidecar.sync import send_heartbeat_sync, sync_configuration_sync


class LocalAuthorizeRequest(BaseModel):
    action: str = Field(..., description="Action to authorize (e.g. hotel.reserve, payment.charge)")
    resource: str = Field(..., description="Target resource (e.g. hotel:grand_hyatt)")
    agent_id: str = Field(..., description="Calling agent identifier")
    amount: Optional[float] = Field(0.0, description="Transaction monetary amount")
    credentials: Optional[List[Dict[str, Any]]] = Field(None, description="Presented ATC/1.0 credentials")
    nonce: Optional[str] = Field(None, description="Anti-replay nonce")
    timestamp: Optional[str] = Field(None, description="Request timestamp")
    force_offline: Optional[bool] = Field(False, description="Simulate offline mode for testing")


class ATPLocalMessageRequest(BaseModel):
    envelope: Dict[str, Any] = Field(..., description="Complete ATP/1.0 signed envelope")
    target_endpoint_url: Optional[str] = Field(None, description="Direct target HTTP(S) URL for DIRECT_PRIVATE delivery")


async def _background_sync_loop():
    """Periodic background task to sync config and send heartbeats."""
    while True:
        try:
            send_heartbeat_sync()
            sync_configuration_sync()
        except Exception:
            pass
        await asyncio.sleep(config.sync_interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize local keypair (never sent to Control Plane)
    get_or_create_local_keypair()

    # 2. Try loading cached configuration
    load_config_cache()

    # 3. Initial sync if gateway_id is configured
    if config.gateway_id:
        state.gateway_id = config.gateway_id
        state.status = "ACTIVE"
        sync_configuration_sync()
        send_heartbeat_sync()

    # 4. Start background sync
    task = asyncio.create_task(_background_sync_loop())
    yield
    task.cancel()


app = FastAPI(
    title="AgentTrust Sidecar",
    version="1.0.0",
    description="Enterprise Data Plane reference implementation for local policy enforcement and DIRECT_PRIVATE routing.",
    lifespan=lifespan,
)


@app.get("/health")
def health_check() -> Dict[str, Any]:
    """Liveness probe: returns health summary."""
    return state.get_health_summary()


@app.get("/ready")
def readiness_check(response: Response) -> Dict[str, Any]:
    """Readiness probe: returns 200 if configured and operational."""
    summary = state.get_health_summary()
    if summary["config_expired"] and config.offline_policy == "FAIL_CLOSED":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"ready": False, "reason": "Configuration expired and policy is FAIL_CLOSED"}
    return {"ready": True, "details": summary}


@app.get("/status")
def detailed_status() -> Dict[str, Any]:
    """Return complete local Data Plane status and metrics."""
    return {
        "gateway_id": state.gateway_id,
        "environment": config.environment,
        "deployment_type": config.deployment_type,
        "offline_policy": config.offline_policy,
        "applied_config_version": state.applied_config_version,
        "control_plane_url": config.control_plane_url,
        "control_plane_reachable": state.control_plane_reachable,
        "active_config_summary": {
            "policies_count": len(state.active_config.get("policies", [])),
            "trusted_issuers_count": len(state.active_config.get("trusted_issuers", [])),
            "revocations_count": len(state.active_config.get("revocations", [])),
        },
        "metrics": state.metrics,
    }


@app.post("/v1/local/authorize")
def local_authorize(payload: LocalAuthorizeRequest) -> Dict[str, Any]:
    """
    Execute local authorization check against cached policy, risk rules, and credentials.
    Zero private business payloads are transmitted to the Control Plane.
    """
    return evaluate_local_request(
        action=payload.action,
        resource=payload.resource,
        agent_id=payload.agent_id,
        amount=payload.amount or 0.0,
        credentials=payload.credentials,
        nonce=payload.nonce,
        timestamp=payload.timestamp,
        force_offline=payload.force_offline or False,
    )


@app.post("/atp/v1/messages")
def forward_atp_message(payload: ATPLocalMessageRequest) -> Dict[str, Any]:
    """
    Forward ATP/1.0 message directly to target agent / peer gateway.
    Injects local gateway attestation and preserves payload privacy in DIRECT_PRIVATE mode.
    """
    return route_atp_message_direct(
        envelope=payload.envelope,
        target_endpoint_url=payload.target_endpoint_url,
        allow_private_ips=config.allow_private_ips,
    )


@app.post("/internal/sync")
def trigger_manual_sync() -> Dict[str, Any]:
    """Manual sync trigger for testing or administrative reload."""
    updated = sync_configuration_sync()
    hb = send_heartbeat_sync()
    return {"synced": updated, "heartbeat_sent": hb, "config_version": state.applied_config_version}
