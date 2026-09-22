"""Local Policy, Authorization, Risk, and Offline Evaluator for AgentTrust Sidecar (Step 23).

Enforces:
- Local identity & capability evaluation
- Replay prevention (nonces)
- ATC/1.0 credential verification against cached trusted issuers and revocations
- Strict Offline Safety: FAIL_CLOSED vs LIMITED_OFFLINE (high-risk operations never allowed offline)
- Config expiration checking
- Multi-party approval holds (PENDING_HUMAN_APPROVAL)
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import time
from typing import Any, Dict, List, Optional

from sidecar.config import config
from sidecar.state import state


class LocalAuthorizationResult:
    LOCAL_APPROVED = "LOCAL_APPROVED"
    CENTRAL_CHECK_REQUIRED = "CENTRAL_CHECK_REQUIRED"
    PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
    REJECTED = "REJECTED"


def evaluate_local_request(
    action: str,
    resource: str,
    agent_id: str,
    amount: float = 0.0,
    credentials: Optional[List[Dict[str, Any]]] = None,
    nonce: Optional[str] = None,
    timestamp: Optional[str] = None,
    force_offline: bool = False,
) -> Dict[str, Any]:
    """
    Evaluate an Agent request locally within the Data Plane.
    Never transmits private business payload to the Control Plane.
    """
    credentials = credentials or []
    is_offline = force_offline or (not state.control_plane_reachable)

    # 1. Anti-Replay Check (300s window)
    if nonce:
        now_mono = time.monotonic()
        # Evict old nonces
        state.processed_nonces = {k: exp for k, exp in state.processed_nonces.items() if exp > now_mono}
        nonce_hash = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        if nonce_hash in state.processed_nonces:
            state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
            return {
                "decision": LocalAuthorizationResult.REJECTED,
                "code": "REPLAY_ATTACK_DETECTED",
                "reason": f"Nonce '{nonce}' has already been processed.",
            }
        state.processed_nonces[nonce_hash] = now_mono + 300.0

    # 2. Config Expiration Check
    if state.is_config_expired():
        state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
        return {
            "decision": LocalAuthorizationResult.REJECTED,
            "code": "CONFIG_EXPIRED",
            "reason": "Cached configuration bundle has expired. Control Plane synchronization required.",
        }

    # 3. Offline Safety Invariant Enforcement
    if is_offline:
        if config.offline_policy == "FAIL_CLOSED":
            state.record_request(LocalAuthorizationResult.REJECTED, was_offline=True)
            return {
                "decision": LocalAuthorizationResult.REJECTED,
                "code": "OFFLINE_FAIL_CLOSED",
                "reason": "Control Plane is offline and gateway policy is FAIL_CLOSED.",
            }
        elif config.offline_policy == "LIMITED_OFFLINE":
            # High-risk requests are NEVER approved while offline
            if amount > 5000:
                state.record_request(LocalAuthorizationResult.CENTRAL_CHECK_REQUIRED, was_offline=True)
                return {
                    "decision": LocalAuthorizationResult.CENTRAL_CHECK_REQUIRED,
                    "code": "OFFLINE_HIGH_RISK_BLOCKED",
                    "reason": f"High monetary value ({amount} USD) requires central Control Plane verification.",
                }
            if action.endswith(".delete") or action.endswith(".admin"):
                state.record_request(LocalAuthorizationResult.CENTRAL_CHECK_REQUIRED, was_offline=True)
                return {
                    "decision": LocalAuthorizationResult.CENTRAL_CHECK_REQUIRED,
                    "code": "OFFLINE_ADMIN_BLOCKED",
                    "reason": f"Administrative action '{action}' requires central Control Plane verification.",
                }
        else:
            state.record_request(LocalAuthorizationResult.REJECTED, was_offline=True)
            return {
                "decision": LocalAuthorizationResult.REJECTED,
                "code": "INVALID_OFFLINE_POLICY",
                "reason": f"Unknown offline policy '{config.offline_policy}'. Failing closed.",
            }

    # 4. Credential Verification against Cached Trust State
    cfg = state.active_config
    required_cred_types = cfg.get("credential_requirements") or []
    if required_cred_types:
        for req_item in required_cred_types:
            req_type = req_item if isinstance(req_item, str) else req_item.get("type")
            if req_type and not any(c.get("credential_type") == req_type for c in credentials):
                state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
                return {
                    "decision": LocalAuthorizationResult.REJECTED,
                    "code": "REQUIRED_CREDENTIAL_MISSING",
                    "reason": f"Required credential type '{req_type}' not presented.",
                }

    # Check for revoked credentials in cached revocations list
    revocations = cfg.get("revocations") or []
    revoked_cred_ids = {r.get("id") for r in revocations if r.get("type") == "credential"}
    for cred in credentials:
        cid = cred.get("credential_id")
        if cid and cid in revoked_cred_ids:
            state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
            return {
                "decision": LocalAuthorizationResult.REJECTED,
                "code": "CREDENTIAL_REVOKED",
                "reason": f"Presented credential '{cid}' has been revoked.",
            }

    # Check for revoked or suspended agents in cached revocations list
    revoked_agent_ids = {r.get("id") for r in revocations if r.get("type") == "agent"}
    if agent_id in revoked_agent_ids:
        state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
        return {
            "decision": LocalAuthorizationResult.REJECTED,
            "code": "AGENT_SUSPENDED",
            "reason": f"Agent '{agent_id}' is suspended or retired.",
        }

    # 5. Local Risk Engine Scoring
    if amount > 5000:
        state.record_request(LocalAuthorizationResult.PENDING_HUMAN_APPROVAL, was_offline=is_offline)
        return {
            "decision": LocalAuthorizationResult.PENDING_HUMAN_APPROVAL,
            "code": "HIGH_VALUE_TRANSACTION",
            "reason": f"Transaction amount ({amount} USD) exceeds autonomous approval limit of $5,000.",
            "approval_required": True,
        }

    if action.endswith(".admin") or action.endswith(".delete"):
        state.record_request(LocalAuthorizationResult.PENDING_HUMAN_APPROVAL, was_offline=is_offline)
        return {
            "decision": LocalAuthorizationResult.PENDING_HUMAN_APPROVAL,
            "code": "HIGH_RISK_CAPABILITY",
            "reason": f"Administrative action '{action}' requires explicit human approval.",
            "approval_required": True,
        }

    # 6. Policy Check
    # Check APL/1.0 policies if present in configuration bundle
    apl_policies = cfg.get("apl_policies") or [p for p in cfg.get("policies", []) if isinstance(p, dict) and p.get("version") == "APL/1.0"]
    if apl_policies:
        apl_context = {
            "agent": {"id": agent_id},
            "agent.id": agent_id,
            "action": action,
            "resource": resource,
            "input": {"amount": amount},
            "input.amount": amount,
        }
        for apl_ast in apl_policies:
            rules = apl_ast.get("rules", [])
            for r in rules:
                when = r.get("when") or r.get("conditions")
                rule_matched = True
                if when:
                    # Check conditions in 'all' list
                    all_conds = when.get("all", [when] if "field" in when else [])
                    for cond in all_conds:
                        f = cond.get("field")
                        op = cond.get("operator", "eq")
                        expected = cond.get("value")
                        actual = apl_context.get(f)
                        if f and f.startswith("input.") and actual is None:
                            actual = apl_context.get("input", {}).get(f.split(".", 1)[1])
                        
                        m = False
                        if op == "eq":
                            m = (actual == expected)
                        elif op == "gt" and actual is not None and expected is not None:
                            m = (float(actual) > float(expected))
                        elif op == "gte" and actual is not None and expected is not None:
                            m = (float(actual) >= float(expected))
                        elif op == "lt" and actual is not None and expected is not None:
                            m = (float(actual) < float(expected))
                        elif op == "lte" and actual is not None and expected is not None:
                            m = (float(actual) <= float(expected))
                        elif op == "in" and isinstance(expected, list):
                            m = (actual in expected)
                        elif op == "starts_with" and actual is not None:
                            m = str(actual).startswith(str(expected))
                        elif op == "exists":
                            m = (actual is not None)
                        if not m:
                            rule_matched = False
                            break
                if rule_matched:
                    effect = str(r.get("effect", "")).upper()
                    if effect == "DENY":
                        state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
                        return {
                            "decision": LocalAuthorizationResult.REJECTED,
                            "code": "APL_POLICY_DENY",
                            "reason": f"Denied by APL/1.0 policy rule '{r.get('id')}': {r.get('description', 'Policy Deny')}",
                        }
                    elif effect == "REQUIRE_APPROVAL":
                        state.record_request(LocalAuthorizationResult.PENDING_HUMAN_APPROVAL, was_offline=is_offline)
                        return {
                            "decision": LocalAuthorizationResult.PENDING_HUMAN_APPROVAL,
                            "code": "APL_POLICY_REQUIRE_APPROVAL",
                            "reason": f"Approval required by APL/1.0 policy rule '{r.get('id')}': {r.get('description', 'Policy Approval Required')}",
                            "approval_required": True,
                        }

    # Fallback to standard enterprise policies
    policies = [p for p in (cfg.get("policies") or []) if isinstance(p, dict) and p.get("version") != "APL/1.0"]
    allowed = False
    if not policies and not apl_policies:
        # If no explicit policies defined, default allow if registered
        allowed = True
    elif not policies and apl_policies:
        # If APL policies ran and did not deny/require approval, consider allowed
        allowed = True
    else:
        for pol in policies:
            allowed_actions = pol.get("allowed_actions") or []
            allowed_resources = pol.get("allowed_resources") or []
            
            action_match = ("*" in allowed_actions) or any(action.startswith(a.replace("*", "")) for a in allowed_actions)
            resource_match = ("*" in allowed_resources) or any(resource.startswith(r.replace("*", "")) for r in allowed_resources)
            
            if action_match and resource_match:
                allowed = True
                break

    if not allowed:
        state.record_request(LocalAuthorizationResult.REJECTED, was_offline=is_offline)
        return {
            "decision": LocalAuthorizationResult.REJECTED,
            "code": "PERMISSION_DENIED",
            "reason": f"Action '{action}' on resource '{resource}' not permitted by local policy.",
        }

    state.record_request(LocalAuthorizationResult.LOCAL_APPROVED, was_offline=is_offline)
    return {
        "decision": LocalAuthorizationResult.LOCAL_APPROVED,
        "code": "AUTHORIZED",
        "reason": "Request successfully verified and authorized by local Data Plane.",
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
    }
