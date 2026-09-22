"""Enterprise Agent Lifecycle State Machine and Governance Orchestrator (Step 28).

Enforces:
- Deterministic lifecycle state transitions:
  DRAFT -> REGISTERED -> REVIEW_REQUIRED -> APPROVED -> ACTIVE <-> SUSPENDED -> RETIREMENT_PENDING -> RETIRED
- Configurable promotion checklist (purpose, classification, ownership)
- Separation of duties (owner cannot approve their own agent's promotion)
- Emergency suspension with instant fail-closed propagation
- Safe retirement workflow with dependency analysis and credential cleanup
- Audit preservation guarantee (never hard-deletes historical records)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation, DelegationStatus
from app.models.agent_governance import (
    AgentCertification,
    AgentGovernancePolicy,
    AgentOwnershipHistory,
    CertificationStatus,
    ExpiryBehavior,
)
from app.models.organization import OrganizationMember, OrganizationRole, SecurityEvent
from app.models.trust_registry import AgentCredential, CredentialRevocationReason, CredentialStatus


class LifecycleTransitionError(Exception):
    """Raised when an invalid lifecycle state transition or checklist failure occurs."""

    def __init__(self, message: str, code: str = "INVALID_TRANSITION", status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


# State Machine Transition Matrix
VALID_TRANSITIONS: Dict[str, Set[str]] = {
    AgentStatus.DRAFT.value: {
        AgentStatus.REGISTERED.value,
        AgentStatus.RETIRED.value,
    },
    AgentStatus.REGISTERED.value: {
        AgentStatus.DRAFT.value,
        AgentStatus.REVIEW_REQUIRED.value,
        AgentStatus.ACTIVE.value,  # Direct activation supported for dev/sandbox or legacy
        AgentStatus.RETIRED.value,
    },
    AgentStatus.REVIEW_REQUIRED.value: {
        AgentStatus.REGISTERED.value,
        AgentStatus.APPROVED.value,
        AgentStatus.RETIRED.value,
    },
    AgentStatus.APPROVED.value: {
        AgentStatus.ACTIVE.value,
        AgentStatus.REVIEW_REQUIRED.value,
        AgentStatus.RETIRED.value,
    },
    AgentStatus.ACTIVE.value: {
        AgentStatus.SUSPENDED.value,
        AgentStatus.REVIEW_REQUIRED.value,
        AgentStatus.RETIREMENT_PENDING.value,
        AgentStatus.RETIRED.value,
    },
    AgentStatus.SUSPENDED.value: {
        AgentStatus.ACTIVE.value,
        AgentStatus.RETIREMENT_PENDING.value,
        AgentStatus.RETIRED.value,
    },
    AgentStatus.RETIREMENT_PENDING.value: {
        AgentStatus.RETIRED.value,
        AgentStatus.SUSPENDED.value,
        AgentStatus.ACTIVE.value,
    },
    AgentStatus.RETIRED.value: set(),  # Terminal state
    # Backwards compatibility legacy aliases
    AgentStatus.INACTIVE.value: {
        AgentStatus.REGISTERED.value,
        AgentStatus.ACTIVE.value,
        AgentStatus.RETIRED.value,
    },
    AgentStatus.REVOKED.value: set(),
}


def normalize_status(status: Any) -> str:
    """Normalize status string or enum to value string."""
    if isinstance(status, AgentStatus):
        return status.value
    val = str(status).strip().lower()
    if val == "inactive":
        return AgentStatus.REGISTERED.value
    if val == "revoked":
        return AgentStatus.RETIRED.value
    return val


def get_governance_policy(db: Session, organization_id: Optional[UUID]) -> AgentGovernancePolicy:
    """Get or create default organization governance policy."""
    if not organization_id:
        return AgentGovernancePolicy(
            periodic_review_days=90,
            expiry_behavior=ExpiryBehavior.ALERT_ONLY,
            dormancy_days=90,
            enforce_separation_of_duties=False,
            require_classification_on_promotion=False,
            require_purpose_on_promotion=False,
        )

    policy = db.scalar(
        select(AgentGovernancePolicy).where(AgentGovernancePolicy.organization_id == organization_id)
    )
    if not policy:
        policy = AgentGovernancePolicy(
            organization_id=organization_id,
            periodic_review_days=90,
            expiry_behavior=ExpiryBehavior.ALERT_ONLY,
            dormancy_days=90,
            enforce_separation_of_duties=True,
            require_classification_on_promotion=True,
            require_purpose_on_promotion=True,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


def evaluate_promotion_checklist(
    agent: Agent,
    policy: AgentGovernancePolicy,
) -> Tuple[bool, List[str]]:
    """Evaluate whether an agent satisfies the enterprise promotion checklist."""
    errors: List[str] = []

    if not agent.name or len(agent.name.strip()) < 3:
        errors.append("Agent name must be at least 3 characters.")

    if not agent.owner_id:
        errors.append("Agent must have an assigned primary owner.")

    if policy.require_purpose_on_promotion:
        if not agent.purpose or len(agent.purpose.strip()) < 10:
            errors.append("Business purpose description must be at least 10 characters.")

    if policy.require_classification_on_promotion:
        valid_classifications = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if (agent.risk_classification or "").upper() not in valid_classifications:
            errors.append(f"Risk classification must be one of {valid_classifications}.")

    return len(errors) == 0, errors


def transition_lifecycle(
    db: Session,
    agent: Agent,
    target_status: str | AgentStatus,
    acting_user_id: Optional[UUID] = None,
    user_role: Optional[OrganizationRole] = None,
    reason: Optional[str] = None,
    bypass_checklist: bool = False,
) -> Agent:
    """Execute a validated lifecycle state transition on an agent."""
    curr_status = normalize_status(agent.status)
    next_status = normalize_status(target_status)

    if curr_status == next_status:
        return agent

    # Check terminal state
    if curr_status in (AgentStatus.RETIRED.value, AgentStatus.REVOKED.value):
        raise LifecycleTransitionError(
            f"Agent '{agent.name}' is in terminal state '{curr_status}' and cannot be transitioned.",
            code="TERMINAL_STATE",
        )

    # Check state machine transitions
    allowed_next = VALID_TRANSITIONS.get(curr_status, set())
    if next_status not in allowed_next:
        raise LifecycleTransitionError(
            f"Transition from '{curr_status}' to '{next_status}' is not permitted. Allowed: {sorted(list(allowed_next))}",
            code="INVALID_TRANSITION",
        )

    org_id = agent.organization_id
    policy = get_governance_policy(db, org_id)

    # Separation of duties check for REVIEW_REQUIRED -> APPROVED or ACTIVE
    if next_status in (AgentStatus.APPROVED.value, AgentStatus.ACTIVE.value) and curr_status == AgentStatus.REVIEW_REQUIRED.value:
        if policy.enforce_separation_of_duties and acting_user_id:
            if agent.owner_id == acting_user_id:
                # Agent owner cannot approve their own agent's promotion
                raise LifecycleTransitionError(
                    "Separation of duties enforced: Agent owner cannot approve their own agent's promotion.",
                    code="SEPARATION_OF_DUTIES_VIOLATION",
                    status_code=403,
                )

    # Checklist verification when entering REVIEW_REQUIRED, APPROVED, or ACTIVE
    if next_status in (AgentStatus.REVIEW_REQUIRED.value, AgentStatus.APPROVED.value, AgentStatus.ACTIVE.value) and not bypass_checklist:
        passed, errors = evaluate_promotion_checklist(agent, policy)
        if not passed:
            raise LifecycleTransitionError(
                f"Agent failed promotion checklist: {'; '.join(errors)}",
                code="CHECKLIST_FAILED",
            )

    # Specific state actions
    now_utc = datetime.now(timezone.utc)

    if next_status == AgentStatus.ACTIVE.value:
        # Set certification window if not already present
        if not agent.certified_until:
            agent.certified_until = now_utc + timedelta(days=policy.periodic_review_days)
            agent.next_review_due_at = agent.certified_until
            agent.certification_status = "CERTIFIED"
        agent.status = AgentStatus.ACTIVE

    elif next_status == AgentStatus.SUSPENDED.value:
        agent.status = AgentStatus.SUSPENDED
        if org_id:
            db.add(
                SecurityEvent(
                    organization_id=org_id,
                    event_type="agent_suspended",
                    severity="warning",
                    description=f"Agent '{agent.name}' ({agent.agent_identifier}) was suspended: {reason or 'No reason provided.'}",
                    details={
                        "agent_id": str(agent.id),
                        "agent_identifier": agent.agent_identifier,
                        "suspended_by": str(acting_user_id) if acting_user_id else "system",
                        "reason": reason,
                    },
                )
            )

    elif next_status == AgentStatus.RETIRED.value:
        # Execute safe retirement cleanup
        _execute_retirement_cleanup(db, agent, acting_user_id, reason)
        agent.status = AgentStatus.RETIRED

    else:
        # Enum string mapping
        for item in AgentStatus:
            if item.value == next_status:
                agent.status = item
                break

    db.commit()
    db.refresh(agent)
    return agent


def check_retirement_dependencies(db: Session, agent: Agent) -> Dict[str, Any]:
    """Inspect dependent relationships and active resources for an agent before retirement."""
    # 1. Incoming delegations (other agents delegating authority to this agent)
    incoming_delegations = db.scalars(
        select(AgentDelegation).where(
            AgentDelegation.child_agent_id == agent.id,
            AgentDelegation.status == DelegationStatus.ACTIVE,
        )
    ).all()

    # 2. Outgoing delegations (this agent delegated authority to other agents)
    outgoing_delegations = db.scalars(
        select(AgentDelegation).where(
            AgentDelegation.parent_agent_id == agent.id,
            AgentDelegation.status == DelegationStatus.ACTIVE,
        )
    ).all()

    # 3. Active credentials issued to this agent
    active_credentials = db.scalars(
        select(AgentCredential).where(
            AgentCredential.subject_agent_id == agent.id,
            AgentCredential.status == CredentialStatus.ACTIVE.value,
        )
    ).all()

    blocking_reasons: List[str] = []
    if incoming_delegations:
        blocking_reasons.append(f"{len(incoming_delegations)} active incoming delegation(s)")
    if outgoing_delegations:
        blocking_reasons.append(f"{len(outgoing_delegations)} active outgoing delegation(s)")
    if active_credentials:
        blocking_reasons.append(f"{len(active_credentials)} active credential(s)")

    return {
        "agent_id": str(agent.id),
        "agent_identifier": agent.agent_identifier,
        "name": agent.name,
        "can_retire": True,  # Retirement can proceed by automatically tearing down these resources
        "has_active_dependencies": len(blocking_reasons) > 0,
        "active_incoming_delegations_count": len(incoming_delegations),
        "active_outgoing_delegations_count": len(outgoing_delegations),
        "active_credentials_count": len(active_credentials),
        "details": {
            "incoming_delegation_ids": [str(d.id) for d in incoming_delegations],
            "outgoing_delegation_ids": [str(d.id) for d in outgoing_delegations],
            "credential_ids": [c.credential_id for c in active_credentials],
        },
        "summary": "; ".join(blocking_reasons) if blocking_reasons else "No active dependencies.",
    }


def _execute_retirement_cleanup(
    db: Session,
    agent: Agent,
    acting_user_id: Optional[UUID],
    reason: Optional[str],
) -> None:
    """Tear down credentials and delegations while strictly preserving audit logs."""
    now_utc = datetime.now(timezone.utc)

    # 1. Revoke active credentials
    active_creds = db.scalars(
        select(AgentCredential).where(
            AgentCredential.subject_agent_id == agent.id,
            AgentCredential.status == CredentialStatus.ACTIVE.value,
        )
    ).all()
    for cred in active_creds:
        cred.status = CredentialStatus.REVOKED.value
        cred.revoked_at = now_utc
        cred.revocation_reason_code = CredentialRevocationReason.AGENT_RETIRED.value

    # 2. Terminate active delegations
    active_delegations = db.scalars(
        select(AgentDelegation).where(
            or_(
                AgentDelegation.parent_agent_id == agent.id,
                AgentDelegation.child_agent_id == agent.id,
            ),
            AgentDelegation.status == DelegationStatus.ACTIVE,
        )
    ).all()
    for delegation in active_delegations:
        delegation.status = DelegationStatus.REVOKED

    # 3. Write Security Event
    if agent.organization_id:
        db.add(
            SecurityEvent(
                organization_id=agent.organization_id,
                event_type="agent_retired",
                severity="info",
                description=f"Agent '{agent.name}' ({agent.agent_identifier}) was permanently retired: {reason or 'Safe decommission.'}",
                details={
                    "agent_id": str(agent.id),
                    "agent_identifier": agent.agent_identifier,
                    "retired_by": str(acting_user_id) if acting_user_id else "system",
                    "credentials_revoked": len(active_creds),
                    "delegations_terminated": len(active_delegations),
                    "reason": reason,
                },
            )
        )
