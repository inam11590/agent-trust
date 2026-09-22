"""Enterprise Agent Governance Service (Step 28).

Covers:
- Accountable ownership management and transfer audit history
- Orphaned agent detection
- Periodic access certification reviews with comprehensive posture snapshots
- Expiry policy enforcement (ALERT_ONLY, REVIEW_REQUIRED, SUSPEND)
- Governance signal detection (dormant, overdue, orphaned, broad permissions)
- Relationship and blast-radius dependency graph construction
- Executive governance KPI calculations
- Bulk governance operations and CSV/JSON inventory import/export
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import io
import json
import secrets
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation, DelegationStatus
from app.models.agent_governance import (
    AgentCertification,
    AgentGovernancePolicy,
    AgentOwnershipHistory,
    CertificationStatus,
    ExpiryBehavior,
    OwnerType,
)
from app.models.audit_log import AuditLog
from app.models.organization import OrganizationMember, SecurityEvent
from app.models.permission import Permission, PermissionStatus
from app.models.policy import Policy, PolicyBinding
from app.models.trust_registry import AgentCredential, CredentialStatus
from app.models.user import User
from app.services.agent_lifecycle import get_governance_policy, transition_lifecycle


def generate_certification_id() -> str:
    """Generate unique public ID for an agent certification review."""
    return f"cert_{secrets.token_hex(12)}"


# ---------------------------------------------------------------------------
# 1. Ownership Management & Transfer Workflow
# ---------------------------------------------------------------------------

def transfer_agent_ownership(
    db: Session,
    agent: Agent,
    new_owner_id: UUID | str,
    new_owner_type: str | OwnerType,
    reason: str,
    changed_by_user_id: Optional[UUID] = None,
    new_team: Optional[str] = None,
) -> AgentOwnershipHistory:
    """Atomically transfer agent ownership and record immutable audit history."""
    old_owner_type = agent.owner_type or "USER"
    old_owner_id = str(agent.owner_id)

    owner_type_str = new_owner_type.value if isinstance(new_owner_type, OwnerType) else str(new_owner_type).upper()
    now_utc = datetime.now(timezone.utc)

    # Record history
    history = AgentOwnershipHistory(
        agent_id=agent.id,
        organization_id=agent.organization_id,
        old_owner_type=old_owner_type,
        old_owner_id=old_owner_id,
        new_owner_type=owner_type_str,
        new_owner_id=str(new_owner_id),
        changed_by=changed_by_user_id,
        reason=reason,
        changed_at=now_utc,
    )
    db.add(history)

    # If owner_type is USER, update owner_id if valid UUID
    if owner_type_str == "USER":
        if isinstance(new_owner_id, UUID):
            agent.owner_id = new_owner_id
        else:
            try:
                agent.owner_id = UUID(str(new_owner_id))
            except ValueError:
                pass

    agent.owner_type = owner_type_str
    if new_team is not None:
        agent.team = new_team

    # Audit security event
    if agent.organization_id:
        db.add(
            SecurityEvent(
                organization_id=agent.organization_id,
                event_type="agent_ownership_transferred",
                severity="info",
                description=f"Ownership of agent '{agent.name}' ({agent.agent_identifier}) was transferred from {old_owner_id} ({old_owner_type}) to {new_owner_id} ({owner_type_str}).",
                details={
                    "agent_id": str(agent.id),
                    "old_owner_id": old_owner_id,
                    "new_owner_id": str(new_owner_id),
                    "reason": reason,
                    "changed_by": str(changed_by_user_id) if changed_by_user_id else "system",
                },
            )
        )

    db.commit()
    db.refresh(agent)
    db.refresh(history)
    return history


def detect_orphaned_agents(db: Session, organization_id: Optional[UUID]) -> List[Dict[str, Any]]:
    """Identify agents whose primary owner no longer exists or is not an active org member."""
    query = select(Agent)
    if organization_id:
        query = query.where(Agent.organization_id == organization_id)
    agents = db.scalars(query).all()

    orphaned = []
    for ag in agents:
        signals = []
        if not ag.owner_id:
            signals.append("OWNER_MISSING")
        else:
            owner_user = db.scalar(select(User).where(User.id == ag.owner_id))
            if not owner_user:
                signals.append("OWNER_MISSING")
            elif organization_id:
                member = db.scalar(
                    select(OrganizationMember).where(
                        OrganizationMember.organization_id == organization_id,
                        OrganizationMember.user_id == ag.owner_id,
                    )
                )
                if not member:
                    signals.append("OWNER_DISABLED")

        if signals:
            orphaned.append({
                "agent_id": str(ag.id),
                "agent_identifier": ag.agent_identifier,
                "name": ag.name,
                "status": ag.status.value,
                "owner_id": str(ag.owner_id) if ag.owner_id else None,
                "owner_type": ag.owner_type,
                "team": ag.team,
                "signals": signals,
            })
    return orphaned


# ---------------------------------------------------------------------------
# 2. Agent Certification & Periodic Access Review
# ---------------------------------------------------------------------------

def capture_agent_governance_snapshot(db: Session, agent: Agent) -> Dict[str, Any]:
    """Capture a comprehensive point-in-time posture snapshot for certification."""
    # 1. Permissions
    permissions = db.scalars(
        select(Permission).where(Permission.agent_id == agent.id)
    ).all()
    perms_data = [
        {
            "id": str(p.id),
            "action": p.action,
            "resource": p.resource,
            "conditions": getattr(p, "conditions", None),
            "status": p.status.value if hasattr(p.status, "value") else str(p.status),
        }
        for p in permissions
    ]

    # 2. Credentials
    credentials = db.scalars(
        select(AgentCredential).where(AgentCredential.subject_agent_id == agent.id)
    ).all()
    creds_data = [
        {
            "credential_id": c.credential_id,
            "credential_type": c.credential_type,
            "status": c.status,
            "expires_at": c.expires_at.isoformat() if c.expires_at else None,
        }
        for c in credentials
    ]

    # 3. Delegations
    delegations = db.scalars(
        select(AgentDelegation).where(
            or_(AgentDelegation.parent_agent_id == agent.id, AgentDelegation.child_agent_id == agent.id)
        )
    ).all()
    delegations_data = [
        {
            "delegation_id": d.delegation_id,
            "parent_agent_id": str(d.parent_agent_id),
            "child_agent_id": str(d.child_agent_id),
            "status": d.status.value if hasattr(d.status, "value") else str(d.status),
            "actions": [d.action] if hasattr(d, "action") else [],
        }
        for d in delegations
    ]

    # 4. Policy bindings
    policy_bindings = db.scalars(
        select(PolicyBinding).where(
            PolicyBinding.scope_type == "agent",
            PolicyBinding.scope_id == agent.agent_identifier,
        )
    ).all()
    policies_data = [
        {
            "binding_id": str(pb.id),
            "policy_id": str(pb.policy_id),
            "priority": pb.priority,
            "enabled": pb.enabled,
        }
        for pb in policy_bindings
    ]

    return {
        "snapshot_timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": {
            "id": str(agent.id),
            "identifier": agent.agent_identifier,
            "name": agent.name,
            "status": agent.status.value,
            "owner_type": agent.owner_type,
            "owner_id": str(agent.owner_id),
            "team": agent.team,
            "risk_classification": agent.risk_classification,
            "business_criticality": agent.business_criticality,
            "data_classification": agent.data_classification,
            "purpose": agent.purpose,
        },
        "permissions": perms_data,
        "credentials": creds_data,
        "delegations": delegations_data,
        "policies": policies_data,
    }


def create_certification_review(
    db: Session,
    agent: Agent,
    reviewer_id: Optional[UUID] = None,
    due_days: int = 14,
    notes: Optional[str] = None,
) -> AgentCertification:
    """Initiate an access review certification for an agent."""
    now_utc = datetime.now(timezone.utc)
    due_at = now_utc + timedelta(days=due_days)

    snapshot = capture_agent_governance_snapshot(db, agent)

    cert = AgentCertification(
        certification_id=generate_certification_id(),
        organization_id=agent.organization_id,
        agent_id=agent.id,
        status=CertificationStatus.PENDING,
        reviewer_id=reviewer_id,
        requested_at=now_utc,
        due_at=due_at,
        notes=notes,
        snapshot_reference=snapshot,
    )
    db.add(cert)

    agent.certification_status = "REVIEW_DUE"
    agent.next_review_due_at = due_at

    db.commit()
    db.refresh(cert)
    db.refresh(agent)
    return cert


def complete_certification_review(
    db: Session,
    cert: AgentCertification,
    decision: str,  # APPROVED or REJECTED
    reviewer_id: UUID,
    notes: Optional[str] = None,
) -> AgentCertification:
    """Record the review decision and adjust agent governance attributes."""
    decision_norm = decision.strip().upper()
    now_utc = datetime.now(timezone.utc)
    cert.completed_at = now_utc
    cert.reviewer_id = reviewer_id
    cert.decision = decision_norm
    cert.notes = notes or cert.notes

    agent = db.scalar(select(Agent).where(Agent.id == cert.agent_id))
    policy = get_governance_policy(db, agent.organization_id if agent else None)

    if decision_norm == "APPROVED":
        cert.status = CertificationStatus.APPROVED
        if agent:
            agent.last_reviewed_at = now_utc
            agent.certified_until = now_utc + timedelta(days=policy.periodic_review_days)
            agent.next_review_due_at = agent.certified_until
            agent.certification_status = "CERTIFIED"
    else:
        cert.status = CertificationStatus.REJECTED
        if agent:
            agent.certification_status = "REVOKED"
            if policy.expiry_behavior == ExpiryBehavior.SUSPEND:
                agent.status = AgentStatus.SUSPENDED

    if agent and agent.organization_id:
        db.add(
            SecurityEvent(
                organization_id=agent.organization_id,
                event_type="agent_certification_completed",
                severity="info" if decision_norm == "APPROVED" else "warning",
                description=f"Certification review for '{agent.name}' was {decision_norm} by reviewer {reviewer_id}.",
                details={
                    "certification_id": cert.certification_id,
                    "decision": decision_norm,
                    "reviewer_id": str(reviewer_id),
                    "notes": notes,
                },
            )
        )

    db.commit()
    db.refresh(cert)
    if agent:
        db.refresh(agent)
    return cert


def check_and_apply_certification_expiries(
    db: Session,
    organization_id: Optional[UUID],
) -> List[Dict[str, Any]]:
    """Scan certified agents for expired review periods and enforce organizational policy."""
    now_utc = datetime.now(timezone.utc)
    policy = get_governance_policy(db, organization_id)

    query = select(Agent).where(
        Agent.status == AgentStatus.ACTIVE,
        Agent.certified_until.is_not(None),
        Agent.certified_until < now_utc,
    )
    if organization_id:
        query = query.where(Agent.organization_id == organization_id)

    expired_agents = db.scalars(query).all()
    actions_taken = []

    for ag in expired_agents:
        prev_status = ag.status.value
        ag.certification_status = "EXPIRED"

        if policy.expiry_behavior == ExpiryBehavior.SUSPEND:
            ag.status = AgentStatus.SUSPENDED
            action_desc = "SUSPENDED"
        elif policy.expiry_behavior == ExpiryBehavior.REVIEW_REQUIRED:
            ag.status = AgentStatus.REVIEW_REQUIRED
            action_desc = "MOVED_TO_REVIEW_REQUIRED"
        else:
            action_desc = "ALERTED"

        if ag.organization_id:
            db.add(
                SecurityEvent(
                    organization_id=ag.organization_id,
                    event_type="agent_certification_expired",
                    severity="warning",
                    description=f"Certification expired for active agent '{ag.name}'. Action taken: {action_desc}.",
                    details={
                        "agent_id": str(ag.id),
                        "certified_until": ag.certified_until.isoformat() if ag.certified_until else None,
                        "action_taken": action_desc,
                    },
                )
            )

        actions_taken.append({
            "agent_id": str(ag.id),
            "agent_identifier": ag.agent_identifier,
            "action": action_desc,
            "previous_status": prev_status,
            "new_status": ag.status.value,
        })

    db.commit()
    return actions_taken


# ---------------------------------------------------------------------------
# 3. Governance Signals & Hygiene Detection
# ---------------------------------------------------------------------------

def evaluate_governance_signals(
    db: Session,
    organization_id: Optional[UUID],
    agent_id: Optional[UUID] = None,
) -> List[Dict[str, Any]]:
    """Evaluate comprehensive governance posture signals across agents."""
    now_utc = datetime.now(timezone.utc)
    policy = get_governance_policy(db, organization_id)
    dormancy_cutoff = now_utc - timedelta(days=policy.dormancy_days)

    query = select(Agent)
    if organization_id:
        query = query.where(Agent.organization_id == organization_id)
    if agent_id:
        query = query.where(Agent.id == agent_id)

    agents = db.scalars(query).all()
    results = []

    for ag in agents:
        signals: List[str] = []

        # 1. Owner checks
        if not ag.owner_id:
            signals.append("OWNER_MISSING")
        else:
            owner_user = db.scalar(select(User).where(User.id == ag.owner_id))
            if not owner_user:
                signals.append("OWNER_MISSING")
            elif organization_id:
                member = db.scalar(
                    select(OrganizationMember).where(
                        OrganizationMember.organization_id == organization_id,
                        OrganizationMember.user_id == ag.owner_id,
                    )
                )
                if not member:
                    signals.append("OWNER_DISABLED")

        # 2. Certification checks
        if ag.certified_until:
            cert_until = ag.certified_until.replace(tzinfo=timezone.utc) if ag.certified_until.tzinfo is None else ag.certified_until
            review_due = ag.next_review_due_at.replace(tzinfo=timezone.utc) if (ag.next_review_due_at and ag.next_review_due_at.tzinfo is None) else ag.next_review_due_at

            if cert_until < now_utc:
                signals.append("CERTIFICATION_EXPIRED")
            elif review_due and review_due < now_utc:
                signals.append("REVIEW_OVERDUE")
            elif review_due and (review_due - now_utc).days <= 14:
                signals.append("REVIEW_DUE")
        elif ag.status == AgentStatus.ACTIVE:
            signals.append("REVIEW_DUE")

        # 3. Dormancy check
        ref_time = ag.last_activity_at or ag.created_at
        if ref_time:
            ref_time_aware = ref_time.replace(tzinfo=timezone.utc) if ref_time.tzinfo is None else ref_time
            if ref_time_aware < dormancy_cutoff:
                signals.append("AGENT_DORMANT")

        # 4. Permissions check (broad / wildcard)
        perms = db.scalars(select(Permission).where(Permission.agent_id == ag.id)).all()
        for p in perms:
            if p.action == "*" or p.resource == "*":
                signals.append("BROAD_PERMISSION")
                break

        if signals:
            results.append({
                "agent_id": str(ag.id),
                "agent_identifier": ag.agent_identifier,
                "name": ag.name,
                "status": ag.status.value,
                "risk_classification": ag.risk_classification,
                "signals": sorted(list(set(signals))),
            })

    return results


# ---------------------------------------------------------------------------
# 4. Dependency & Blast-Radius Graph
# ---------------------------------------------------------------------------

def calculate_blast_radius_graph(db: Session, agent_id: UUID) -> Dict[str, Any]:
    """Construct an authoritative node-and-edge dependency graph for an agent."""
    agent = db.scalar(select(Agent).where(Agent.id == agent_id))
    if not agent:
        raise ValueError(f"Agent with ID '{agent_id}' not found.")

    nodes: List[Dict[str, Any]] = [
        {
            "id": f"agent:{str(agent.id)}",
            "type": "agent",
            "label": agent.name,
            "identifier": agent.agent_identifier,
            "status": agent.status.value,
            "risk_classification": agent.risk_classification,
            "is_root": True,
        }
    ]
    edges: List[Dict[str, Any]] = []
    seen_node_ids: Set[str] = {f"agent:{str(agent.id)}"}

    # 1. Incoming delegations (callers who delegated to this agent)
    incoming = db.scalars(
        select(AgentDelegation).where(AgentDelegation.child_agent_id == agent.id)
    ).all()
    for d in incoming:
        parent_agent = db.scalar(select(Agent).where(Agent.id == d.parent_agent_id))
        if parent_agent:
            p_node_id = f"agent:{str(parent_agent.id)}"
            if p_node_id not in seen_node_ids:
                nodes.append({
                    "id": p_node_id,
                    "type": "caller_agent",
                    "label": parent_agent.name,
                    "identifier": parent_agent.agent_identifier,
                    "status": parent_agent.status.value,
                    "risk_classification": parent_agent.risk_classification,
                })
                seen_node_ids.add(p_node_id)
            edges.append({
                "source": p_node_id,
                "target": f"agent:{str(agent.id)}",
                "relationship": "DELEGATES_TO",
                "status": d.status.value if hasattr(d.status, "value") else str(d.status),
                "actions": [d.action] if hasattr(d, "action") else [],
            })

    # 2. Outgoing delegations (targets this agent delegated authority to)
    outgoing = db.scalars(
        select(AgentDelegation).where(AgentDelegation.parent_agent_id == agent.id)
    ).all()
    for d in outgoing:
        child_agent = db.scalar(select(Agent).where(Agent.id == d.child_agent_id))
        if child_agent:
            c_node_id = f"agent:{str(child_agent.id)}"
            if c_node_id not in seen_node_ids:
                nodes.append({
                    "id": c_node_id,
                    "type": "target_agent",
                    "label": child_agent.name,
                    "identifier": child_agent.agent_identifier,
                    "status": child_agent.status.value,
                    "risk_classification": child_agent.risk_classification,
                })
                seen_node_ids.add(c_node_id)
            edges.append({
                "source": f"agent:{str(agent.id)}",
                "target": c_node_id,
                "relationship": "DELEGATED_AUTHORITY_TO",
                "status": d.status.value if hasattr(d.status, "value") else str(d.status),
                "actions": [d.action] if hasattr(d, "action") else [],
            })

    # 3. Active Credentials
    creds = db.scalars(
        select(AgentCredential).where(
            AgentCredential.subject_agent_id == agent.id,
            AgentCredential.status == CredentialStatus.ACTIVE.value,
        )
    ).all()
    for c in creds:
        cred_node_id = f"credential:{c.credential_id}"
        if cred_node_id not in seen_node_ids:
            nodes.append({
                "id": cred_node_id,
                "type": "credential",
                "label": c.credential_type,
                "identifier": c.credential_id,
                "status": c.status,
            })
            seen_node_ids.add(cred_node_id)
        edges.append({
            "source": f"agent:{str(agent.id)}",
            "target": cred_node_id,
            "relationship": "HOLDS_CREDENTIAL",
        })

    # 4. Bound Policies
    bindings = db.scalars(
        select(PolicyBinding).where(
            PolicyBinding.scope_type == "agent",
            PolicyBinding.scope_id == agent.agent_identifier,
            PolicyBinding.enabled.is_(True),
        )
    ).all()
    for pb in bindings:
        policy = db.scalar(select(Policy).where(Policy.id == pb.policy_id))
        if policy:
            pol_node_id = f"policy:{policy.policy_id}"
            if pol_node_id not in seen_node_ids:
                nodes.append({
                    "id": pol_node_id,
                    "type": "policy",
                    "label": policy.name,
                    "identifier": policy.policy_id,
                    "status": policy.status,
                })
                seen_node_ids.add(pol_node_id)
            edges.append({
                "source": pol_node_id,
                "target": f"agent:{str(agent.id)}",
                "relationship": "GOVERNS_AGENT",
            })

    # Compute blast radius metrics
    connected_agents_count = sum(1 for n in nodes if n["type"] in ("caller_agent", "target_agent"))
    risk_factor = 1.0
    if agent.risk_classification == "CRITICAL":
        risk_factor = 4.0
    elif agent.risk_classification == "HIGH":
        risk_factor = 2.5
    elif agent.risk_classification == "MEDIUM":
        risk_factor = 1.5

    blast_radius_score = int((connected_agents_count * 10 + len(creds) * 5 + len(bindings) * 2) * risk_factor)

    return {
        "root_agent_id": str(agent.id),
        "root_agent_name": agent.name,
        "nodes": nodes,
        "edges": edges,
        "metrics": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "connected_agents_count": connected_agents_count,
            "active_credentials_count": len(creds),
            "bound_policies_count": len(bindings),
            "blast_radius_score": blast_radius_score,
        },
    }


# ---------------------------------------------------------------------------
# 5. Executive Dashboard Metrics
# ---------------------------------------------------------------------------

def get_executive_governance_kpis(db: Session, organization_id: Optional[UUID]) -> Dict[str, Any]:
    """Calculate high-level enterprise governance KPIs for the dashboard."""
    query = select(Agent)
    if organization_id:
        query = query.where(Agent.organization_id == organization_id)
    agents = db.scalars(query).all()

    total_count = len(agents)
    status_counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}

    for ag in agents:
        s = ag.status.value
        status_counts[s] = status_counts.get(s, 0) + 1
        rc = (ag.risk_classification or "LOW").upper()
        risk_counts[rc] = risk_counts.get(rc, 0) + 1

    signals = evaluate_governance_signals(db, organization_id)
    signal_counts: Dict[str, int] = {}
    for item in signals:
        for sig in item["signals"]:
            signal_counts[sig] = signal_counts.get(sig, 0) + 1

    # Pending certifications
    cert_query = select(func.count(AgentCertification.id)).where(
        AgentCertification.status == CertificationStatus.PENDING
    )
    if organization_id:
        cert_query = cert_query.where(AgentCertification.organization_id == organization_id)
    pending_certs = db.scalar(cert_query) or 0

    return {
        "total_agents": total_count,
        "active_agents": status_counts.get(AgentStatus.ACTIVE.value, 0),
        "draft_agents": status_counts.get(AgentStatus.DRAFT.value, 0),
        "review_required_agents": status_counts.get(AgentStatus.REVIEW_REQUIRED.value, 0),
        "suspended_agents": status_counts.get(AgentStatus.SUSPENDED.value, 0),
        "retired_agents": status_counts.get(AgentStatus.RETIRED.value, 0),
        "pending_reviews_count": pending_certs,
        "risk_breakdown": risk_counts,
        "signal_breakdown": signal_counts,
        "orphaned_count": signal_counts.get("OWNER_MISSING", 0) + signal_counts.get("OWNER_DISABLED", 0),
        "dormant_count": signal_counts.get("AGENT_DORMANT", 0),
        "overdue_count": signal_counts.get("REVIEW_OVERDUE", 0),
    }


# ---------------------------------------------------------------------------
# 6. Bulk Governance Operations & Import / Export
# ---------------------------------------------------------------------------

def execute_bulk_governance(
    db: Session,
    organization_id: Optional[UUID],
    action: str,
    agent_ids: List[UUID | str],
    params: Dict[str, Any],
    acting_user_id: Optional[UUID] = None,
) -> Dict[str, Any]:
    """Execute bulk operations across multiple agents with tenant safety."""
    action_norm = action.strip().lower()
    processed: List[str] = []
    errors: List[Dict[str, str]] = []

    for raw_id in agent_ids:
        try:
            aid = raw_id if isinstance(raw_id, UUID) else UUID(str(raw_id))
            agent = db.scalar(select(Agent).where(Agent.id == aid))
            if not agent:
                errors.append({"agent_id": str(raw_id), "error": "Agent not found"})
                continue
            if organization_id and agent.organization_id != organization_id:
                errors.append({"agent_id": str(raw_id), "error": "Tenant access denied"})
                continue

            if action_norm == "transfer_owner":
                new_owner_id = params.get("new_owner_id")
                new_owner_type = params.get("new_owner_type", "USER")
                reason = params.get("reason", "Bulk ownership transfer")
                transfer_agent_ownership(
                    db, agent, new_owner_id, new_owner_type, reason, acting_user_id, params.get("new_team")
                )
                processed.append(str(agent.id))

            elif action_norm == "trigger_review":
                due_days = int(params.get("due_days", 14))
                notes = params.get("notes", "Triggered via bulk governance")
                create_certification_review(db, agent, reviewer_id=acting_user_id, due_days=due_days, notes=notes)
                processed.append(str(agent.id))

            elif action_norm == "suspend":
                reason = params.get("reason", "Bulk emergency suspension")
                transition_lifecycle(
                    db, agent, AgentStatus.SUSPENDED, acting_user_id=acting_user_id, reason=reason
                )
                processed.append(str(agent.id))

            elif action_norm == "add_tags":
                new_tags = params.get("tags", [])
                existing = set(agent.tags or [])
                existing.update(new_tags)
                agent.tags = list(existing)
                db.commit()
                processed.append(str(agent.id))

            else:
                errors.append({"agent_id": str(raw_id), "error": f"Unsupported bulk action '{action}'"})

        except Exception as exc:
            errors.append({"agent_id": str(raw_id), "error": str(exc)})

    return {
        "action": action_norm,
        "processed_count": len(processed),
        "failed_count": len(errors),
        "processed_agent_ids": processed,
        "errors": errors,
    }


def export_agent_inventory(
    db: Session,
    organization_id: Optional[UUID],
    format: str = "json",
) -> str:
    """Export authoritative agent inventory in JSON or CSV format."""
    query = select(Agent)
    if organization_id:
        query = query.where(Agent.organization_id == organization_id)
    agents = db.scalars(query).all()

    records = []
    for ag in agents:
        records.append({
            "agent_identifier": ag.agent_identifier,
            "name": ag.name,
            "description": ag.description or "",
            "status": ag.status.value,
            "owner_type": ag.owner_type,
            "owner_id": str(ag.owner_id) if ag.owner_id else "",
            "team": ag.team or "",
            "purpose": ag.purpose or "",
            "business_function": ag.business_function or "",
            "risk_classification": ag.risk_classification,
            "business_criticality": ag.business_criticality,
            "data_classification": ag.data_classification,
            "source": ag.source,
            "tags": json.dumps(ag.tags or []),
            "certification_status": ag.certification_status,
            "certified_until": ag.certified_until.isoformat() if ag.certified_until else "",
            "created_at": ag.created_at.isoformat() if ag.created_at else "",
        })

    if format.lower() == "csv":
        output = io.StringIO()
        if records:
            writer = csv.DictWriter(output, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)
        return output.getvalue()

    return json.dumps(records, indent=2)


def import_agent_inventory(
    db: Session,
    organization_id: Optional[UUID],
    records: List[Dict[str, Any]],
    default_owner_id: UUID,
    source: str = "IMPORT",
) -> Dict[str, Any]:
    """Import and validate agent records into inventory."""
    imported: List[str] = []
    errors: List[Dict[str, str]] = []

    for i, rec in enumerate(records):
        identifier = rec.get("agent_identifier") or rec.get("id") or f"imported-agent-{secrets.token_hex(4)}"
        name = rec.get("name") or identifier

        try:
            existing = db.scalar(select(Agent).where(Agent.agent_identifier == identifier))
            if existing:
                errors.append({"record_index": str(i), "identifier": identifier, "error": "Agent identifier already exists"})
                continue

            owner_id_val = default_owner_id
            if rec.get("owner_id"):
                try:
                    owner_id_val = UUID(str(rec["owner_id"]))
                except ValueError:
                    pass

            agent = Agent(
                name=name,
                description=rec.get("description"),
                agent_identifier=identifier,
                owner_id=owner_id_val,
                organization_id=organization_id,
                status=AgentStatus.REGISTERED,
                owner_type=rec.get("owner_type", "USER"),
                team=rec.get("team"),
                purpose=rec.get("purpose"),
                business_function=rec.get("business_function"),
                risk_classification=rec.get("risk_classification", "LOW"),
                business_criticality=rec.get("business_criticality", "LOW"),
                data_classification=rec.get("data_classification", "INTERNAL"),
                source=source,
                tags=rec.get("tags") if isinstance(rec.get("tags"), list) else [],
            )
            db.add(agent)
            db.commit()
            imported.append(identifier)
        except Exception as exc:
            db.rollback()
            errors.append({"record_index": str(i), "identifier": identifier, "error": str(exc)})

    return {
        "imported_count": len(imported),
        "failed_count": len(errors),
        "imported_identifiers": imported,
        "errors": errors,
    }
