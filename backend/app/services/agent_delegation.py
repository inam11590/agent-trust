"""Business logic for Agent-to-Agent Trust and Delegation (Step 19)."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation, DelegationStatus, generate_delegation_id
from app.models.permission import Permission, PermissionStatus
from app.models.user import User
from app.schemas.agent_delegation import (
    AgentDelegationCreate,
    DelegationChainNode,
    DelegationChainResponse,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_delegation(
    db: Session,
    payload: AgentDelegationCreate,
    current_user: User | None = None,
    acting_agent: Agent | None = None,
) -> AgentDelegation:
    """Create a new validated agent-to-agent delegation."""
    checked_at = utc_now()

    # 1. No self-delegation
    if payload.parent_agent_id == payload.child_agent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-delegation is strictly prohibited",
        )

    # 2. Fetch parent and child agents
    parent_agent = db.get(Agent, payload.parent_agent_id)
    if not parent_agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parent agent not found",
        )
    if parent_agent.status != AgentStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parent agent is not active",
        )

    child_agent = db.get(Agent, payload.child_agent_id)
    if not child_agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Child agent not found",
        )
    if child_agent.status != AgentStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Child agent is not active",
        )

    # 3. Intra-organization rule
    if not parent_agent.organization_id or not child_agent.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Both agents must belong to an organization for delegation",
        )
    if parent_agent.organization_id != child_agent.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cross-organization delegation is strictly forbidden",
        )

    organization_id = parent_agent.organization_id

    # 4. Fetch and validate root/parent permission
    parent_permission = db.get(Permission, payload.parent_permission_id)
    if not parent_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Parent permission not found",
        )
    if parent_permission.agent_id != parent_agent.id and payload.parent_delegation_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parent permission does not belong to the parent agent",
        )
    if not parent_permission.is_usable(checked_at):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parent permission is not active or has expired",
        )
    if not parent_permission.allow_delegation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parent permission does not permit delegation (allow_delegation=False)",
        )

    # 5. Handle Chained Delegation or Root Delegation
    if payload.parent_delegation_id is not None:
        parent_delegation = db.get(AgentDelegation, payload.parent_delegation_id)
        if not parent_delegation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent delegation not found",
            )
        if parent_delegation.status != DelegationStatus.ACTIVE or not parent_delegation.is_usable(checked_at):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent delegation is inactive, revoked, or expired",
            )
        if parent_delegation.child_agent_id != parent_agent.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent agent must be the recipient/child of the parent delegation",
            )
        if not parent_delegation.allow_further_delegation:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent delegation does not allow further sub-delegation",
            )
        if parent_delegation.parent_permission_id != parent_permission.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent delegation does not match specified parent permission",
            )

        current_depth = parent_delegation.current_depth + 1
        effective_max_depth = min(parent_delegation.max_delegation_depth, payload.max_delegation_depth)
        if current_depth > effective_max_depth:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegation depth {current_depth} exceeds maximum allowed depth {effective_max_depth}",
            )

        # Transitive Cycle Detection
        ancestor = parent_delegation
        ancestor_agents = {child_agent.id, parent_agent.id}
        while ancestor is not None:
            if ancestor.parent_agent_id in ancestor_agents:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Delegation cycle detected in ancestor chain",
                )
            ancestor_agents.add(ancestor.parent_agent_id)
            if ancestor.parent_delegation_id:
                ancestor = db.get(AgentDelegation, ancestor.parent_delegation_id)
            else:
                break

        # Narrowing checks against parent_delegation
        if payload.action != parent_delegation.action:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegated action '{payload.action}' must match parent action '{parent_delegation.action}'",
            )
        if payload.resource != parent_delegation.resource:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegated resource '{payload.resource}' must match parent resource '{parent_delegation.resource}'",
            )
        if parent_delegation.maximum_amount is not None:
            if payload.maximum_amount is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Parent delegation requires an amount constraint; delegated amount cannot be unbounded",
                )
            if payload.maximum_amount > parent_delegation.maximum_amount:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Delegated amount {payload.maximum_amount} exceeds parent delegation limit {parent_delegation.maximum_amount}",
                )
            if payload.currency != parent_delegation.currency:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Delegated currency '{payload.currency}' must match parent currency '{parent_delegation.currency}'",
                )

        if payload.expires_at > parent_delegation.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegated expiry {payload.expires_at.isoformat()} cannot exceed parent delegation expiry {parent_delegation.expires_at.isoformat()}",
            )

        if parent_delegation.requires_approval and not payload.requires_approval:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent delegation requires approval; cannot drop approval requirement",
            )

    else:
        # Direct delegation from root permission (Depth 1)
        current_depth = 1
        effective_max_depth = payload.max_delegation_depth

        # Narrowing checks against parent_permission
        if payload.action != parent_permission.action:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegated action '{payload.action}' must match parent permission action '{parent_permission.action}'",
            )
        if payload.resource != parent_permission.resource:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegated resource '{payload.resource}' must match parent permission resource '{parent_permission.resource}'",
            )
        if parent_permission.maximum_amount is not None:
            if payload.maximum_amount is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Parent permission requires an amount constraint; delegated amount cannot be unbounded",
                )
            if payload.maximum_amount > parent_permission.maximum_amount:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Delegated amount {payload.maximum_amount} exceeds parent permission limit {parent_permission.maximum_amount}",
                )
            if payload.currency != parent_permission.currency:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Delegated currency '{payload.currency}' must match parent currency '{parent_permission.currency}'",
                )

        if payload.expires_at > parent_permission.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Delegated expiry {payload.expires_at.isoformat()} cannot exceed parent permission expiry {parent_permission.expires_at.isoformat()}",
            )

        if parent_permission.requires_approval and not payload.requires_approval:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent permission requires approval; cannot drop approval requirement",
            )

    delegation = AgentDelegation(
        delegation_id=generate_delegation_id(),
        parent_agent_id=payload.parent_agent_id,
        child_agent_id=payload.child_agent_id,
        parent_permission_id=payload.parent_permission_id,
        parent_delegation_id=payload.parent_delegation_id,
        organization_id=organization_id,
        action=payload.action,
        resource=payload.resource,
        maximum_amount=payload.maximum_amount,
        currency=payload.currency,
        requires_approval=payload.requires_approval,
        allow_further_delegation=payload.allow_further_delegation,
        current_depth=current_depth,
        max_delegation_depth=effective_max_depth,
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
        status=DelegationStatus.ACTIVE,
    )
    db.add(delegation)
    db.commit()
    db.refresh(delegation)
    return delegation


def verify_delegation_chain(
    db: Session,
    delegation_id: str,
    action: str,
    resource: str,
    amount: Decimal | None = None,
    currency: str | None = None,
    at: datetime | None = None,
    child_agent_id: UUID | None = None,
    organization_id: UUID | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Verify an entire delegation chain from child up to root permission at execution time."""
    checked_at = at or utc_now()

    delegation = db.scalar(
        select(AgentDelegation).where(AgentDelegation.delegation_id == delegation_id)
    )
    if not delegation:
        return False, "DELEGATION_NOT_FOUND", {}

    # Intra-organization scope check
    if organization_id and delegation.organization_id != organization_id:
        return False, "DELEGATION_CROSS_ORG_FORBIDDEN", {}

    # Child agent check
    if child_agent_id and delegation.child_agent_id != child_agent_id:
        return False, "DELEGATION_CHILD_AGENT_MISMATCH", {}

    # Traverse chain
    current: AgentDelegation | None = delegation
    seen_agents: set[UUID] = set()
    chain_nodes: list[AgentDelegation] = []

    effective_requires_approval = False
    effective_max_amount: Decimal | None = None
    effective_currency: str | None = None
    effective_expires_at: datetime = delegation.expires_at

    while current is not None:
        chain_nodes.append(current)

        # Check delegation live status and validity window
        if current.status == DelegationStatus.REVOKED:
            return False, "DELEGATION_REVOKED", {"delegation_id": current.delegation_id}
        if current.status == DelegationStatus.SUSPENDED:
            return False, "DELEGATION_SUSPENDED", {"delegation_id": current.delegation_id}
        if current.status == DelegationStatus.EXPIRED or checked_at >= current.expires_at:
            return False, "DELEGATION_EXPIRED", {"delegation_id": current.delegation_id}
        if checked_at < current.valid_from:
            return False, "DELEGATION_NOT_YET_VALID", {"delegation_id": current.delegation_id}

        # Check child agent status
        child_agent = db.get(Agent, current.child_agent_id)
        if not child_agent or child_agent.status != AgentStatus.ACTIVE:
            return False, "CHILD_AGENT_INACTIVE", {"agent_id": current.child_agent_id}

        # Check parent agent status
        parent_agent = db.get(Agent, current.parent_agent_id)
        if not parent_agent or parent_agent.status != AgentStatus.ACTIVE:
            return False, "PARENT_AGENT_INACTIVE", {"agent_id": current.parent_agent_id}

        # Cycle detection
        if current.child_agent_id in seen_agents or current.parent_agent_id in seen_agents:
            return False, "DELEGATION_CYCLE_DETECTED", {"delegation_id": current.delegation_id}
        seen_agents.add(current.child_agent_id)

        # Action and resource match
        if current.action != action:
            return False, "DELEGATION_ACTION_MISMATCH", {"delegation_id": current.delegation_id}
        if current.resource != resource:
            return False, "DELEGATION_RESOURCE_MISMATCH", {"delegation_id": current.delegation_id}

        # Accumulate effective restrictions
        if current.requires_approval:
            effective_requires_approval = True

        if current.expires_at < effective_expires_at:
            effective_expires_at = current.expires_at

        if current.maximum_amount is not None:
            if effective_max_amount is None or current.maximum_amount < effective_max_amount:
                effective_max_amount = current.maximum_amount
                effective_currency = current.currency

        if current.parent_delegation_id:
            current = db.get(AgentDelegation, current.parent_delegation_id)
        else:
            break

    # Now verify the root permission
    root_delegation = chain_nodes[-1]
    root_permission = db.get(Permission, root_delegation.parent_permission_id)
    if not root_permission:
        return False, "PARENT_PERMISSION_NOT_FOUND", {}

    if root_permission.status == PermissionStatus.REVOKED:
        return False, "PARENT_PERMISSION_REVOKED", {"permission_id": str(root_permission.id)}
    if root_permission.status == PermissionStatus.EXPIRED or checked_at >= root_permission.expires_at:
        return False, "PARENT_PERMISSION_EXPIRED", {"permission_id": str(root_permission.id)}
    if root_permission.status != PermissionStatus.ACTIVE or not root_permission.is_usable(checked_at):
        return False, "PARENT_PERMISSION_INACTIVE", {"permission_id": str(root_permission.id)}

    if not root_permission.allow_delegation:
        return False, "DELEGATION_NOT_ALLOWED_BY_PARENT_PERMISSION", {"permission_id": str(root_permission.id)}

    # Root permission owner / agent
    root_agent = db.get(Agent, root_permission.agent_id)
    if not root_agent or root_agent.status != AgentStatus.ACTIVE:
        return False, "PARENT_AGENT_INACTIVE", {"agent_id": root_permission.agent_id}

    if root_permission.action != action:
        return False, "DELEGATION_ACTION_MISMATCH", {}
    if root_permission.resource != resource:
        return False, "DELEGATION_RESOURCE_MISMATCH", {}

    if root_permission.requires_approval:
        effective_requires_approval = True

    if root_permission.expires_at < effective_expires_at:
        effective_expires_at = root_permission.expires_at

    if root_permission.maximum_amount is not None:
        if effective_max_amount is None or root_permission.maximum_amount < effective_max_amount:
            effective_max_amount = root_permission.maximum_amount
            effective_currency = root_permission.currency

    # Validate amount against effective constraints
    if amount is not None:
        if effective_max_amount is None:
            return False, "AMOUNT_NOT_PERMITTED", {}
        if currency != effective_currency:
            return False, "CURRENCY_MISMATCH", {
                "expected": effective_currency,
                "provided": currency,
            }
        if amount > effective_max_amount:
            return False, "AMOUNT_EXCEEDS_DELEGATION_LIMIT", {
                "effective_max_amount": effective_max_amount,
                "amount": amount,
            }

    metadata = {
        "delegation": delegation,
        "root_permission": root_permission,
        "parent_agent_id": delegation.parent_agent_id,
        "root_agent_id": root_permission.agent_id,
        "effective_requires_approval": effective_requires_approval,
        "effective_maximum_amount": effective_max_amount,
        "effective_currency": effective_currency,
        "effective_expires_at": effective_expires_at,
        "depth": len(chain_nodes),
    }
    return True, "OK", metadata


def revoke_delegation(
    db: Session,
    delegation_id: str,
    revoked_by_user_id: UUID | None = None,
    revoked_by_agent_id: UUID | None = None,
    reason: str | None = None,
    cascade: bool = True,
) -> AgentDelegation:
    """Revoke a delegation and cascade revocation down the transitive tree."""
    delegation = db.scalar(
        select(AgentDelegation).where(AgentDelegation.delegation_id == delegation_id)
    )
    if not delegation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Delegation not found",
        )

    now = utc_now()
    delegation.status = DelegationStatus.REVOKED
    delegation.revoked_at = now
    delegation.revocation_reason = reason or "Revoked by user/agent"
    delegation.revoked_by_user_id = revoked_by_user_id
    delegation.revoked_by_agent_id = revoked_by_agent_id

    if cascade:
        # Cascade to all downstream delegations
        queue = [delegation.id]
        while queue:
            parent_id = queue.pop(0)
            children = list(
                db.scalars(
                    select(AgentDelegation).where(
                        AgentDelegation.parent_delegation_id == parent_id,
                        AgentDelegation.status == DelegationStatus.ACTIVE,
                    )
                )
            )
            for child in children:
                child.status = DelegationStatus.REVOKED
                child.revoked_at = now
                child.revocation_reason = f"Cascade revocation from parent delegation: {reason or 'Parent revoked'}"
                child.revoked_by_user_id = revoked_by_user_id
                child.revoked_by_agent_id = revoked_by_agent_id
                queue.append(child.id)

    db.commit()
    db.refresh(delegation)
    return delegation


def get_delegation_chain(db: Session, delegation_id: str) -> DelegationChainResponse:
    """Retrieve full transitive chain and calculate effective bounds for UI/audit."""
    delegation = db.scalar(
        select(AgentDelegation).where(AgentDelegation.delegation_id == delegation_id)
    )
    if not delegation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Delegation not found",
        )

    is_valid, validation_reason, metadata = verify_delegation_chain(
        db,
        delegation_id=delegation_id,
        action=delegation.action,
        resource=delegation.resource,
        amount=delegation.maximum_amount,
        currency=delegation.currency,
    )

    # Build chain nodes list
    chain_nodes: list[DelegationChainNode] = []
    current: AgentDelegation | None = delegation
    depth = 0

    while current is not None:
        parent_agent = db.get(Agent, current.parent_agent_id)
        child_agent = db.get(Agent, current.child_agent_id)
        chain_nodes.append(
            DelegationChainNode(
                depth=current.current_depth,
                delegation_id=current.delegation_id,
                parent_agent_id=current.parent_agent_id,
                parent_agent_name=parent_agent.name if parent_agent else None,
                child_agent_id=current.child_agent_id,
                child_agent_name=child_agent.name if child_agent else None,
                action=current.action,
                resource=current.resource,
                maximum_amount=current.maximum_amount,
                currency=current.currency,
                requires_approval=current.requires_approval,
                status=current.status.value,
                valid_from=current.valid_from,
                expires_at=current.expires_at,
            )
        )
        if current.parent_delegation_id:
            current = db.get(AgentDelegation, current.parent_delegation_id)
        else:
            break

    # Add root permission node at top
    root_delegation = chain_nodes[-1]
    root_permission = db.get(Permission, delegation.parent_permission_id)
    if root_permission:
        root_agent = db.get(Agent, root_permission.agent_id)
        chain_nodes.append(
            DelegationChainNode(
                depth=0,
                delegation_id=None,
                parent_agent_id=None,
                parent_agent_name="Root User Permission",
                child_agent_id=root_permission.agent_id,
                child_agent_name=root_agent.name if root_agent else None,
                action=root_permission.action,
                resource=root_permission.resource,
                maximum_amount=root_permission.maximum_amount,
                currency=root_permission.currency,
                requires_approval=root_permission.requires_approval,
                status=root_permission.status.value,
                valid_from=root_permission.valid_from,
                expires_at=root_permission.expires_at,
            )
        )

    # Order from Root (depth 0) down to Child
    chain_nodes.reverse()

    return DelegationChainResponse(
        delegation_id=delegation.delegation_id,
        root_permission_id=delegation.parent_permission_id,
        is_valid=is_valid,
        validation_error=None if is_valid else validation_reason,
        effective_action=delegation.action,
        effective_resource=delegation.resource,
        effective_maximum_amount=metadata.get("effective_maximum_amount", delegation.maximum_amount),
        effective_currency=metadata.get("effective_currency", delegation.currency),
        effective_requires_approval=metadata.get("effective_requires_approval", delegation.requires_approval),
        effective_expires_at=metadata.get("effective_expires_at", delegation.expires_at),
        chain=chain_nodes,
    )


def list_delegations(
    db: Session,
    organization_id: UUID,
    status_filter: DelegationStatus | None = None,
    agent_id: UUID | None = None,
) -> list[AgentDelegation]:
    """List delegations within an organization, optionally filtered by status or agent."""
    query = select(AgentDelegation).where(AgentDelegation.organization_id == organization_id)
    if status_filter:
        query = query.where(AgentDelegation.status == status_filter)
    if agent_id:
        query = query.where(
            or_(
                AgentDelegation.parent_agent_id == agent_id,
                AgentDelegation.child_agent_id == agent_id,
            )
        )
    query = query.order_by(AgentDelegation.created_at.desc())
    return list(db.scalars(query))

