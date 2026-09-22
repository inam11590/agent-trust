"""Enterprise Agent Governance Pydantic schemas (Step 28)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AgentLifecycleTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_status: str = Field(description="Desired target status (e.g. active, suspended, retired, review_required)")
    reason: Optional[str] = Field(default=None, max_length=1000)
    bypass_checklist: bool = Field(default=False, description="Admin bypass of validation checklist")


class AgentOwnershipTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_owner_id: str = Field(min_length=1, max_length=255, description="User ID, Team name, or Service Principal")
    new_owner_type: str = Field(default="USER", description="USER, TEAM, or SERVICE_OWNER")
    new_team: Optional[str] = Field(default=None, max_length=128)
    reason: str = Field(min_length=3, max_length=1000, description="Business justification for transfer")


class AgentOwnershipHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_id: UUID
    organization_id: Optional[UUID] = None
    old_owner_type: str
    old_owner_id: str
    new_owner_type: str
    new_owner_id: str
    changed_by: Optional[UUID] = None
    reason: str
    changed_at: datetime


class AgentCertificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    certification_id: str
    organization_id: Optional[UUID] = None
    agent_id: UUID
    status: str
    reviewer_id: Optional[UUID] = None
    requested_at: datetime
    due_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    decision: Optional[str] = None
    notes: Optional[str] = None
    snapshot_reference: Dict[str, Any] = Field(default_factory=dict)


class CreateCertificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Optional[UUID] = None
    reviewer_id: Optional[UUID] = None
    due_days: int = Field(default=14, ge=1, le=365)
    notes: Optional[str] = Field(default=None, max_length=2000)


class DecideCertificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: str = Field(description="APPROVED or REJECTED")
    notes: Optional[str] = Field(default=None, max_length=2000)


class GovernancePolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    organization_id: UUID
    periodic_review_days: int
    expiry_behavior: str
    dormancy_days: int
    enforce_separation_of_duties: bool
    require_classification_on_promotion: bool
    require_purpose_on_promotion: bool


class UpdateGovernancePolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    periodic_review_days: Optional[int] = Field(default=None, ge=1, le=730)
    expiry_behavior: Optional[str] = None  # ALERT_ONLY, REVIEW_REQUIRED, SUSPEND
    dormancy_days: Optional[int] = Field(default=None, ge=1, le=730)
    enforce_separation_of_duties: Optional[bool] = None
    require_classification_on_promotion: Optional[bool] = None
    require_purpose_on_promotion: Optional[bool] = None


class BulkGovernanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(description="transfer_owner, trigger_review, suspend, or add_tags")
    agent_ids: List[str] = Field(min_length=1)
    params: Dict[str, Any] = Field(default_factory=dict)


class ImportInventoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records: List[Dict[str, Any]] = Field(min_length=1)
    source: str = Field(default="IMPORT")


class EmergencySuspendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=1000)


class ReactivateAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Optional[str] = Field(default=None, max_length=1000)


class RetireAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=1000)
    force: bool = Field(default=False, description="Tear down active dependencies and retire immediately")


class RetirementCheckResponse(BaseModel):
    agent_id: str
    agent_identifier: str
    name: str
    can_retire: bool
    has_active_dependencies: bool
    active_incoming_delegations_count: int
    active_outgoing_delegations_count: int
    active_credentials_count: int
    details: Dict[str, Any]
    summary: str


class DependencyGraphResponse(BaseModel):
    root_agent_id: str
    root_agent_name: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    metrics: Dict[str, Any]
