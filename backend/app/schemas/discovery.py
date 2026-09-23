"""Pydantic schemas for Agent Discovery (Step 29)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DiscoverySourceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    source_type: str = Field(...)
    configuration: Dict[str, Any] = Field(default_factory=dict)
    credential_reference: Optional[str] = Field(None, max_length=128)


class DiscoverySourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_id: str
    organization_id: UUID
    name: str
    source_type: str
    status: str
    configuration: Dict[str, Any]
    credential_reference: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    last_success_at: Optional[datetime] = None
    last_error_code: Optional[str] = None
    last_error_message: Optional[str] = None
    resources_examined_count: int
    candidates_found_count: int
    created_at: datetime
    updated_at: datetime


class DiscoveryRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: str
    source_id: UUID
    organization_id: UUID
    status: str
    trigger_type: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    resources_examined: int
    candidates_found: int
    known_matches: int
    unmanaged_found: int
    errors_count: int
    error_summary: Optional[str] = None
    run_summary: Dict[str, Any]


class DiscoveryEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: str
    candidate_id: UUID
    source_id: UUID
    evidence_type: str
    category: str
    strength: str
    details: Dict[str, Any]
    observed_at: datetime


class DiscoveryCandidateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    candidate_id: str
    organization_id: UUID
    source_id: UUID
    external_resource_reference: str
    candidate_type: str
    display_name: str
    environment: str
    location_reference: str
    confidence_score: int
    confidence_level: str
    confidence_reasons: List[str]
    status: str
    matched_agent_id: Optional[UUID] = None
    match_type: Optional[str] = None
    match_reasons: List[str]
    suggested_owner_id: Optional[UUID] = None
    suggested_owner_type: Optional[str] = None
    suggested_owner_name: Optional[str] = None
    suggested_owner_confidence: Optional[str] = None
    suggested_owner_reasons: List[str]
    fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime
    ignored_until: Optional[datetime] = None
    ignore_reason: Optional[str] = None
    false_positive_reason: Optional[str] = None
    evidence_summary: Dict[str, Any]
    relationships: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class MatchCandidateRequest(BaseModel):
    agent_id: str = Field(..., description="Agent UUID or public agent_identifier")


class OnboardCandidateRequest(BaseModel):
    owner_id: UUID = Field(..., description="User ID of primary accountable owner")
    owner_type: str = Field("USER", description="USER, TEAM, or SERVICE_OWNER")
    purpose: Optional[str] = Field(None, min_length=10, max_length=2000)
    risk_classification: str = Field("LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    team: Optional[str] = Field(None, max_length=128)
    business_function: Optional[str] = Field(None, max_length=128)


class IgnoreCandidateRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=255)
    days: int = Field(30, ge=1, le=365)


class FalsePositiveCandidateRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=255)


class DiscoveryDashboardResponse(BaseModel):
    total_candidates: int
    total_sources: int
    new_candidates: int
    needs_review: int
    unmanaged_agents: int
    high_confidence_unmanaged: int
    production_unmanaged: int
    matched_agents: int
    registered_agents: int
    ignored_candidates: int
    false_positives: int
    stale_candidates: int
    sources_with_errors: int
