"""Pydantic Schemas for APL/1.0 Policies, Versions, Validation, Simulator, and Rollback."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[str] = Field("General", max_length=100)
    tags: Optional[List[str]] = Field(default_factory=list)
    target: Optional[Dict[str, Any]] = Field(default_factory=dict)
    initial_yaml_source: Optional[str] = None


class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[str] = Field(None, max_length=100)
    tags: Optional[List[str]] = None
    target: Optional[Dict[str, Any]] = None


class PolicyResponse(BaseModel):
    id: str
    organization_id: UUID
    name: str
    description: Optional[str] = None
    category: str = "General"
    tags: List[str] = []
    target: Dict[str, Any] = {}
    active_version: Optional[int] = None
    total_versions: int = 0
    status: str = "DRAFT"
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PolicyVersionCreateRequest(BaseModel):
    yaml_source: str = Field(..., min_length=1)
    change_description: Optional[str] = Field(None, max_length=1000)


class PolicyVersionResponse(BaseModel):
    id: str
    policy_id: str
    version_number: int
    status: str
    content_hash: str
    yaml_source: str
    compiled_ast: Dict[str, Any]
    change_description: Optional[str] = None
    is_active: bool
    created_by: Optional[UUID] = None
    reviewed_by: Optional[UUID] = None
    published_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class PolicyValidateRequest(BaseModel):
    yaml_source: str
    source_format: str = "yaml"


class ValidationIssueSchema(BaseModel):
    message: str
    path: str
    severity: str = "ERROR"


class LintIssueSchema(BaseModel):
    code: str
    message: str
    rule_id: Optional[str] = None
    severity: str


class PolicyValidateResponse(BaseModel):
    is_valid: bool
    content_hash: Optional[str] = None
    errors: List[ValidationIssueSchema] = []
    warnings: List[ValidationIssueSchema] = []
    lint_issues: List[LintIssueSchema] = []


class PolicySimulateRequest(BaseModel):
    yaml_source: Optional[str] = None
    policy_id: Optional[str] = None
    version_number: Optional[int] = None
    context: Dict[str, Any] = Field(..., description="Authorization request context")


class PolicySimulateResponse(BaseModel):
    decision: str
    explanation: str
    matched_rules: List[Dict[str, Any]] = []
    unmatched_rules: List[str] = []
    default_effect_applied: bool = False
    trace: List[Dict[str, Any]] = []
    evaluation_time_ms: float


class PolicyImpactAnalysisRequest(BaseModel):
    candidate_yaml_source: str
    baseline_version: Optional[int] = None
    sample_requests: Optional[List[Dict[str, Any]]] = None


class SampleComparisonResult(BaseModel):
    request_index: int
    context_summary: str
    baseline_decision: str
    candidate_decision: str
    decision_changed: bool


class PolicyImpactAnalysisResponse(BaseModel):
    diff: Dict[str, Any]
    security_sensitive_changes: bool
    markdown_summary: str
    sample_comparisons: List[SampleComparisonResult] = []
    affected_sample_count: int = 0


class PolicyPublishRequest(BaseModel):
    version_number: int
    sync_gateways: bool = True


class PolicyRollbackRequest(BaseModel):
    target_version: int
    reason: str = Field(..., min_length=3, max_length=500)
    sync_gateways: bool = True


class PolicyTestCaseCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    context: Dict[str, Any]
    expected_decision: str = Field(..., pattern="^(ALLOW|REQUIRE_APPROVAL|DENY)$")


class PolicyTestCaseResponse(BaseModel):
    id: str
    policy_id: str
    name: str
    description: Optional[str] = None
    context: Dict[str, Any]
    expected_decision: str
    created_at: datetime

    model_config = {"from_attributes": True}


class PolicyTestRunResult(BaseModel):
    test_id: str
    test_name: str
    expected_decision: str
    actual_decision: str
    passed: bool
    explanation: str
    duration_ms: float


class PolicyTestRunSummary(BaseModel):
    policy_id: str
    version_evaluated: int
    total_tests: int
    passed_tests: int
    failed_tests: int
    all_passed: bool
    results: List[PolicyTestRunResult]
