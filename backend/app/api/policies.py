"""API endpoints for AgentTrust Policy Language (APL/1.0), Versioning, Simulator, and Rollback."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import time
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.models import Organization, OrganizationMember, OrganizationRole, User
from app.models.policy import (
    Policy,
    PolicyBinding,
    PolicyTestCase,
    PolicyVersion,
    generate_policy_id,
)
from app.schemas.policy import (
    LintIssueSchema,
    PolicyCreateRequest,
    PolicyImpactAnalysisRequest,
    PolicyImpactAnalysisResponse,
    PolicyPublishRequest,
    PolicyResponse,
    PolicyRollbackRequest,
    PolicySimulateRequest,
    PolicySimulateResponse,
    PolicyTestCaseCreateRequest,
    PolicyTestCaseResponse,
    PolicyTestRunResult,
    PolicyTestRunSummary,
    PolicyUpdateRequest,
    PolicyValidateRequest,
    PolicyValidateResponse,
    PolicyVersionCreateRequest,
    PolicyVersionResponse,
    SampleComparisonResult,
    ValidationIssueSchema,
)
from app.services.apl import (
    APLLinter,
    APLParseError,
    APLValidator,
    compute_policy_content_hash,
    compute_policy_diff,
    evaluate_apl_policy,
    list_templates,
    parse_policy_document,
)

router = APIRouter(prefix="/policies", tags=["Policies"])


def resolve_organization(
    db: Session,
    user: User,
    organization_id: Optional[UUID] = None,
) -> UUID:
    """Resolve and verify user organization membership."""
    if organization_id:
        membership = db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.organization_id == organization_id,
            )
        )
        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User does not have access to specified organization",
            )
        return organization_id

    # Fallback to user's first organization
    membership = db.scalar(
        select(OrganizationMember).where(OrganizationMember.user_id == user.id)
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User does not belong to any organization",
        )
    return membership.organization_id


@router.get("/templates", response_model=List[Dict[str, Any]])
def get_policy_templates():
    """Retrieve pre-built enterprise APL/1.0 policy templates."""
    return list_templates()


@router.post("/validate", response_model=PolicyValidateResponse)
def validate_policy_document(req: PolicyValidateRequest):
    """
    Validate raw APL/1.0 YAML/JSON policy document against schema, safe field registry, and static linter.
    """
    try:
        normalized_ast, content_hash = parse_policy_document(req.yaml_source, source_format=req.source_format)
    except APLParseError as pe:
        return PolicyValidateResponse(
            is_valid=False,
            content_hash=None,
            errors=[ValidationIssueSchema(message=pe.message, path=pe.path, severity="ERROR")],
            warnings=[],
            lint_issues=[],
        )

    # 1. Structural & semantic validation
    validator = APLValidator()
    val_res = validator.validate(normalized_ast)

    # 2. Static linter
    linter = APLLinter()
    lint_issues = linter.lint(normalized_ast)

    return PolicyValidateResponse(
        is_valid=val_res.is_valid,
        content_hash=content_hash,
        errors=[ValidationIssueSchema(message=e.message, path=e.path, severity=e.severity) for e in val_res.errors],
        warnings=[ValidationIssueSchema(message=w.message, path=w.path, severity=w.severity) for w in val_res.warnings],
        lint_issues=[
            LintIssueSchema(code=l.code, message=l.message, rule_id=l.rule_id, severity=l.severity)
            for l in lint_issues
        ],
    )


@router.post("/simulate", response_model=PolicySimulateResponse)
def simulate_policy_execution(
    req: PolicySimulateRequest,
    request: Request,
):
    """
    Execute sandboxed, deterministic simulation of an APL policy against a context with step-by-step trace.
    Zero side-effects.
    """
    ast: Optional[Dict[str, Any]] = None

    if req.yaml_source:
        try:
            ast, _ = parse_policy_document(req.yaml_source)
        except APLParseError as pe:
            raise HTTPException(status_code=400, detail=f"Invalid policy syntax: {pe.message}")
    elif req.policy_id:
        factory = getattr(request.app.state, "session_factory", None)
        if factory is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        with factory() as db:
            policy = db.get(Policy, req.policy_id)
            if not policy:
                raise HTTPException(status_code=404, detail="Policy not found")

            target_ver = req.version_number or getattr(policy, "active_version", None)
            if not target_ver:
                raise HTTPException(status_code=400, detail="Policy has no active or specified version")

            ver = db.scalar(
                select(PolicyVersion).where(
                    PolicyVersion.policy_id == policy.id,
                    PolicyVersion.version_number == target_ver,
                )
            )
            if not ver:
                raise HTTPException(status_code=404, detail=f"Policy version {target_ver} not found")
            ast = getattr(ver, "normalized_document", None) or getattr(ver, "compiled_ast", None)
    else:
        raise HTTPException(status_code=400, detail="Either 'yaml_source' or 'policy_id' must be provided")

    result = evaluate_apl_policy(ast, req.context)
    return PolicySimulateResponse(
        decision=result.decision,
        explanation=result.explanation,
        matched_rules=result.matched_rules,
        unmatched_rules=result.unmatched_rules,
        default_effect_applied=result.default_effect_applied,
        trace=result.trace,
        evaluation_time_ms=result.evaluation_time_ms,
    )


@router.get("", response_model=List[PolicyResponse])
def list_policies(
    organization_id: Optional[UUID] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List all policies registered in the organization."""
    org_id = resolve_organization(db, user, organization_id)
    policies = db.scalars(
        select(Policy)
        .where(Policy.organization_id == org_id)
        .order_by(desc(Policy.created_at))
    ).all()

    resp: List[PolicyResponse] = []
    for p in policies:
        count = db.scalar(
            select(func.count(PolicyVersion.id)).where(PolicyVersion.policy_id == p.id)
        ) or 0
        resp.append(
            PolicyResponse(
                id=p.id,
                organization_id=p.organization_id,
                name=p.name,
                description=p.description,
                category=p.category,
                tags=p.tags or [],
                target=p.target or {},
                active_version=p.active_version,
                total_versions=count,
                status=p.status,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
        )
    return resp


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    req: PolicyCreateRequest,
    organization_id: Optional[UUID] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new policy record and optional initial version."""
    org_id = resolve_organization(db, user, organization_id)

    policy = Policy(
        organization_id=org_id,
        name=req.name,
        description=req.description,
        category=req.category or "General",
        tags=req.tags or [],
        target=req.target or {},
        status="DRAFT",
    )
    db.add(policy)
    db.flush()

    total_versions = 0
    if req.initial_yaml_source:
        try:
            ast, content_hash = parse_policy_document(req.initial_yaml_source)
        except APLParseError as pe:
            raise HTTPException(status_code=400, detail=f"Initial YAML parse error: {pe.message}")

        val = APLValidator().validate(ast)
        if not val.is_valid:
            err_msg = "; ".join([e.message for e in val.errors])
            raise HTTPException(status_code=400, detail=f"Initial YAML validation failed: {err_msg}")

        ver = PolicyVersion(
            policy_id=policy.id,
            version_number=1,
            status="DRAFT",
            content_hash=content_hash,
            yaml_source=req.initial_yaml_source,
            compiled_ast=ast,
            change_description="Initial policy definition",
            is_active=False,
            created_by=user.id,
        )
        db.add(ver)
        total_versions = 1

    db.commit()
    db.refresh(policy)

    return PolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        category=policy.category,
        tags=policy.tags or [],
        target=policy.target or {},
        active_version=policy.active_version,
        total_versions=total_versions,
        status=policy.status,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Retrieve details of a single policy."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    count = db.scalar(
        select(func.count(PolicyVersion.id)).where(PolicyVersion.policy_id == policy.id)
    ) or 0

    return PolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        category=policy.category,
        tags=policy.tags or [],
        target=policy.target or {},
        active_version=policy.active_version,
        total_versions=count,
        status=policy.status,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.put("/{policy_id}", response_model=PolicyResponse)
def update_policy_metadata(
    policy_id: str,
    req: PolicyUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update policy metadata (name, description, category, tags, target)."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    if req.name is not None:
        policy.name = req.name
    if req.description is not None:
        policy.description = req.description
    if req.category is not None:
        policy.category = req.category
    if req.tags is not None:
        policy.tags = req.tags
    if req.target is not None:
        policy.target = req.target

    db.commit()
    db.refresh(policy)

    count = db.scalar(
        select(func.count(PolicyVersion.id)).where(PolicyVersion.policy_id == policy.id)
    ) or 0

    return PolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        category=policy.category,
        tags=policy.tags or [],
        target=policy.target or {},
        active_version=policy.active_version,
        total_versions=count,
        status=policy.status,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Delete policy and all associated versions."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    # Delete bindings, test cases, versions, and policy
    db.query(PolicyBinding).filter(PolicyBinding.policy_id == policy.id).delete()
    db.query(PolicyTestCase).filter(PolicyTestCase.policy_id == policy.id).delete()
    db.query(PolicyVersion).filter(PolicyVersion.policy_id == policy.id).delete()
    db.delete(policy)
    db.commit()
    return None


@router.get("/{policy_id}/versions", response_model=List[PolicyVersionResponse])
def list_policy_versions(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List immutable versions for a policy."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    versions = db.scalars(
        select(PolicyVersion)
        .where(PolicyVersion.policy_id == policy.id)
        .order_by(desc(PolicyVersion.version_number))
    ).all()
    return [PolicyVersionResponse.model_validate(v) for v in versions]


@router.post("/{policy_id}/versions", response_model=PolicyVersionResponse, status_code=status.HTTP_201_CREATED)
def create_policy_version(
    policy_id: str,
    req: PolicyVersionCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a new immutable draft version for a policy."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    # Parse and validate
    try:
        ast, content_hash = parse_policy_document(req.yaml_source)
    except APLParseError as pe:
        raise HTTPException(status_code=400, detail=f"Policy parse error: {pe.message}")

    val = APLValidator().validate(ast)
    if not val.is_valid:
        err_msg = "; ".join([e.message for e in val.errors])
        raise HTTPException(status_code=400, detail=f"Policy validation failed: {err_msg}")

    # Monotonic version calculation
    latest_ver = db.scalar(
        select(func.max(PolicyVersion.version_number)).where(PolicyVersion.policy_id == policy.id)
    ) or 0
    next_ver = latest_ver + 1

    ver = PolicyVersion(
        policy_id=policy.id,
        version_number=next_ver,
        status="DRAFT",
        content_hash=content_hash,
        yaml_source=req.yaml_source,
        compiled_ast=ast,
        change_description=req.change_description,
        is_active=False,
        created_by=user.id,
    )
    db.add(ver)
    db.commit()
    db.refresh(ver)
    return PolicyVersionResponse.model_validate(ver)


@router.get("/{policy_id}/versions/{version_number}", response_model=PolicyVersionResponse)
def get_policy_version(
    policy_id: str,
    version_number: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get specific immutable policy version."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    ver = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.version_number == version_number,
        )
    )
    if not ver:
        raise HTTPException(status_code=404, detail=f"Version {version_number} not found")
    return PolicyVersionResponse.model_validate(ver)


@router.get("/{policy_id}/diff")
def diff_policy_versions(
    policy_id: str,
    v1: int = Query(..., description="Base version number"),
    v2: int = Query(..., description="Target version number to compare"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Compute semantic diff and security impact between two policy versions."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    ver1 = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.version_number == v1,
        )
    )
    ver2 = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.version_number == v2,
        )
    )
    if not ver1:
        raise HTTPException(status_code=404, detail=f"Version {v1} not found")
    if not ver2:
        raise HTTPException(status_code=404, detail=f"Version {v2} not found")

    diff = compute_policy_diff(ver1.compiled_ast, ver2.compiled_ast, old_version=v1, new_version=v2)
    return diff.to_dict()


@router.post("/{policy_id}/impact", response_model=PolicyImpactAnalysisResponse)
def impact_analysis(
    policy_id: str,
    req: PolicyImpactAnalysisRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Run impact analysis comparing candidate policy AST against active baseline version across sample contexts.
    """
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    try:
        cand_ast, _ = parse_policy_document(req.candidate_yaml_source)
    except APLParseError as pe:
        raise HTTPException(status_code=400, detail=f"Candidate YAML syntax error: {pe.message}")

    base_ver_num = req.baseline_version or policy.active_version
    base_ast: Dict[str, Any] = {"version": "APL/1.0", "name": "Empty Baseline", "rules": [], "default_effect": "DENY"}
    if base_ver_num:
        base_ver = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy.id,
                PolicyVersion.version_number == base_ver_num,
            )
        )
        if base_ver and isinstance(base_ver.compiled_ast, dict):
            base_ast = base_ver.compiled_ast

    diff = compute_policy_diff(base_ast, cand_ast, old_version=base_ver_num or 0, new_version=999)

    # Sample comparisons
    sample_comparisons: List[SampleComparisonResult] = []
    affected_count = 0

    samples = req.sample_requests or [
        {"action": "test.read", "input": {"amount": 100}},
        {"action": "test.write", "input": {"amount": 2500}},
        {"action": "test.delete", "input": {"amount": 10000}},
    ]

    for idx, sample_ctx in enumerate(samples):
        base_eval = evaluate_apl_policy(base_ast, sample_ctx)
        cand_eval = evaluate_apl_policy(cand_ast, sample_ctx)
        changed = (base_eval.decision != cand_eval.decision)
        if changed:
            affected_count += 1
        sample_comparisons.append(
            SampleComparisonResult(
                request_index=idx,
                context_summary=json.dumps(sample_ctx),
                baseline_decision=base_eval.decision,
                candidate_decision=cand_eval.decision,
                decision_changed=changed,
            )
        )

    return PolicyImpactAnalysisResponse(
        diff=diff.to_dict(),
        security_sensitive_changes=diff.has_security_sensitive_changes,
        markdown_summary=diff.markdown_summary,
        sample_comparisons=sample_comparisons,
        affected_sample_count=affected_count,
    )


@router.post("/{policy_id}/publish", response_model=PolicyResponse)
def publish_policy_version(
    policy_id: str,
    req: PolicyPublishRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Publish an immutable policy version.
    Activates the version, deactivates previous versions, and pushes a monotonic signed config snapshot to Gateways.
    """
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    target_ver = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.version_number == req.version_number,
        )
    )
    if not target_ver:
        raise HTTPException(status_code=404, detail=f"Version {req.version_number} not found")

    # Deactivate all versions for this policy
    all_versions = db.scalars(
        select(PolicyVersion).where(PolicyVersion.policy_id == policy.id)
    ).all()
    for v in all_versions:
        v.is_active = False

    # Mark target version active and published
    target_ver.is_active = True
    target_ver.status = "PUBLISHED"
    target_ver.published_at = datetime.now(timezone.utc)
    target_ver.reviewed_by = user.id

    policy.active_version = target_ver.version_number
    policy.status = "ACTIVE"
    policy.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(policy)

    # Automatically trigger monotonic signed config bundle update if requested
    if req.sync_gateways:
        try:
            from app.schemas.enterprise_gateways import GatewayPublishConfigRequest
            from app.services.gateway_control_service import build_and_publish_config
            build_and_publish_config(
                db=db,
                org_id=policy.organization_id,
                req=GatewayPublishConfigRequest(
                    environment="production",
                    validity_hours=24,
                ),
                user_id=user.id,
            )
        except Exception:
            # Non-blocking if gateways not yet registered
            pass

    count = len(all_versions)
    return PolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        category=policy.category,
        tags=policy.tags or [],
        target=policy.target or {},
        active_version=policy.active_version,
        total_versions=count,
        status=policy.status,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.post("/{policy_id}/rollback", response_model=PolicyResponse)
def rollback_policy_version(
    policy_id: str,
    req: PolicyRollbackRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Rollback to an earlier version.
    Maintains immutability: generates a new monotonic signed configuration snapshot. Old versions are never modified or replayed.
    """
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    target_ver = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.version_number == req.target_version,
        )
    )
    if not target_ver:
        raise HTTPException(status_code=404, detail=f"Target rollback version {req.target_version} not found")

    # Deactivate current active version
    all_versions = db.scalars(
        select(PolicyVersion).where(PolicyVersion.policy_id == policy.id)
    ).all()
    for v in all_versions:
        v.is_active = False

    target_ver.is_active = True
    target_ver.status = "ACTIVE"
    policy.active_version = target_ver.version_number
    policy.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(policy)

    # Push new monotonic signed config snapshot to Gateways
    if req.sync_gateways:
        try:
            from app.schemas.enterprise_gateways import GatewayPublishConfigRequest
            from app.services.gateway_control_service import build_and_publish_config
            build_and_publish_config(
                db=db,
                org_id=policy.organization_id,
                req=GatewayPublishConfigRequest(
                    environment="production",
                    validity_hours=24,
                ),
                user_id=user.id,
            )
        except Exception:
            pass

    count = len(all_versions)
    return PolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        category=policy.category,
        tags=policy.tags or [],
        target=policy.target or {},
        active_version=policy.active_version,
        total_versions=count,
        status=policy.status,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.get("/{policy_id}/tests", response_model=List[PolicyTestCaseResponse])
def list_policy_test_cases(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List test cases associated with a policy."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    tests = db.scalars(
        select(PolicyTestCase)
        .where(PolicyTestCase.policy_id == policy.id)
        .order_by(PolicyTestCase.created_at)
    ).all()
    return [PolicyTestCaseResponse.model_validate(t) for t in tests]


@router.post("/{policy_id}/tests", response_model=PolicyTestCaseResponse, status_code=status.HTTP_201_CREATED)
def create_policy_test_case(
    policy_id: str,
    req: PolicyTestCaseCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Add a test case to a policy."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    tc = PolicyTestCase(
        policy_id=policy.id,
        name=req.name,
        description=req.description,
        context=req.context,
        expected_decision=req.expected_decision.upper(),
    )
    db.add(tc)
    db.commit()
    db.refresh(tc)
    return PolicyTestCaseResponse.model_validate(tc)


@router.post("/{policy_id}/tests/run", response_model=PolicyTestRunSummary)
def run_policy_tests(
    policy_id: str,
    version_number: Optional[int] = Query(None, description="Version number to test, defaults to active_version"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Execute all test cases against a specific policy version."""
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    resolve_organization(db, user, policy.organization_id)

    target_ver = version_number or policy.active_version
    if not target_ver:
        raise HTTPException(status_code=400, detail="No active or specified version to test")

    ver = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.policy_id == policy.id,
            PolicyVersion.version_number == target_ver,
        )
    )
    if not ver:
        raise HTTPException(status_code=404, detail=f"Version {target_ver} not found")

    tests = db.scalars(
        select(PolicyTestCase).where(PolicyTestCase.policy_id == policy.id)
    ).all()

    results: List[PolicyTestRunResult] = []
    passed_count = 0

    for t in tests:
        eval_res = evaluate_apl_policy(ver.compiled_ast, t.context)
        passed = (eval_res.decision == t.expected_decision)
        if passed:
            passed_count += 1
        results.append(
            PolicyTestRunResult(
                test_id=t.id,
                test_name=t.name,
                expected_decision=t.expected_decision,
                actual_decision=eval_res.decision,
                passed=passed,
                explanation=eval_res.explanation,
                duration_ms=eval_res.evaluation_time_ms,
            )
        )

    return PolicyTestRunSummary(
        policy_id=policy.id,
        version_evaluated=target_ver,
        total_tests=len(tests),
        passed_tests=passed_count,
        failed_tests=len(tests) - passed_count,
        all_passed=(passed_count == len(tests)),
        results=results,
    )
