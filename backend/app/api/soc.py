"""API endpoints for Enterprise Security Operations Center (SOC)."""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, or_
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, get_db
from app.models import (
    DetectionRule,
    Organization,
    OrganizationMember,
    SecurityAlert,
    SecurityEvent,
    SecurityExportDestination,
    User,
)
from app.schemas.soc import (
    AcknowledgeAlertRequest,
    CreateDetectionRuleRequest,
    CreateExportDestinationRequest,
    DetectionRuleItem,
    PaginatedSecurityAlerts,
    PaginatedUnifiedSecurityEvents,
    RelatedEventsResponse,
    ResolveAlertRequest,
    SecurityAlertItem,
    SecurityExportDestinationItem,
    SecurityOverviewResponse,
    TestExportResponse,
    UnifiedSecurityEventItem,
    UpdateDetectionRuleRequest,
)
from app.services.siem_exporter import deliver_export_payload, format_event_as_json
from app.services.soc_service import (
    acknowledge_alert,
    ensure_builtin_rules,
    get_agent_security_profile,
    get_gateway_security_profile,
    get_soc_overview,
    resolve_alert,
)

router = APIRouter(tags=["Enterprise SOC"])


def resolve_organization(
    db: Session,
    user: User,
    organization_id: UUID | None = None,
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
                detail="Access denied to requested organization",
            )
        return organization_id

    membership = db.scalar(
        select(OrganizationMember).where(OrganizationMember.user_id == user.id)
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User has no associated organization",
        )
    return membership.organization_id


def _match_identifier(model_id_col: Any, model_str_id_col: Any, lookup_val: str):
    """Safely match either the string identifier (evt_..., alt_...) or UUID primary key."""
    conds = [model_str_id_col == lookup_val]
    try:
        u = UUID(lookup_val)
        conds.append(model_id_col == u)
    except (ValueError, TypeError):
        pass
    return or_(*conds)


@router.get("/overview", response_model=SecurityOverviewResponse)
def get_overview(
    organization_id: UUID | None = None,
    window_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    ensure_builtin_rules(db)
    data = get_soc_overview(db, org_id, window_hours)
    return SecurityOverviewResponse(**data)


@router.get("/events", response_model=PaginatedUnifiedSecurityEvents)
def list_events(
    organization_id: UUID | None = None,
    severity: str | None = None,
    category: str | None = None,
    event_type: str | None = None,
    agent_id: UUID | None = None,
    gateway_id: UUID | None = None,
    decision: str | None = None,
    risk_level: str | None = None,
    correlation_id: str | None = None,
    request_id: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)

    conditions = [SecurityEvent.organization_id == org_id]
    if severity:
        conditions.append(SecurityEvent.severity == severity.upper())
    if category:
        conditions.append(SecurityEvent.category == category.upper())
    if event_type:
        conditions.append(SecurityEvent.event_type == event_type)
    if agent_id:
        conditions.append(SecurityEvent.agent_id == agent_id)
    if gateway_id:
        conditions.append(SecurityEvent.gateway_id == gateway_id)
    if decision:
        conditions.append(SecurityEvent.decision == decision.upper())
    if risk_level:
        conditions.append(SecurityEvent.risk_level == risk_level.upper())
    if correlation_id:
        conditions.append(SecurityEvent.correlation_id == correlation_id)
    if request_id:
        conditions.append(SecurityEvent.request_id == request_id)
    if from_time:
        conditions.append(SecurityEvent.created_at >= from_time)
    if to_time:
        conditions.append(SecurityEvent.created_at <= to_time)
    if cursor:
        conditions.append(SecurityEvent.event_id < cursor)

    total = db.scalar(select(func.count(SecurityEvent.id)).where(*conditions)) or 0
    query = (
        select(SecurityEvent)
        .where(*conditions)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(limit)
    )
    events = list(db.scalars(query))
    next_cur = events[-1].event_id if len(events) == limit else None

    return PaginatedUnifiedSecurityEvents(
        items=[UnifiedSecurityEventItem.model_validate(e) for e in events],
        total=total,
        next_cursor=next_cur,
    )


@router.get("/events/{event_id}", response_model=UnifiedSecurityEventItem)
def get_event_detail(
    event_id: str,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    event = db.scalar(
        select(SecurityEvent).where(
            _match_identifier(SecurityEvent.id, SecurityEvent.event_id, event_id),
            SecurityEvent.organization_id == org_id,
        )
    )
    if not event:
        raise HTTPException(status_code=404, detail="Security event not found")
    return UnifiedSecurityEventItem.model_validate(event)


@router.get("/events/{event_id}/related", response_model=RelatedEventsResponse)
def get_related_events(
    event_id: str,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    event = db.scalar(
        select(SecurityEvent).where(
            _match_identifier(SecurityEvent.id, SecurityEvent.event_id, event_id),
            SecurityEvent.organization_id == org_id,
        )
    )
    if not event:
        raise HTTPException(status_code=404, detail="Security event not found")

    or_clauses = []
    if event.correlation_id:
        or_clauses.append(SecurityEvent.correlation_id == event.correlation_id)
    if event.request_id:
        or_clauses.append(SecurityEvent.request_id == event.request_id)
    if event.agent_id:
        or_clauses.append(SecurityEvent.agent_id == event.agent_id)

    if not or_clauses:
        return RelatedEventsResponse(primary_event_id=event.event_id or str(event.id), related_events=[], total_found=0)

    window_start = event.created_at - timedelta(hours=1)
    window_end = event.created_at + timedelta(hours=1)

    stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.organization_id == org_id,
            SecurityEvent.id != event.id,
            SecurityEvent.created_at >= window_start,
            SecurityEvent.created_at <= window_end,
            or_(*or_clauses),
        )
        .order_by(SecurityEvent.created_at.asc())
        .limit(50)
    )
    related = list(db.scalars(stmt))
    return RelatedEventsResponse(
        primary_event_id=event.event_id or str(event.id),
        related_events=[UnifiedSecurityEventItem.model_validate(e) for e in related],
        total_found=len(related),
    )


@router.get("/alerts", response_model=PaginatedSecurityAlerts)
def list_alerts(
    organization_id: UUID | None = None,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    conditions = [SecurityAlert.organization_id == org_id]
    if status_filter:
        conditions.append(SecurityAlert.status == status_filter.upper())
    if severity:
        conditions.append(SecurityAlert.severity == severity.upper())

    total = db.scalar(select(func.count(SecurityAlert.id)).where(*conditions)) or 0
    query = (
        select(SecurityAlert)
        .where(*conditions)
        .order_by(SecurityAlert.last_seen_at.desc())
        .limit(limit)
    )
    alerts = list(db.scalars(query))
    return PaginatedSecurityAlerts(
        items=[SecurityAlertItem.model_validate(a) for a in alerts],
        total=total,
    )


@router.get("/alerts/{alert_id}", response_model=SecurityAlertItem)
def get_alert_detail(
    alert_id: str,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    alert = db.scalar(
        select(SecurityAlert).where(
            _match_identifier(SecurityAlert.id, SecurityAlert.alert_id, alert_id),
            SecurityAlert.organization_id == org_id,
        )
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return SecurityAlertItem.model_validate(alert)


@router.post("/alerts/{alert_id}/acknowledge", response_model=SecurityAlertItem)
def acknowledge_alert_endpoint(
    alert_id: str,
    req: AcknowledgeAlertRequest | None = None,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    alert = db.scalar(
        select(SecurityAlert).where(
            _match_identifier(SecurityAlert.id, SecurityAlert.alert_id, alert_id),
            SecurityAlert.organization_id == org_id,
        )
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    updated = acknowledge_alert(db, alert, user.id)
    return SecurityAlertItem.model_validate(updated)


@router.post("/alerts/{alert_id}/resolve", response_model=SecurityAlertItem)
def resolve_alert_endpoint(
    alert_id: str,
    req: ResolveAlertRequest | None = None,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    alert = db.scalar(
        select(SecurityAlert).where(
            _match_identifier(SecurityAlert.id, SecurityAlert.alert_id, alert_id),
            SecurityAlert.organization_id == org_id,
        )
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    note = req.resolution_note if req else None
    updated = resolve_alert(db, alert, user.id, note)
    return SecurityAlertItem.model_validate(updated)


@router.get("/rules", response_model=list[DetectionRuleItem])
def list_rules(
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    ensure_builtin_rules(db)
    rules = list(db.scalars(
        select(DetectionRule)
        .where(
            (DetectionRule.organization_id == org_id) | (DetectionRule.organization_id.is_(None))
        )
        .order_by(DetectionRule.created_at.desc())
    ))
    return [DetectionRuleItem.model_validate(r) for r in rules]


@router.post("/rules", response_model=DetectionRuleItem, status_code=201)
def create_rule(
    req: CreateDetectionRuleRequest,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)

    # Validate declarative conditions — strict rejection of arbitrary code execution
    cond_str = str(req.conditions).lower()
    unsafe_tokens = ["exec(", "eval(", "import ", "__", "subprocess", "os.", "sys.", "lambda", "function"]
    if any(token in cond_str for token in unsafe_tokens):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="UNSAFE_DETECTION_RULE: Code execution is strictly prohibited in detection rules.",
        )

    existing = db.scalar(select(DetectionRule).where(DetectionRule.rule_id == req.rule_id))
    if existing:
        raise HTTPException(status_code=400, detail="Rule ID already exists")

    rule = DetectionRule(
        id=uuid4(),
        rule_id=req.rule_id,
        organization_id=org_id,
        name=req.name,
        description=req.description,
        event_type=req.event_type,
        category=req.category,
        conditions=req.conditions,
        threshold=req.threshold,
        window_seconds=req.window_seconds,
        severity=req.severity.upper(),
        enabled=req.enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return DetectionRuleItem.model_validate(rule)


@router.patch("/rules/{rule_id}", response_model=DetectionRuleItem)
def update_rule(
    rule_id: str,
    req: UpdateDetectionRuleRequest,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    rule = db.scalar(
        select(DetectionRule).where(
            _match_identifier(DetectionRule.id, DetectionRule.rule_id, rule_id),
            (DetectionRule.organization_id == org_id) | (DetectionRule.organization_id.is_(None)),
        )
    )
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if req.name is not None:
        rule.name = req.name
    if req.description is not None:
        rule.description = req.description
    if req.threshold is not None:
        rule.threshold = req.threshold
    if req.window_seconds is not None:
        rule.window_seconds = req.window_seconds
    if req.severity is not None:
        rule.severity = req.severity.upper()
    if req.enabled is not None:
        rule.enabled = req.enabled

    db.commit()
    db.refresh(rule)
    return DetectionRuleItem.model_validate(rule)


@router.get("/exports", response_model=list[SecurityExportDestinationItem])
def list_exports(
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    exports = list(db.scalars(
        select(SecurityExportDestination)
        .where(SecurityExportDestination.organization_id == org_id)
        .order_by(SecurityExportDestination.created_at.desc())
    ))
    return [SecurityExportDestinationItem.model_validate(x) for x in exports]


@router.post("/exports", response_model=SecurityExportDestinationItem, status_code=201)
def create_export(
    req: CreateExportDestinationRequest,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    if req.endpoint_url:
        from app.services.ssrf_protection import SSRFValidationError, resolve_and_validate_endpoint_url
        try:
            resolve_and_validate_endpoint_url(req.endpoint_url, allow_private_ips=False, enforce_https=False)
        except SSRFValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"SSRF_PROTECTION_BLOCKED: {str(e)}",
            )

    dest = SecurityExportDestination(
        id=uuid4(),
        destination_id=f"exp_{uuid4().hex[:16]}",
        organization_id=org_id,
        name=req.name,
        destination_type=req.destination_type.upper(),
        endpoint_url=req.endpoint_url,
        secret_ref=req.secret_ref,
        min_severity=req.min_severity.upper(),
        categories=req.categories,
        enabled=req.enabled,
    )
    db.add(dest)
    db.commit()
    db.refresh(dest)
    return SecurityExportDestinationItem.model_validate(dest)


@router.post("/exports/{destination_id}/test", response_model=TestExportResponse)
def test_export(
    destination_id: str,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    dest = db.scalar(
        select(SecurityExportDestination).where(
            _match_identifier(SecurityExportDestination.id, SecurityExportDestination.destination_id, destination_id),
            SecurityExportDestination.organization_id == org_id,
        )
    )
    if not dest:
        raise HTTPException(status_code=404, detail="Export destination not found")

    sample_event = SecurityEvent(
        id=uuid4(),
        event_id=f"evt_test_{uuid4().hex[:12]}",
        organization_id=org_id,
        event_type="test_export_ping",
        category="SYSTEM",
        severity="INFO",
        description="AgentTrust SOC test export verification probe",
        action="test_export",
        decision="ALLOWED",
        environment="test",
        details={"probe": "ok", "test": True},
    )
    payload = format_event_as_json(sample_event)
    success, err = deliver_export_payload(dest, payload)
    return TestExportResponse(
        success=success,
        error=err,
        exported_sample_event_id=sample_event.event_id,
    )


@router.get("/agents/{agent_id}/profile")
def get_agent_profile(
    agent_id: UUID,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    profile = get_agent_security_profile(db, org_id, agent_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Agent not found")
    return profile


@router.get("/gateways/{gateway_id}/profile")
def get_gateway_profile(
    gateway_id: UUID,
    organization_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    org_id = resolve_organization(db, user, organization_id)
    profile = get_gateway_security_profile(db, org_id, gateway_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Gateway not found")
    return profile
