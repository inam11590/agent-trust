"""JWT-managed credentials and API-key-authenticated versioned developer API."""

from datetime import datetime, timezone
import json
from typing import Annotated, Literal
from uuid import UUID
from pydantic import ValidationError

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.schemas.authorization import AuthorizationRequest
from app.schemas.developer import (
    APIKeyCreate, APIKeyCreated, APIKeyResponse,
    DeveloperAuthorizationResponse, DeveloperLogDetailResponse, DeveloperLogResponse,
    DeveloperOverviewResponse, OnboardingProgressResponse,
    PermissionTemplateCreate, ProductionChecklistResponse,
    SandboxScenarioResult, TestAgentCreate, TestAgentResponse,
    WebhookCreate, WebhookCreated, WebhookDeliveryDetail,
    WebhookResponse, WebhookTestRequest
)
from app.models import (
    APIKey, Agent, AgentStatus, AuditLog, Organization,
    OrganizationMember, OrganizationRole, WebhookDelivery, WebhookEndpoint, WebhookStatus,
)
from app.services.api_keys import (
    APIKeyNotFound,
    DeveloperPrincipal,
    OrganizationNotFound,
    authenticate_api_key,
    create_api_key,
    list_api_keys,
    public_key,
    revoke_api_key,
)
from app.services.developer import (
    DeveloperRequestNotFound,
    IdempotencyConflict,
    RequestInProgress,
    developer_authorize,
    developer_logs,
    get_developer_log_detail,
    get_developer_request,
)
from app.services.sandbox import (
    create_permission_template,
    create_test_agent,
    get_developer_onboarding_progress,
    get_production_readiness_checklist,
    run_sandbox_scenario,
)
from app.services.webhooks import (
    WebhookConfigurationError,
    configure_webhook,
    retry_sandbox_webhook,
    send_test_webhook,
)
from app.services.organization_context import CurrentWorkspace, resolve_workspace
from app.services.security_events import record_security_event
from app.services.agent_signing import KEY_ID_PATTERN, SigningError, verify_request

management_router = APIRouter(prefix="/developer", tags=["developer management"])
api_router = APIRouter(prefix="/api/v1", tags=["developer api"])


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def developer_principal(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    api_key: Annotated[str | None, Header(alias="X-API-Key", max_length=200)] = None,
) -> DeveloperPrincipal:
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    principal = authenticate_api_key(db, api_key)
    if principal is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    limit = request.app.state.settings.developer_rate_limit_per_minute
    if not request.app.state.developer_rate_limiter.allow(principal.api_key.id, limit):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")
    return principal


DeveloperAuth = Annotated[DeveloperPrincipal, Depends(developer_principal)]


@management_router.get("/overview", response_model=DeveloperOverviewResponse)
def get_developer_overview(
    user: CurrentUser,
    response: Response,
    workspace: CurrentWorkspace,
    db: Annotated[Session, Depends(get_db)],
) -> DeveloperOverviewResponse:
    workspace.require("use_developer_tools")
    org_id = workspace.organization_id
    org = db.get(Organization, org_id) if org_id else None

    # Key counts by environment
    keys_sb = db.scalar(select(func.count()).select_from(APIKey).where(
        APIKey.organization_id == org_id,
        APIKey.environment == "sandbox",
        APIKey.status == "active",
    )) or 0
    keys_prod = db.scalar(select(func.count()).select_from(APIKey).where(
        APIKey.organization_id == org_id,
        APIKey.environment == "production",
        APIKey.status == "active",
    )) or 0

    # Agent counts by environment
    agents_sb = db.scalar(select(func.count()).select_from(Agent).where(
        Agent.organization_id == org_id,
        Agent.environment == "sandbox",
        Agent.status == AgentStatus.ACTIVE,
    )) or 0
    agents_prod = db.scalar(select(func.count()).select_from(Agent).where(
        Agent.organization_id == org_id,
        Agent.environment == "production",
        Agent.status == AgentStatus.ACTIVE,
    )) or 0

    # Monthly requests
    from app.services.plan_limits import month_period
    start_date, _ = month_period()
    start_dt = datetime.combine(start_date, datetime.min.time(), timezone.utc)
    monthly_reqs = db.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.organization_id == org_id,
        AuditLog.requested_at >= start_dt,
    )) or 0

    webhook_ep = db.scalar(select(WebhookEndpoint).where(
        WebhookEndpoint.organization_id == org_id,
    ))
    webhook_status = webhook_ep.status.value if webhook_ep else "not_configured"

    onboarding_data = get_developer_onboarding_progress(db, user, org_id)
    checklist_data = get_production_readiness_checklist(db, user, org_id)
    recent_logs = [DeveloperLogResponse(**item) for item in developer_logs(
        db, user.id, org_id,
        include_all_organization_keys=workspace.role in {OrganizationRole.OWNER, OrganizationRole.ADMIN},
        limit=10,
    )]

    _no_store(response)
    return DeveloperOverviewResponse(
        organization_id=org_id,
        organization_name=org.name if org else None,
        environment="SANDBOX",
        api_status="operational",
        sandbox_api_keys_count=keys_sb,
        production_api_keys_count=keys_prod,
        sandbox_agents_count=agents_sb,
        production_agents_count=agents_prod,
        authorization_requests_this_month=monthly_reqs,
        webhook_status=webhook_status,
        production_access_status=org.production_access_status if org else "NOT_REQUESTED",
        onboarding=OnboardingProgressResponse(**onboarding_data),
        checklist=ProductionChecklistResponse(**checklist_data),
        recent_activity=recent_logs,
    )


@management_router.post("/api-keys", response_model=APIKeyCreated, status_code=201)
def add_api_key(payload: APIKeyCreate, user: CurrentUser, response: Response,
                request: Request,
                workspace: CurrentWorkspace,
                db: Annotated[Session, Depends(get_db)]) -> APIKeyCreated:
    from app.api.account_security import require_recent_step_up
    require_recent_step_up(request)
    target = workspace
    if payload.organization_id is not None and payload.organization_id != workspace.organization_id:
        target = resolve_workspace(db, user.id, payload.organization_id)
        if target is None:
            raise HTTPException(status_code=404, detail={"error": "ORGANIZATION_NOT_FOUND", "message": "Organization not found."})
    target.require("manage_keys")
    try:
        record, full_key = create_api_key(db, user, payload, target.organization_id)
    except OrganizationNotFound:
        raise HTTPException(status_code=404, detail={"error": "ORGANIZATION_NOT_FOUND", "message": "Organization not found."}) from None
    record_security_event(
        db, user.id, "api_key.created", organization_id=record.organization_id,
        description=f"API key created ({record.environment}): {record.id}",
    )
    _no_store(response)
    response.headers["Location"] = f"/developer/api-keys/{record.id}"
    return APIKeyCreated(**public_key(record, full_key))


@management_router.get("/api-keys", response_model=list[APIKeyResponse])
def get_api_keys(user: CurrentUser, response: Response,
                 workspace: CurrentWorkspace,
                 db: Annotated[Session, Depends(get_db)],
                 environment: str | None = None) -> list[APIKeyResponse]:
    workspace.require("manage_keys")
    _no_store(response)
    keys = list_api_keys(db, user.id, workspace.organization_id, workspace.role)
    if environment:
        keys = [k for k in keys if getattr(k, "environment", "production") == environment]
    return [APIKeyResponse(**public_key(key)) for key in keys]


@management_router.post("/api-keys/{key_id}/revoke", response_model=APIKeyResponse)
def revoke_key(key_id: UUID, user: CurrentUser, response: Response,
               workspace: CurrentWorkspace,
               db: Annotated[Session, Depends(get_db)]) -> APIKeyResponse:
    workspace.require("manage_keys")
    try:
        record = revoke_api_key(db, user.id, key_id, workspace.organization_id, workspace.role)
    except APIKeyNotFound:
        raise HTTPException(status_code=404, detail={"error": "API_KEY_NOT_FOUND", "message": "API key not found."}) from None
    record_security_event(
        db, user.id, "api_key.revoked", organization_id=record.organization_id,
        description=f"API key revoked: {record.id}",
    )
    _no_store(response)
    return APIKeyResponse(**public_key(record))


@management_router.post("/agents/test", response_model=TestAgentResponse, status_code=201)
def create_sandbox_test_agent(
    payload: TestAgentCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> TestAgentResponse:
    workspace.require("use_developer_tools")
    org_id = payload.organization_id or workspace.organization_id
    agent = create_test_agent(db, user, org_id, payload.name)
    record_security_event(
        db, user.id, "agent.test_created", organization_id=agent.organization_id,
        description=f"Test agent created: {agent.name} ({agent.agent_identifier})",
    )
    _no_store(response)
    return TestAgentResponse(
        id=agent.id,
        agent_identifier=agent.agent_identifier,
        name=agent.name,
        environment="sandbox",
        status="active",
        instructions="Generate signing keys using 'agenttrust keys generate' locally, then register public key.",
    )


@management_router.post("/permissions/templates", status_code=201)
def add_permission_template(
    payload: PermissionTemplateCreate,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    workspace.require("use_developer_tools")
    try:
        permission = create_permission_template(db, user, payload.agent_id, payload.template)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "INVALID_TEMPLATE", "message": str(exc)}) from None
    _no_store(response)
    return {
        "id": str(permission.id),
        "agent_id": str(permission.agent_id),
        "action": permission.action,
        "resource": permission.resource,
        "maximum_amount": str(permission.maximum_amount) if permission.maximum_amount is not None else None,
        "currency": permission.currency,
        "status": permission.status.value,
        "template": payload.template,
    }


@management_router.get("/sandbox/scenarios")
def list_scenarios() -> list[dict]:
    return [
        {
            "id": "scenario_1",
            "name": "Scenario 1: $300 Flight (Expected: APPROVED)",
            "description": "Standard request within $500 limit is automatically approved.",
            "expected_status": "APPROVED",
        },
        {
            "id": "scenario_2",
            "name": "Scenario 2: $450 Hotel + Manual Approval (Expected: PENDING)",
            "description": "Permission requires owner review; returns PENDING status.",
            "expected_status": "PENDING",
        },
        {
            "id": "scenario_3",
            "name": "Scenario 3: $700 with $500 limit (Expected: REJECTED)",
            "description": "Amount exceeds allowed limit and is safely rejected.",
            "expected_status": "REJECTED",
        },
        {
            "id": "scenario_4",
            "name": "Scenario 4: Modified Signature (Expected: INVALID_AGENT_SIGNATURE)",
            "description": "Tampered signature bytes are detected and rejected cryptographically.",
            "expected_status": "INVALID_AGENT_SIGNATURE",
        },
        {
            "id": "scenario_5",
            "name": "Scenario 5: Replayed Request (Expected: REPLAY_DETECTED)",
            "description": "Duplicate nonce within the validity window is rejected.",
            "expected_status": "REPLAY_DETECTED",
        },
    ]


@management_router.post("/sandbox/scenarios/{scenario_id}/run", response_model=SandboxScenarioResult)
def run_scenario(
    scenario_id: str,
    request: Request,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> SandboxScenarioResult:
    workspace.require("use_developer_tools")
    try:
        result = run_sandbox_scenario(db, request.app.state.settings, user, workspace.organization_id, scenario_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "SCENARIO_ERROR", "message": str(exc)}) from None
    _no_store(response)
    return result


@management_router.post("/webhooks/test")
def trigger_webhook_test(
    payload: WebhookTestRequest,
    request: Request,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    workspace.require("use_developer_tools")
    endpoint = db.scalar(select(WebhookEndpoint).where(
        WebhookEndpoint.organization_id == workspace.organization_id,
        WebhookEndpoint.status == WebhookStatus.ACTIVE,
    ))
    if endpoint is None:
        raise HTTPException(status_code=404, detail={"error": "WEBHOOK_NOT_CONFIGURED", "message": "No active webhook endpoint configured for this organization."})
    delivery = send_test_webhook(db, request.app.state.settings, endpoint.id, payload.event_type)
    _no_store(response)
    return {
        "delivery_id": str(delivery.id),
        "event_type": delivery.event_type,
        "status": delivery.status,
        "test_mode": delivery.is_test,
        "attempt_count": delivery.attempt_count,
        "request_id": delivery.request_id,
        "response_status": delivery.response_status,
    }


@management_router.get("/webhooks/deliveries", response_model=list[WebhookDeliveryDetail])
def get_webhook_deliveries(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=20, le=100),
) -> list[WebhookDeliveryDetail]:
    workspace.require("use_developer_tools")
    deliveries = list(db.scalars(
        select(WebhookDelivery)
        .join(WebhookEndpoint, WebhookEndpoint.id == WebhookDelivery.webhook_endpoint_id)
        .where(WebhookEndpoint.organization_id == workspace.organization_id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(limit)
    ))
    _no_store(response)
    return [
        WebhookDeliveryDetail(
            id=d.id,
            webhook_endpoint_id=d.webhook_endpoint_id,
            request_id=d.request_id,
            event_type=d.event_type,
            is_test=d.is_test,
            status=d.status,
            attempt_count=d.attempt_count,
            response_status=d.response_status,
            response_body=d.response_body,
            last_error=d.last_error,
            delivered_at=d.delivered_at,
            created_at=d.created_at,
        )
        for d in deliveries
    ]


@management_router.post("/webhooks/deliveries/{delivery_id}/retry", response_model=WebhookDeliveryDetail)
def retry_delivery(
    delivery_id: UUID,
    request: Request,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> WebhookDeliveryDetail:
    workspace.require("use_developer_tools")
    if workspace.organization_id is None:
        raise HTTPException(status_code=400, detail={"error": "ORGANIZATION_REQUIRED", "message": "Organization required to retry webhooks."})
    try:
        delivery = retry_sandbox_webhook(db, request.app.state.settings, delivery_id, workspace.organization_id)
    except WebhookConfigurationError as exc:
        raise HTTPException(status_code=400, detail={"error": "RETRY_ERROR", "message": str(exc)}) from None
    _no_store(response)
    return WebhookDeliveryDetail(
        id=delivery.id,
        webhook_endpoint_id=delivery.webhook_endpoint_id,
        request_id=delivery.request_id,
        event_type=delivery.event_type,
        is_test=delivery.is_test,
        status=delivery.status,
        attempt_count=delivery.attempt_count,
        response_status=delivery.response_status,
        response_body=delivery.response_body,
        last_error=delivery.last_error,
        delivered_at=delivery.delivered_at,
        created_at=delivery.created_at,
    )


@management_router.get("/logs", response_model=list[DeveloperLogResponse])
def get_logs(user: CurrentUser, response: Response,
             workspace: CurrentWorkspace,
             db: Annotated[Session, Depends(get_db)],
             environment: str | None = None,
             status: str | None = None,
             agent_id: str | None = None,
             request_id: str | None = None,
             limit: int = Query(default=100, le=200),
             offset: int = Query(default=0, ge=0)) -> list[DeveloperLogResponse]:
    workspace.require("use_developer_tools")
    _no_store(response)
    return [DeveloperLogResponse(**item) for item in developer_logs(
        db, user.id, workspace.organization_id,
        include_all_organization_keys=workspace.role in {OrganizationRole.OWNER, OrganizationRole.ADMIN},
        environment=environment,
        status_filter=status,
        agent_id_filter=agent_id,
        request_id_filter=request_id,
        limit=limit,
        offset=offset,
    )]


@management_router.get("/logs/{request_id}", response_model=DeveloperLogDetailResponse)
def get_log_detail(
    request_id: str,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> DeveloperLogDetailResponse:
    workspace.require("use_developer_tools")
    detail = get_developer_log_detail(
        db, user.id, workspace.organization_id, request_id,
        include_all_keys=workspace.role in {OrganizationRole.OWNER, OrganizationRole.ADMIN},
    )
    if detail is None:
        raise HTTPException(status_code=404, detail={"error": "LOG_NOT_FOUND", "message": "API request record not found."})
    _no_store(response)
    return DeveloperLogDetailResponse(**detail)


@management_router.get("/production-access/checklist", response_model=ProductionChecklistResponse)
def get_checklist(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> ProductionChecklistResponse:
    workspace.require("use_developer_tools")
    checklist_data = get_production_readiness_checklist(db, user, workspace.organization_id)
    _no_store(response)
    return ProductionChecklistResponse(**checklist_data)


@management_router.post("/production-access/request")
def request_production_access(
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    if workspace.role != OrganizationRole.OWNER:
        raise HTTPException(status_code=403, detail={"error": "FORBIDDEN", "message": "Only organization owners can request production access."})
    org = db.get(Organization, workspace.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail={"error": "ORGANIZATION_NOT_FOUND", "message": "Organization not found."})
    if org.production_access_status == "APPROVED":
        return {"status": "APPROVED", "message": "Production access is already approved."}
    org.production_access_status = "REQUESTED"
    org.production_requested_at = datetime.now(timezone.utc)
    record_security_event(
        db, user.id, "production_access.requested", organization_id=org.id,
        description=f"Production access requested by owner for {org.name}",
    )
    db.commit()
    _no_store(response)
    return {"status": "REQUESTED", "message": "Production access request submitted for security review."}


@management_router.post("/webhook", response_model=WebhookCreated, status_code=201)
def add_webhook(payload: WebhookCreate, request: Request, user: CurrentUser,
                workspace: CurrentWorkspace,
                response: Response, db: Annotated[Session, Depends(get_db)]) -> WebhookCreated:
    target = workspace
    if payload.organization_id != workspace.organization_id:
        target = resolve_workspace(db, user.id, payload.organization_id)
        if target is None:
            raise HTTPException(status_code=404, detail={"error": "ORGANIZATION_NOT_FOUND", "message": "Organization not found."})
    try:
        endpoint, secret = configure_webhook(
            db, request.app.state.settings, target, payload.organization_id, str(payload.url),
        )
    except WebhookConfigurationError as exc:
        message = str(exc)
        status = 404 if message == "Organization not found" else 409 if message == "Webhook already configured" else 422
        raise HTTPException(status_code=status, detail={"error": "WEBHOOK_CONFIG_ERROR", "message": message}) from None
    _no_store(response)
    return WebhookCreated(
        id=endpoint.id,
        organization_id=endpoint.organization_id,
        url=endpoint.url,
        environment=getattr(endpoint, "environment", "production"),
        status=endpoint.status,
        created_at=endpoint.created_at,
        signing_secret=secret,
    )


@management_router.get("/openapi.json")
def get_developer_openapi_spec(request: Request) -> JSONResponse:
    """Generate a clean, sanitized OpenAPI specification containing public developer endpoints."""
    app_schema = request.app.openapi()
    # Filter paths to only public developer APIs
    allowed_prefixes = ("/api/v1/",)
    public_paths = {
        path: methods
        for path, methods in app_schema.get("paths", {}).items()
        if any(path.startswith(prefix) for prefix in allowed_prefixes)
    }
    public_spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "AgentTrust Public Developer API",
            "version": "1.0.0",
            "description": "Cryptographically secure AI agent authorization and runtime permission enforcement.",
        },
        "servers": [{"url": "http://localhost:8000", "description": "Local development / Sandbox"}],
        "paths": public_paths,
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "AgentTrust Sandbox (at_test_...) or Live (at_live_...) API key.",
                },
            },
        },
        "security": [{"ApiKeyAuth": []}],
    }
    return JSONResponse(content=public_spec)


def _developer_response(result) -> DeveloperAuthorizationResponse:
    reason = (
        "High risk — approval required"
        if result.decision == "PENDING" and result.risk_level in {"HIGH", "CRITICAL"}
        else "User approval required" if result.decision == "PENDING" else result.reason
    )
    return DeveloperAuthorizationResponse(
        request_id=result.request_id, status=result.decision, reason=reason,
        risk={"level": result.risk_level} if result.risk_level in {"HIGH", "CRITICAL"} else None,
    )


@api_router.post(
    "/authorize",
    response_model=DeveloperAuthorizationResponse,
    response_model_exclude_none=True,
    summary="Authorize an AI Agent Action",
    description="Submit an AI agent action for cryptographic signature validation, permission evaluation, and risk assessment.",
)
async def authorize(
    principal: DeveloperAuth,
    response: Response,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", min_length=1, max_length=200)] = None,
) -> DeveloperAuthorizationResponse:
    settings = request.app.state.settings
    maximum = settings.agent_signed_body_max_bytes
    declared = request.headers.get("Content-Length")
    if declared is not None and (not declared.isdecimal() or int(declared) > maximum):
        raise HTTPException(status_code=413, detail={"error": "PAYLOAD_TOO_LARGE", "message": "Request body exceeds maximum size."})
    chunks = bytearray()
    async for chunk in request.stream():
        if len(chunks) + len(chunk) > maximum:
            raise HTTPException(status_code=413, detail={"error": "PAYLOAD_TOO_LARGE", "message": "Request body exceeds maximum size."})
        chunks.extend(chunk)
    body = bytes(chunks)
    try:
        payload = AuthorizationRequest.model_validate_json(body)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from None
    try:
        signature = verify_request(
            db, principal, settings, request.app.state.redis_client,
            agent_id=payload.agent_id, headers=request.headers, body=body,
            method=request.method, path=request.url.path, raw_headers=request.scope["headers"],
        )
    except SigningError as exc:
        if exc.code != "REPLAY_PROTECTION_UNAVAILABLE":
            limiter = request.app.state.agent_signature_failure_limiter
            if not limiter.allow(principal.api_key.id, settings.agent_signature_failure_limit_per_minute):
                raise HTTPException(status_code=429, detail={"error": "RATE_LIMIT_EXCEEDED", "message": "Agent signature failure rate limit exceeded."}) from None
            event_type = {
                "REPLAY_DETECTED": "agent_replay_detected",
                "REQUEST_TIMESTAMP_INVALID": "agent_timestamp_rejected",
            }.get(exc.code, "agent_signature_failed")
            event_limiter = request.app.state.agent_signature_event_limiter
            if event_limiter.allow((principal.api_key.id, event_type), 1):
                claimed_key = request.headers.get("X-Agent-Key-ID", "")
                record_security_event(
                    db, None, event_type, organization_id=principal.api_key.organization_id,
                    description="Agent request identity verification failed", severity="warning",
                    details={"api_key_id": str(principal.api_key.id), "agent_id": payload.agent_id,
                             "key_id": claimed_key if KEY_ID_PATTERN.fullmatch(claimed_key) else None},
                )
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None
    try:
        result = developer_authorize(db, principal, payload, idempotency_key, settings, signature=signature)
    except IdempotencyConflict:
        raise HTTPException(
            status_code=409,
            detail={"error": "IDEMPOTENCY_CONFLICT", "message": "Idempotency key was already used with a different request payload."},
        ) from None
    except RequestInProgress:
        raise HTTPException(
            status_code=409,
            detail={"error": "REQUEST_IN_PROGRESS", "message": "Request with this idempotency key is still processing."},
        ) from None
    _no_store(response)
    return _developer_response(result)


@api_router.get(
    "/authorization-requests/{request_id}",
    response_model=DeveloperAuthorizationResponse,
    response_model_exclude_none=True,
    summary="Get Authorization Request Decision",
    description="Check the current status and decision of an authorization request.",
)
def request_status(
    request_id: str,
    principal: DeveloperAuth,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> DeveloperAuthorizationResponse:
    if len(request_id) != 28 or not request_id.startswith("req_"):
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Authorization request not found."})
    try:
        result = get_developer_request(db, principal, request_id)
    except DeveloperRequestNotFound:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND", "message": "Authorization request not found."}) from None
    _no_store(response)
    return _developer_response(result)
