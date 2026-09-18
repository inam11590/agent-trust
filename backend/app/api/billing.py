"""Authenticated organization billing API and unauthenticated signed provider webhook."""

from typing import Annotated
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import OrganizationRole
from app.schemas.billing import (CancelResponse, CheckoutRequest, CheckoutResponse, PlanResponse,
    PortalResponse, SubscriptionResponse, UsageItem, UsageResponse)
from app.services.billing import BillingInputError, cancel, create_checkout, list_plans, portal_url, process_webhook
from app.services.billing_providers import BillingProviderError
from app.services.organization_context import CurrentWorkspace
from app.services.plan_limits import month_period, usage_values

router = APIRouter(prefix="/billing", tags=["billing"])

def _organization(workspace: CurrentWorkspace):
    if workspace.organization_id is None: raise HTTPException(422, detail="Select an organization workspace for billing")
    return workspace.organization_id

def _manage(workspace: CurrentWorkspace, request: Request) -> None:
    workspace.require("manage_billing")
    if workspace.role == OrganizationRole.ADMIN and not request.app.state.settings.billing_admin_can_manage:
        raise HTTPException(403, detail="Only the organization owner can change billing")

@router.get("/plans", response_model=list[PlanResponse])
def plans(request: Request, user: CurrentUser, db: Annotated[Session, Depends(get_db)]): return list_plans(db, request.app.state.settings)

@router.get("/subscription", response_model=SubscriptionResponse)
def subscription(user: CurrentUser, workspace: CurrentWorkspace, db: Annotated[Session, Depends(get_db)]):
    workspace.require("view_billing"); org = _organization(workspace); record, plan, values = usage_values(db, org)
    return SubscriptionResponse(organization_id=org, plan=PlanResponse.model_validate(plan), status=record.status,
        current_period_start=record.current_period_start, current_period_end=record.current_period_end,
        cancel_at_period_end=record.cancel_at_period_end, trial_ends_at=record.trial_ends_at, grace_ends_at=record.grace_ends_at,
        usage={key: UsageItem(used=value.used, limit=value.limit) for key, value in values.items()})

@router.get("/usage", response_model=UsageResponse)
def usage(user: CurrentUser, workspace: CurrentWorkspace, db: Annotated[Session, Depends(get_db)]):
    workspace.require("view_billing"); org = _organization(workspace); _, plan, values = usage_values(db, org); start, end = month_period()
    return UsageResponse(organization_id=org, plan_code=plan.code, period_start=start, period_end=end,
        usage={key: UsageItem(used=value.used, limit=value.limit) for key, value in values.items()})

@router.post("/checkout", response_model=CheckoutResponse)
def checkout(payload: CheckoutRequest, request: Request, user: CurrentUser, workspace: CurrentWorkspace, db: Annotated[Session, Depends(get_db)]):
    _manage(workspace, request); org = _organization(workspace)
    try: return CheckoutResponse(checkout_url=create_checkout(db, request.app.state.settings, org, user.id, user.email, payload.plan_code))
    except (BillingInputError, BillingProviderError) as exc: raise HTTPException(422, detail=str(exc)) from None

@router.post("/portal", response_model=PortalResponse)
def portal(request: Request, user: CurrentUser, workspace: CurrentWorkspace, db: Annotated[Session, Depends(get_db)]):
    _manage(workspace, request); org = _organization(workspace)
    try: return PortalResponse(portal_url=portal_url(db, request.app.state.settings, org))
    except (BillingInputError, BillingProviderError) as exc: raise HTTPException(422, detail=str(exc)) from None

@router.post("/cancel", response_model=CancelResponse)
def cancel_subscription(request: Request, user: CurrentUser, workspace: CurrentWorkspace, db: Annotated[Session, Depends(get_db)]):
    from app.api.account_security import require_recent_step_up
    require_recent_step_up(request)
    if workspace.role != OrganizationRole.OWNER: raise HTTPException(403, detail="Only the organization owner can cancel a subscription")
    record = cancel(db, request.app.state.settings, _organization(workspace), user.id)
    return CancelResponse(status=record.status, cancel_at_period_end=record.cancel_at_period_end, current_period_end=record.current_period_end)

@router.post("/webhook")
async def webhook(request: Request, db: Annotated[Session, Depends(get_db)], paddle_signature: Annotated[str | None, Header(alias="Paddle-Signature")] = None):
    body = await request.body()
    try: result = process_webhook(db, request.app.state.settings, body, paddle_signature or "")
    except (BillingInputError, BillingProviderError): raise HTTPException(400, detail="Invalid billing webhook") from None
    return {"status": result}
