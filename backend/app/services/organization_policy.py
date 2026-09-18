"""Organization rules that can only strengthen a valid permission/risk result."""

from sqlalchemy.orm import Session
from uuid import UUID

from app.models import OrganizationSecurityPolicy
from app.schemas.authorization import AuthorizationRequest
from app.services.risk_engine import RiskEvaluation


def evaluate_organization_policy(db: Session, organization_id: UUID | None,
                                 request: AuthorizationRequest, risk: RiskEvaluation) -> tuple[str, str | None]:
    if organization_id is None:
        return "ALLOW", None
    policy = db.get(OrganizationSecurityPolicy, organization_id)
    if policy is None:
        return "ALLOW", None
    if policy.block_critical_risk and risk.level.value == "CRITICAL":
        return "DENY", "Request rejected by organization security policy"
    if policy.require_approval_for_high_risk and risk.level.value in {"HIGH", "CRITICAL"}:
        return "REQUIRE_APPROVAL", "Organization policy requires approval for high-risk actions"
    threshold = policy.require_manual_approval_above_amount
    if request.action == "purchase" and threshold is not None:
        if request.currency != policy.approval_threshold_currency:
            return "REQUIRE_APPROVAL", "Organization policy requires approval for purchases in a different currency"
        if request.amount is not None and request.amount > threshold:
            return "REQUIRE_APPROVAL", f"Organization policy requires approval for purchases above {threshold.normalize()} {policy.approval_threshold_currency}"
    return "ALLOW", None
