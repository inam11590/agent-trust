"""Protected HTTP entry point for authorization decisions."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.schemas.authorization import AuthorizationRequest, AuthorizationResponse
from app.services.authorization import authorize_action
from app.services.organization_context import CurrentWorkspace

router = APIRouter(tags=["authorization"])


@router.post("/authorize", response_model=AuthorizationResponse)
def authorize(
    payload: AuthorizationRequest,
    user: CurrentUser,
    workspace: CurrentWorkspace,
    response: Response,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> AuthorizationResponse:
    workspace.require("decide_requests")
    result = authorize_action(
        db, user.id, payload, organization_scope=workspace.organization_id,
        settings=request.app.state.settings,
    )
    response.headers["Cache-Control"] = "no-store"
    return AuthorizationResponse(
        request_id=result.request_id,
        decision=result.decision,
        reason=result.reason,
        risk={
            "score": result.risk_score,
            "level": result.risk_level,
            "reasons": list(result.risk_reasons),
        } if result.risk_level else None,
    )
