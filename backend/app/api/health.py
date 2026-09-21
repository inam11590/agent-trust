"""Process, dependency, and protected metrics endpoints."""

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.core.observability import metrics

router = APIRouter()


@router.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "AgentTrust API"}

@router.get("/health/live", tags=["health"])
def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", tags=["health"])
def ready(request: Request, db: Session = Depends(get_db)) -> dict:
    settings = request.app.state.settings
    db_status = "unknown"
    redis_status = "disabled"
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        raise HTTPException(status_code=503, detail="Service dependencies unavailable: database offline") from None

    if settings.redis_url.get_secret_value():
        try:
            if request.app.state.redis_client is not None:
                request.app.state.redis_client.ping()
                redis_status = "ok"
            elif settings.redis_required:
                raise HTTPException(status_code=503, detail="Service dependencies unavailable: redis required")
        except Exception:
            if settings.redis_required:
                raise HTTPException(status_code=503, detail="Service dependencies unavailable: redis offline") from None
            redis_status = "degraded"

    is_standby = settings.region_role == "standby" or settings.region_fencing_enabled
    return {
        "status": "ok",
        "region_id": settings.region_id,
        "region_role": settings.region_role,
        "fenced": is_standby,
        "dependencies": {
            "database": db_status,
            "redis": redis_status,
        },
    }


@router.get("/health/region", tags=["health"])
def region_health(request: Request) -> dict:
    settings = request.app.state.settings
    is_standby = settings.region_role == "standby" or settings.region_fencing_enabled
    return {
        "status": "STANDBY" if is_standby else "OPERATIONAL",
        "region_id": settings.region_id,
        "region_role": settings.region_role,
        "fenced": is_standby,
    }


@router.get("/metrics", include_in_schema=False)
def application_metrics(
    request: Request,
    x_metrics_token: str | None = Header(default=None, alias="X-Metrics-Token"),
) -> Response:
    expected = request.app.state.settings.metrics_auth_token.get_secret_value()
    protected = request.app.state.settings.app_env in {"staging", "production"}
    if protected and (not x_metrics_token or not hmac.compare_digest(x_metrics_token, expected)):
        raise HTTPException(status_code=404, detail="Not found")
    return Response(metrics.render(), media_type="text/plain; version=0.0.4")


@router.get("/health/database", tags=["health"])
def database_health(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        # Never return connection strings, credentials, or driver errors.
        raise HTTPException(status_code=503, detail="Database unavailable") from None
    return {"status": "ok", "database": "PostgreSQL"}
