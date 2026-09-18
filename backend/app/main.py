"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from fastapi.responses import JSONResponse
import logging
import secrets
from time import perf_counter

from app.api.health import router as health_router
from app.api.auth import router as auth_router
from app.api.account_security import router as account_security_router
from app.api.enterprise_security import router as enterprise_security_router
from app.api.authorization import router as authorization_router
from app.api.authorization_requests import router as authorization_requests_router
from app.api.developer import api_router as developer_api_router, management_router as developer_management_router
from app.api.audit_logs import router as audit_logs_router
from app.api.agents import router as agents_router
from app.api.agent_signing import router as agent_signing_router
from app.api.permissions import router as permissions_router
from app.api.agent_delegations import router as agent_delegations_router
from app.api.users import router as users_router
from app.api.organizations import router as organizations_router
from app.api.notifications import router as notifications_router
from app.api.risk import router as risk_router
from app.api.billing import router as billing_router
from app.api.cross_organization_trust import router as cross_org_trust_router, profile_router as cross_org_profile_router
from app.api.cross_org_requests import router as cross_org_requests_router
from app.api.errors import database_error_handler, validation_error_handler, plan_limit_error_handler
from app.services.plan_limits import PlanLimitReached
from app.core.config import Settings
from app.database.session import create_database_engine
from app.services.rate_limit import create_rate_limiter
from app.core.observability import configure_logging, metrics, request_id_context, scrub_error_event


@asynccontextmanager
async def lifespan(application: FastAPI):
    settings = application.state.settings
    engine = create_database_engine(settings) if settings.database_configured else None
    application.state.engine = engine
    application.state.session_factory = sessionmaker(engine) if engine is not None else None
    application.state.redis_client = None
    if settings.redis_url.get_secret_value():
        from redis import Redis
        application.state.redis_client = Redis.from_url(settings.redis_url.get_secret_value(), socket_connect_timeout=2, socket_timeout=2)
    try:
        yield
    finally:
        if engine is not None:
            engine.dispose()
        if application.state.redis_client is not None:
            application.state.redis_client.close()


def create_app() -> FastAPI:
    settings = Settings()
    configure_logging(settings.log_level)
    if settings.sentry_dsn.get_secret_value():
        import sentry_sdk
        sentry_sdk.init(dsn=settings.sentry_dsn.get_secret_value(), environment=settings.sentry_environment or settings.app_env,
            traces_sample_rate=settings.sentry_traces_sample_rate, send_default_pii=False, before_send=scrub_error_event)
    application = FastAPI(title="AgentTrust API", version="0.1.0", lifespan=lifespan)
    application.state.settings = settings
    application.state.auth_rate_limiter = create_rate_limiter(settings, "agenttrust:auth")
    application.state.developer_rate_limiter = create_rate_limiter(settings, "agenttrust:developer")
    application.state.agent_signature_failure_limiter = create_rate_limiter(settings, "agenttrust:signature-failure")
    application.state.agent_signature_event_limiter = create_rate_limiter(settings, "agenttrust:signature-event")
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Organization-ID", "Idempotency-Key",
                       "X-Agent-ID", "X-Agent-Key-ID", "X-Agent-Timestamp", "X-Agent-Nonce",
                       "X-Agent-Signature", "X-Agent-Signature-Version"],
    )
    application.include_router(health_router)
    application.include_router(auth_router)
    application.include_router(account_security_router)
    application.include_router(enterprise_security_router)
    application.include_router(users_router)
    application.include_router(organizations_router)
    application.include_router(notifications_router)
    application.include_router(risk_router)
    application.include_router(billing_router)
    application.include_router(agents_router)
    application.include_router(agent_signing_router)
    application.include_router(permissions_router)
    application.include_router(agent_delegations_router)
    application.include_router(cross_org_trust_router)
    application.include_router(cross_org_profile_router)
    application.include_router(cross_org_requests_router)
    application.include_router(authorization_router)
    application.include_router(authorization_requests_router)
    application.include_router(developer_management_router)
    application.include_router(developer_api_router)
    application.include_router(audit_logs_router)
    application.add_exception_handler(RequestValidationError, validation_error_handler)
    application.add_exception_handler(SQLAlchemyError, database_error_handler)
    application.add_exception_handler(PlanLimitReached, plan_limit_error_handler)

    @application.middleware("http")
    async def production_middleware(request: Request, call_next):
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if supplied.startswith("req_") and 8 <= len(supplied) <= 80 and supplied.replace("_", "").isalnum() else f"req_{secrets.token_hex(12)}"
        request.state.request_id = request_id; token = request_id_context.set(request_id); started = perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logging.getLogger("agenttrust").exception("unhandled_request_error", extra={"event": "unhandled_error"})
            response = JSONResponse(status_code=500, content={"error": "INTERNAL_ERROR", "message": "An unexpected error occurred.", "request_id": request_id})
        route = getattr(request.scope.get("route"), "path", "unmatched")
        duration = perf_counter() - started
        metrics.http(request.method, route, response.status_code, duration)
        logging.getLogger("agenttrust.access").info("request_complete", extra={"route": route, "method": request.method, "status_code": response.status_code, "duration_ms": round(duration * 1000, 2)})
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if application.state.settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        request_id_context.reset(token)
        return response
    return application


app = create_app()
