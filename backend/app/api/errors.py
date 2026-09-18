"""Safe API errors that omit submitted inputs and database details."""

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from app.services.plan_limits import PlanLimitReached


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
                for error in exc.errors()
            ],
        },
    )


async def database_error_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

async def plan_limit_error_handler(request: Request, exc: PlanLimitReached) -> JSONResponse:
    return JSONResponse(status_code=402, content={"error": exc.code, "message": exc.message})
