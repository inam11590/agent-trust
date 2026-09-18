"""One engine per application; one session per request."""

from collections.abc import Generator

from fastapi import HTTPException, Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from app.core.config import Settings


def create_database_engine(settings: Settings) -> Engine:
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
        pool_recycle=settings.database_pool_recycle_seconds,
        hide_parameters=True,
        connect_args={"options": "-c statement_timeout=5000"},
    )


def get_db(request: Request) -> Generator[Session, None, None]:
    factory = request.app.state.session_factory
    if factory is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    # Callers explicitly commit writes; close rolls back unfinished work.
    with factory() as session:
        yield session
