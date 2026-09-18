"""Private in-app notifications, preferences, mobile devices, and SSE updates."""

import asyncio
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser
from app.database.session import get_db
from app.models import Notification
from app.schemas.notification import (
    DeviceCreate, DeviceResponse, NotificationFilters, NotificationPreferenceResponse,
    NotificationPreferenceUpdate, NotificationResponse, PaginatedNotifications, UnreadCountResponse,
)
from app.services.notification_service import (
    archive_notification, get_preferences, list_notifications, mark_all_read, mark_read,
    register_device, revoke_device, unread_count, update_preferences,
)
from app.services.notification_service import DeviceLimitReached, DeviceTokenConflict

router = APIRouter(tags=["notifications"])


@router.get("/notifications", response_model=PaginatedNotifications)
def get_notifications(
    filters: Annotated[NotificationFilters, Depends()], user: CurrentUser,
    response: Response, db: Annotated[Session, Depends(get_db)],
) -> PaginatedNotifications:
    items, total, pages = list_notifications(db, user.id, filters)
    response.headers["Cache-Control"] = "no-store"
    return PaginatedNotifications(
        items=[NotificationResponse.model_validate(item) for item in items],
        page=filters.page, page_size=filters.page_size, total=total, total_pages=pages,
    )


@router.get("/notifications/unread-count", response_model=UnreadCountResponse)
def get_unread_count(user: CurrentUser, response: Response, db: Annotated[Session, Depends(get_db)]):
    response.headers["Cache-Control"] = "no-store"
    return UnreadCountResponse(count=unread_count(db, user.id))


@router.post("/notifications/{notification_id}/read", response_model=NotificationResponse)
def read_notification(
    notification_id: UUID, user: CurrentUser, response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    item = mark_read(db, user.id, notification_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    response.headers["Cache-Control"] = "no-store"
    return NotificationResponse.model_validate(item)


@router.post("/notifications/read-all", response_model=UnreadCountResponse)
def read_all_notifications(user: CurrentUser, db: Annotated[Session, Depends(get_db)]):
    mark_all_read(db, user.id)
    return UnreadCountResponse(count=0)


@router.post("/notifications/{notification_id}/archive", response_model=NotificationResponse)
def archive_one_notification(
    notification_id: UUID, user: CurrentUser, response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    item = archive_notification(db, user.id, notification_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    response.headers["Cache-Control"] = "no-store"
    return NotificationResponse.model_validate(item)


@router.get("/notification-preferences", response_model=NotificationPreferenceResponse)
def get_notification_preferences(
    user: CurrentUser, response: Response, db: Annotated[Session, Depends(get_db)],
):
    preference = get_preferences(db, user.id)
    db.commit()
    db.refresh(preference)
    response.headers["Cache-Control"] = "no-store"
    return NotificationPreferenceResponse.model_validate(preference)


@router.patch("/notification-preferences", response_model=NotificationPreferenceResponse)
def patch_notification_preferences(
    payload: NotificationPreferenceUpdate, user: CurrentUser, response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    response.headers["Cache-Control"] = "no-store"
    return NotificationPreferenceResponse.model_validate(update_preferences(db, user.id, payload))


@router.post("/devices", response_model=DeviceResponse, status_code=201)
def add_device(
    payload: DeviceCreate, user: CurrentUser, response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    try:
        device = register_device(db, user.id, payload)
    except DeviceTokenConflict:
        raise HTTPException(status_code=409, detail="Push token is already registered") from None
    except DeviceLimitReached:
        raise HTTPException(status_code=429, detail="Too many active devices") from None
    response.headers["Cache-Control"] = "no-store"
    response.headers["Location"] = f"/devices/{device.id}"
    return DeviceResponse.model_validate(device)


@router.delete("/devices/{device_id}", status_code=204)
def delete_device(device_id: UUID, user: CurrentUser, db: Annotated[Session, Depends(get_db)]):
    if not revoke_device(db, user.id, device_id):
        raise HTTPException(status_code=404, detail="Device not found")
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


@router.get("/notifications/stream")
async def stream_notifications(request: Request, user: CurrentUser):
    """Send a small user-specific SSE snapshot whenever unread state changes."""
    factory = request.app.state.session_factory
    user_id = user.id

    async def events():
        previous: tuple[int, str | None] | None = None
        while not await request.is_disconnected():
            with factory() as db:
                count = unread_count(db, user_id)
                latest = db.scalar(select(Notification).where(
                    Notification.user_id == user_id,
                ).order_by(Notification.created_at.desc(), Notification.id.desc()).limit(1))
                current = (count, str(latest.id) if latest else None)
            if current != previous:
                yield f"event: notifications\ndata: {json.dumps({'count': count, 'latest_id': current[1]})}\n\n"
                previous = current
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(events(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no",
    })
