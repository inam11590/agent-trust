"""Reliability and disaster recovery management API."""

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.config import Settings
from app.database.session import get_db
from app.models.user import User
from app.services.reliability import get_system_status, reconcile_security_state

router = APIRouter()


class VerifyBackupRequest(BaseModel):
    manifest_path: str = Field(description="Relative or absolute path to backup_manifest.json")


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Active user access required")
    return user


@router.get("/reliability/status", tags=["reliability"])
def reliability_status(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Returns cluster health, region role, and dependency status for administrators."""
    return get_system_status(db, request.app.state.redis_client, request.app.state.settings)


@router.get("/reliability/reconcile", tags=["reliability"])
def security_reconciliation(
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Executes a security state audit verifying durability of revocations, approvals, and nonces."""
    return reconcile_security_state(db)


@router.post("/reliability/backup/verify", tags=["reliability"])
def verify_backup(
    payload: VerifyBackupRequest,
    user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Verifies SHA-256 integrity and structure of a backup manifest."""
    manifest_path = Path(payload.manifest_path)
    if not manifest_path.is_file():
        raise HTTPException(status_code=404, detail="Manifest file not found")

    import json
    import hashlib

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        dump_filename = data.get("backup_file")
        expected_sha256 = data.get("sha256")
        dump_path = manifest_path.parent / dump_filename
        if not dump_path.is_file():
            raise HTTPException(status_code=404, detail=f"Backup file '{dump_filename}' not found alongside manifest")

        hasher = hashlib.sha256()
        with open(dump_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        computed_sha256 = hasher.hexdigest()

        if computed_sha256 != expected_sha256:
            raise HTTPException(
                status_code=400,
                detail=f"Integrity check failed: checksum mismatch (expected {expected_sha256}, got {computed_sha256})",
            )

        return {
            "status": "VALID",
            "backup_file": dump_filename,
            "sha256": computed_sha256,
            "created_at": data.get("created_at"),
            "table_counts": data.get("table_counts", {}),
            "integrity_verified": True,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Verification error: {str(exc)}")
