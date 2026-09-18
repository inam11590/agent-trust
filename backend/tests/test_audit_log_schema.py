"""Validation tests for bounded audit-log filters."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.audit_log import AuditLogFilters


def test_audit_filters_normalize_capabilities() -> None:
    filters = AuditLogFilters(action=" Purchase ", resource=" FLIGHT ")
    assert filters.action == "purchase"
    assert filters.resource == "flight"


@pytest.mark.parametrize(
    "values",
    [
        {"page": 0},
        {"page_size": 0},
        {"page_size": 101},
        {"decision": "UNKNOWN"},
        {"agent_id": "not-an-agent"},
        {"start_date": datetime(2026, 1, 2, tzinfo=timezone.utc),
         "end_date": datetime(2026, 1, 1, tzinfo=timezone.utc)},
    ],
)
def test_invalid_audit_filters_are_rejected(values: dict) -> None:
    with pytest.raises(ValidationError):
        AuditLogFilters(**values)
