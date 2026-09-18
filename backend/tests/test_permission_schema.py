from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.permission import PermissionCreate


def valid_payload() -> dict:
    return {
        "agent_id": uuid4(),
        "action": "purchase",
        "resource": "flight",
        "maximum_amount": "500.00",
        "currency": "USD",
        "valid_from": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
    }


def test_permission_input_is_normalized_and_uses_decimal_money():
    payload = valid_payload()
    payload.update(action=" Purchase ", resource=" FLIGHT ", currency=" usd ")
    permission = PermissionCreate(**payload)
    assert permission.action == "purchase"
    assert permission.resource == "flight"
    assert permission.currency == "USD"
    assert permission.maximum_amount == Decimal("500.00")
    assert permission.valid_from.tzinfo is not None


def test_valid_from_defaults_to_current_utc_time():
    payload = valid_payload()
    del payload["valid_from"]
    before = datetime.now(timezone.utc)
    permission = PermissionCreate(**payload)
    after = datetime.now(timezone.utc)
    assert before <= permission.valid_from <= after


@pytest.mark.parametrize(
    "updates",
    [
        {"maximum_amount": "0"},
        {"maximum_amount": "-1"},
        {"maximum_amount": "1.00001"},
        {"maximum_amount": "1000000000000000.0000"},
        {"maximum_amount": None, "currency": "USD"},
        {"maximum_amount": "500", "currency": None},
        {"currency": "US"},
        {"currency": "USDD"},
        {"currency": "123"},
        {"action": ""},
        {"action": "purchase flight"},
        {"resource": ""},
        {"resource": "flight ticket"},
    ],
)
def test_invalid_amount_currency_and_capability_values_are_rejected(updates):
    payload = valid_payload()
    payload.update(updates)
    with pytest.raises(ValidationError):
        PermissionCreate(**payload)


@pytest.mark.parametrize("mode", ["equal", "reversed", "past", "naive_start", "naive_end"])
def test_invalid_dates_are_rejected(mode):
    payload = valid_payload()
    now = datetime.now(timezone.utc)
    if mode == "equal":
        payload["valid_from"] = now + timedelta(hours=1)
        payload["expires_at"] = payload["valid_from"]
    elif mode == "reversed":
        payload["valid_from"] = now + timedelta(hours=2)
        payload["expires_at"] = now + timedelta(hours=1)
    elif mode == "past":
        payload["valid_from"] = now - timedelta(hours=2)
        payload["expires_at"] = now - timedelta(hours=1)
    elif mode == "naive_start":
        payload["valid_from"] = datetime.now()
    else:
        payload["expires_at"] = datetime.now() + timedelta(hours=1)
    with pytest.raises(ValidationError):
        PermissionCreate(**payload)


@pytest.mark.parametrize("field", ["owner_id", "status", "id"])
def test_server_owned_fields_are_rejected(field):
    payload = valid_payload()
    payload[field] = "client-controlled"
    with pytest.raises(ValidationError):
        PermissionCreate(**payload)
