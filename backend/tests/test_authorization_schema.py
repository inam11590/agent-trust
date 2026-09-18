from decimal import Decimal

import pytest
from pydantic import ValidationError

from app.schemas.authorization import AuthorizationRequest


def valid_request() -> dict:
    return {
        "agent_id": "agt_" + "a" * 24,
        "action": "purchase",
        "resource": "flight",
        "amount": "420.00",
        "currency": "USD",
    }


def test_authorization_request_normalizes_values_and_preserves_decimal_money():
    payload = valid_request()
    payload.update(action=" Purchase ", resource=" FLIGHT ", currency=" usd ")
    request = AuthorizationRequest(**payload)
    assert request.action == "purchase"
    assert request.resource == "flight"
    assert request.amount == Decimal("420.00")
    assert request.currency == "USD"


@pytest.mark.parametrize(
    "updates",
    [
        {"agent_id": "invalid"},
        {"agent_id": "agt_" + "g" * 24},
        {"action": "purchase flight"},
        {"resource": ""},
        {"amount": "-0.01"},
        {"amount": "1.00001"},
        {"amount": "1000000000000000.0000"},
        {"amount": None, "currency": "USD"},
        {"amount": "10", "currency": None},
        {"currency": "US"},
        {"currency": "123"},
        {"owner_id": "client-controlled"},
    ],
)
def test_invalid_authorization_requests_are_rejected(updates):
    payload = valid_request()
    payload.update(updates)
    with pytest.raises(ValidationError):
        AuthorizationRequest(**payload)


def test_non_monetary_request_is_valid():
    payload = valid_request()
    payload.update(amount=None, currency=None)
    request = AuthorizationRequest(**payload)
    assert request.amount is None
    assert request.currency is None
