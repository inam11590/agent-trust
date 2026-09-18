"""Validated authorization requests and decision responses."""

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator


class AuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    agent_id: str = Field(min_length=1, max_length=255, pattern=r"^agt_[0-9a-f]{24}$")
    action: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    resource: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9:_-]*$")
    amount: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=19,
        decimal_places=4,
    )
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    delegation_id: str | None = Field(default=None, pattern=r"^dlg_[0-9a-f]{24}$")

    @field_validator("action", "resource", mode="before")
    @classmethod
    def normalize_capability(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("currency", mode="before")
    @classmethod
    def normalize_currency(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_money_pair(self) -> "AuthorizationRequest":
        if (self.amount is None) != (self.currency is None):
            raise ValueError("amount and currency must be provided together")
        return self


class AuthorizationResponse(BaseModel):
    request_id: str = Field(pattern=r"^req_[0-9a-f]{24}$")
    decision: str = Field(pattern=r"^(APPROVED|REJECTED|PENDING)$")
    reason: str
    risk: "OwnerRiskResponse | None" = None


class OwnerRiskResponse(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str = Field(pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    reasons: list[str]
