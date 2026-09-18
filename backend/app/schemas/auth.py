"""Validated JSON authentication requests and the access-token response."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator


class EmailCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: EmailStr = Field(max_length=320)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower()


class RegisterRequest(EmailCredentials):
    password: SecretStr = Field(min_length=15, max_length=128)
    full_name: str = Field(min_length=1, max_length=200)

    @field_validator("full_name", mode="before")
    @classmethod
    def trim_name(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


class LoginRequest(EmailCredentials):
    password: SecretStr = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class MFARequiredResponse(BaseModel):
    status: Literal["MFA_REQUIRED"] = "MFA_REQUIRED"
    challenge_token: str
    expires_in: int


class MFAVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    challenge_token: SecretStr = Field(min_length=32, max_length=128)
    code: SecretStr = Field(min_length=6, max_length=64)
