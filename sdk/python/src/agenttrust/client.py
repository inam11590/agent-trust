"""AgentTrust HTTP client; API keys and local signing keys are never logged."""

from dataclasses import dataclass
from decimal import Decimal
import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from pathlib import Path

from agenttrust.signing import AgentSigner


class AgentTrustError(Exception):
    pass


@dataclass(frozen=True)
class AuthorizationResult:
    request_id: str
    status: str
    reason: str


class AgentTrust:
    def __init__(self, api_key: str, base_url: str = "https://api.agenttrust.example", timeout: float = 10.0):
        if not api_key or not (api_key.startswith("at_live_") or api_key.startswith("at_test_")):
            raise ValueError("A valid AgentTrust API key is required")
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must use HTTP or HTTPS")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self.environment = "sandbox" if api_key.startswith("at_test_") else "production"

    @classmethod
    def from_env(cls, base_url: str | None = None, timeout: float = 10.0) -> "AgentTrust":
        key = os.environ.get("AGENTTRUST_API_KEY", "")
        url = base_url or os.environ.get("AGENTTRUST_BASE_URL", "https://api.agenttrust.example")
        return cls(key, url, timeout)

    def authorize(self, *, agent_id: str, action: str, resource: str,
                  amount: int | float | Decimal | None = None, currency: str | None = None,
                  delegation_id: str | None = None,
                  idempotency_key: str | None = None) -> AuthorizationResult:
        return self._authorize(agent_id=agent_id, action=action, resource=resource,
            amount=amount, currency=currency, delegation_id=delegation_id,
            idempotency_key=idempotency_key, signer=None)

    def agent(self, *, agent_id: str, key_id: str, private_key_path: str | Path) -> "SignedAgent":
        return SignedAgent(self, AgentSigner(agent_id, key_id, private_key_path))

    def _authorize(self, *, agent_id: str, action: str, resource: str,
                   amount: int | float | Decimal | None, currency: str | None,
                   delegation_id: str | None = None,
                   idempotency_key: str | None, signer: AgentSigner | None) -> AuthorizationResult:
        if not agent_id or not action or not resource:
            raise ValueError("agent_id, action, and resource are required")
        if (amount is None) != (currency is None):
            raise ValueError("amount and currency must be provided together")
        if amount is not None and Decimal(str(amount)) < 0:
            raise ValueError("amount cannot be negative")
        body: dict[str, Any] = {"agent_id": agent_id, "action": action, "resource": resource}
        if amount is not None:
            body.update(amount=float(amount), currency=currency)
        if delegation_id is not None:
            body["delegation_id"] = delegation_id
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._result(self._request("POST", "/api/v1/authorize", body, headers, signer=signer))

    def create_delegation(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/v1/agent-delegations", payload)

    def list_delegations(self, *, parent_agent_id: str | None = None, child_agent_id: str | None = None) -> list[dict[str, Any]]:
        params = []
        if parent_agent_id:
            params.append(f"parent_agent_id={parent_agent_id}")
        if child_agent_id:
            params.append(f"child_agent_id={child_agent_id}")
        query = f"?{'&'.join(params)}" if params else ""
        return self._request("GET", f"/api/v1/agent-delegations{query}")

    def get_delegation(self, delegation_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/agent-delegations/{delegation_id}")

    def get_delegation_chain(self, delegation_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/agent-delegations/{delegation_id}/chain")

    def revoke_delegation(self, delegation_id: str, reason: str = "Revoked by user") -> dict[str, Any]:
        return self._request("POST", f"/api/v1/agent-delegations/{delegation_id}/revoke", {"reason": reason})

    def get_request(self, request_id: str) -> AuthorizationResult:
        if not request_id.startswith("req_"):
            raise ValueError("A valid request_id is required")
        return self._result(self._request("GET", f"/api/v1/authorization-requests/{request_id}"))

    @staticmethod
    def _result(data: dict[str, Any]) -> AuthorizationResult:
        return AuthorizationResult(str(data["request_id"]), str(data["status"]), str(data["reason"]))

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None,
                 extra_headers: dict[str, str] | None = None,
                 signer: AgentSigner | None = None) -> dict[str, Any]:
        headers = {"X-API-Key": self._api_key, "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode()
        if signer is not None:
            if data is None:
                raise ValueError("Signed authorization needs a request body")
            headers.update(signer.headers(method, path, data))
        request = Request(self._base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read())
        except HTTPError as error:
            try:
                detail = json.loads(error.read()).get("detail", "API request failed")
            except Exception:
                detail = "API request failed"
            raise AgentTrustError(f"AgentTrust API error ({error.code}): {detail}") from None
        except (URLError, TimeoutError):
            raise AgentTrustError("Could not connect to AgentTrust") from None


class SignedAgent:
    def __init__(self, client: AgentTrust, signer: AgentSigner):
        self._client = client
        self._signer = signer

    @property
    def agent_id(self) -> str:
        return self._signer.agent_id

    def authorize(self, *, action: str, resource: str,
                  amount: int | float | Decimal | None = None, currency: str | None = None,
                  delegation_id: str | None = None,
                  idempotency_key: str | None = None) -> AuthorizationResult:
        return self._client._authorize(agent_id=self._signer.agent_id, action=action,
            resource=resource, amount=amount, currency=currency,
            delegation_id=delegation_id,
            idempotency_key=idempotency_key, signer=self._signer)

    def delegate(self, *, child_agent_id: str, parent_permission_id: str,
                 action: str, resource: str,
                 maximum_amount: int | float | Decimal | None = None,
                 currency: str | None = None,
                 requires_approval: bool = False,
                 allow_delegation: bool = True,
                 expires_at: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "parent_agent_id": self._signer.agent_id,
            "child_agent_id": child_agent_id,
            "parent_permission_id": parent_permission_id,
            "action": action,
            "resource": resource,
            "requires_approval": requires_approval,
            "allow_delegation": allow_delegation,
        }
        if maximum_amount is not None:
            payload["maximum_amount"] = float(maximum_amount)
            payload["currency"] = currency
        if expires_at is not None:
            payload["expires_at"] = expires_at
        return self._client.create_delegation(payload)
