"""AgentTrust HTTP client; API keys and local signing keys are never logged."""

from __future__ import annotations

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


@dataclass(frozen=True)
class CrossOrgAuthorizationResult:
    request_id: str
    status: str
    reason: str
    pending_approvals: list[str]


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
        self.credentials = CredentialsClient(self)
        self.issuers = IssuersClient(self)
        self.gateways = GatewaysClient(self)
        self.security = SecurityClient(self)
        self.policies = PoliciesClient(self)

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

    def authorize_cross_org(
        self,
        *,
        source_agent_id: str,
        target_org_id: str,
        target_agent_id: str,
        action: str,
        resource: str,
        amount: int | float | Decimal | None = None,
        currency: str | None = None,
        delegation_id: str | None = None,
        context: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        signer: AgentSigner | None = None,
        source_org_id: str | None = None,
    ) -> CrossOrgAuthorizationResult:
        if not source_agent_id or not target_org_id or not target_agent_id or not action or not resource:
            raise ValueError("source_agent_id, target_org_id, target_agent_id, action, and resource are required")
        if (amount is None) != (currency is None):
            raise ValueError("amount and currency must be provided together")
        if amount is not None and Decimal(str(amount)) < 0:
            raise ValueError("amount cannot be negative")
        body: dict[str, Any] = {
            "source_agent_id": source_agent_id,
            "target_org_id": target_org_id,
            "target_agent_id": target_agent_id,
            "action": action,
            "resource": resource,
        }
        if amount is not None:
            body.update(amount=float(amount), currency=currency)
        if delegation_id is not None:
            body["delegation_id"] = delegation_id
        if context is not None:
            body["context"] = context
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else {}
        if signer is not None:
            raw_body = json.dumps(body, separators=(",", ":")).encode("ascii")
            headers.update(
                signer.cross_org_headers(
                    method="POST",
                    path="/api/v1/cross-org/authorize",
                    body=raw_body,
                    source_org_id=source_org_id or "00000000-0000-0000-0000-000000000000",
                    target_org_id=target_org_id,
                    target_agent_id=target_agent_id,
                )
            )
        res = self._request("POST", "/api/v1/cross-org/authorize", body, headers if headers else None)
        return CrossOrgAuthorizationResult(
            request_id=str(res.get("request_id", "")),
            status=str(res.get("status", "")),
            reason=str(res.get("reason", "")),
            pending_approvals=list(res.get("pending_approvals") or []),
        )

    # Cross-Organization Trust Management
    def list_trust(self, *, status: str | None = None, direction: str | None = None) -> list[dict[str, Any]]:
        params = []
        if status:
            params.append(f"status={status}")
        if direction:
            params.append(f"direction={direction}")
        query = f"?{'&'.join(params)}" if params else ""
        return self._request("GET", f"/v1/organization-trust{query}")

    def get_trust(self, trust_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/organization-trust/{trust_id}")

    def request_trust(self, *, target_org_id: str, proposed_policy: dict[str, Any], notes: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"target_organization_id": target_org_id, "proposed_policy": proposed_policy}
        if notes:
            payload["notes"] = notes
        return self._request("POST", "/v1/organization-trust/request", payload)

    def accept_trust(self, trust_id: str, agreed_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"agreed_policy": agreed_policy} if agreed_policy else {}
        return self._request("POST", f"/v1/organization-trust/{trust_id}/accept", payload)

    def reject_trust(self, trust_id: str, reason: str = "Rejected by target organization") -> dict[str, Any]:
        return self._request("POST", f"/v1/organization-trust/{trust_id}/reject", {"reason": reason})

    def revoke_trust(self, trust_id: str, reason: str = "Revoked by organization") -> dict[str, Any]:
        return self._request("POST", f"/v1/organization-trust/{trust_id}/revoke", {"reason": reason})

    def search_profiles(self, *, query: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
        params = []
        if query:
            params.append(f"q={query}")
        if tag:
            params.append(f"tag={tag}")
        qs = f"?{'&'.join(params)}" if params else ""
        return self._request("GET", f"/v1/organization-trust/directory{qs}")

    def update_public_profile(self, org_id: str, profile: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", f"/v1/organizations/{org_id}/public-profile", profile)

    def set_target_policy(self, org_id: str, target_org_id: str, policy: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", f"/v1/organizations/{org_id}/target-policy/{target_org_id}", policy)

    def connect_external_agent(self, trust_id: str, *, external_agent_id: str, internal_agent_id: str, agreed_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"external_agent_id": external_agent_id, "internal_agent_id": internal_agent_id}
        if agreed_policy:
            payload["agreed_policy"] = agreed_policy
        return self._request("POST", f"/v1/organization-trust/{trust_id}/agents/connect", payload)

    def list_external_agents(self, trust_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/v1/organization-trust/{trust_id}/agents")

    def get_cross_org_request(self, request_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/cross-org/requests/{request_id}")

    def decide_cross_org_approval(self, request_id: str, *, decision: str, reason: str | None = None) -> dict[str, Any]:
        payload = {"decision": decision}
        if reason:
            payload["reason"] = reason
        return self._request("POST", f"/v1/cross-org/requests/{request_id}/approve", payload)

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

    def dispatch_atp_envelope(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a signed ATP/1.0 envelope to the AgentTrust Gateway."""
        return self._request("POST", "/api/v1/atp/messages", envelope)

    def get_atp_message(self, message_id: str) -> dict[str, Any]:
        """Retrieve state and delivery audit logs for an ATP message."""
        return self._request("GET", f"/api/v1/atp/messages/{message_id}")

    def get_gateway_identity(self) -> dict[str, Any]:
        """Fetch the public Gateway Ed25519 identity key and attestation parameters."""
        return self._request("GET", "/api/v1/atp/gateway-identity")

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

    def authorize_external(
        self,
        *,
        target_org_id: str,
        target_agent_id: str,
        action: str,
        resource: str,
        amount: int | float | Decimal | None = None,
        currency: str | None = None,
        delegation_id: str | None = None,
        context: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        source_org_id: str | None = None,
    ) -> CrossOrgAuthorizationResult:
        return self._client.authorize_cross_org(
            source_agent_id=self._signer.agent_id,
            target_org_id=target_org_id,
            target_agent_id=target_agent_id,
            action=action,
            resource=resource,
            amount=amount,
            currency=currency,
            delegation_id=delegation_id,
            context=context,
            idempotency_key=idempotency_key,
            signer=self._signer,
            source_org_id=source_org_id,
        )

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

    def send_atp_message(
        self,
        *,
        source_org_id: str,
        target_address: str,
        capability: str,
        payload: Any,
        message_id: str | None = None,
        credentials: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Sign and dispatch an ATP/1.0 message to a target agent via AgentTrust Gateway."""
        if not target_address.startswith("atp://"):
            raise ValueError(f"Invalid target address: {target_address}. Expected atp://<org>/<agent>")
        parts = target_address[len("atp://"):].split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid target address: {target_address}. Expected atp://<org>/<agent>")
        target_org_id, target_agent_id = parts[0], parts[1]

        envelope = self._signer.sign_atp_envelope(
            source_org_id=source_org_id,
            target_org_id=target_org_id,
            target_agent_id=target_agent_id,
            capability=capability,
            payload=payload,
            message_id=message_id,
            credentials=credentials,
        )
        return self._client.dispatch_atp_envelope(envelope)


class CredentialsClient:
    def __init__(self, client: AgentTrust):
        self._client = client

    def issue(
        self,
        *,
        agent_id: str,
        credential_type: str = "AgentIdentityCredential",
        claims: dict[str, Any] | None = None,
        validity_days: int | None = None,
        environment: str = "production",
    ) -> dict[str, Any]:
        return self._client._request(
            "POST",
            "/v1/credentials",
            body={
                "agent_id": agent_id,
                "credential_type": credential_type,
                "claims": claims,
                "validity_days": validity_days,
                "environment": environment,
            },
        )

    def verify(self, credential: dict[str, Any], expected_environment: str = "production") -> dict[str, Any]:
        return self._client._request(
            "POST",
            "/v1/credentials/verify",
            body={
                "credential": credential,
                "expected_environment": expected_environment,
            },
        )

    def get_status(self, credential_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/credentials/{credential_id}/status")

    def revoke(self, credential_id: str, reason_code: str = "ISSUER_ACTION") -> dict[str, Any]:
        return self._client._request(
            "POST",
            f"/v1/credentials/{credential_id}/revoke",
            body={"reason_code": reason_code},
        )

    def list(
        self,
        status: str | None = None,
        credential_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        query_parts = [f"limit={limit}", f"offset={offset}"]
        if status:
            query_parts.append(f"status_filter={status}")
        if credential_type:
            query_parts.append(f"credential_type={credential_type}")
        return self._client._request("GET", f"/v1/credentials?{'&'.join(query_parts)}")


class IssuersClient:
    def __init__(self, client: AgentTrust):
        self._client = client

    def list(self) -> list[dict[str, Any]]:
        return self._client._request("GET", "/v1/trust-registry/issuers")

    def create(self, name: str) -> dict[str, Any]:
        return self._client._request("POST", "/v1/trust-registry/issuers", body={"name": name})

    def get(self, issuer_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/trust-registry/issuers/{issuer_id}")

    def rotate_key(self, issuer_id: str, revoke_old_key: bool = False) -> dict[str, Any]:
        return self._client._request(
            "POST",
            f"/v1/trust-registry/issuers/{issuer_id}/rotate-key",
            body={"revoke_old_key": revoke_old_key},
        )

    def suspend(self, issuer_id: str) -> dict[str, Any]:
        return self._client._request("POST", f"/v1/trust-registry/issuers/{issuer_id}/suspend")

    def revoke(self, issuer_id: str) -> dict[str, Any]:
        return self._client._request("POST", f"/v1/trust-registry/issuers/{issuer_id}/revoke")


class GatewaysClient:
    def __init__(self, client: AgentTrust):
        self._client = client

    def list(self, environment: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        query_parts = []
        if environment:
            query_parts.append(f"environment={environment}")
        if status:
            query_parts.append(f"status={status}")
        query_str = f"?{'&'.join(query_parts)}" if query_parts else ""
        return self._client._request("GET", f"/v1/gateways{query_str}")

    def register(
        self,
        name: str,
        deployment_type: str = "SELF_HOSTED_GATEWAY",
        environment: str = "PRODUCTION",
        offline_policy: str = "FAIL_CLOSED",
        labels: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._client._request(
            "POST",
            "/v1/gateways",
            body={
                "name": name,
                "deployment_type": deployment_type,
                "environment": environment,
                "offline_policy": offline_policy,
                "labels": labels or {},
            },
        )

    def get(self, gateway_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/gateways/{gateway_id}")

    def suspend(self, gateway_id: str) -> dict[str, Any]:
        return self._client._request("POST", f"/v1/gateways/{gateway_id}/suspend")

    def revoke(self, gateway_id: str) -> dict[str, Any]:
        return self._client._request("POST", f"/v1/gateways/{gateway_id}/revoke")

    def publish_config(
        self,
        environment: str = "production",
        policies: list[dict[str, Any]] | None = None,
        trusted_issuers: list[dict[str, Any]] | None = None,
        credential_requirements: list[dict[str, Any]] | None = None,
        revocations: list[dict[str, Any]] | None = None,
        routing: dict[str, Any] | None = None,
        validity_hours: int = 24,
    ) -> dict[str, Any]:
        return self._client._request(
            "POST",
            "/v1/gateways/config/publish",
            body={
                "environment": environment,
                "policies": policies,
                "trusted_issuers": trusted_issuers,
                "credential_requirements": credential_requirements,
                "revocations": revocations,
                "routing": routing,
                "validity_hours": validity_hours,
            },
        )

    def rollback_config(self, target_version: int) -> dict[str, Any]:
        return self._client._request(
            "POST",
            "/v1/gateways/config/rollback",
            body={"target_version": target_version},
        )

    def config_history(self, environment: str = "production") -> list[dict[str, Any]]:
        return self._client._request("GET", f"/v1/gateways/config/history?environment={environment}")


class SecurityClient:
    def __init__(self, client: AgentTrust):
        self._client = client

    def get_overview(self, window_hours: int = 24) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/security/overview?window_hours={window_hours}")

    def list_events(
        self,
        severity: str | None = None,
        category: str | None = None,
        event_type: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        params = [f"limit={limit}"]
        if severity:
            params.append(f"severity={severity}")
        if category:
            params.append(f"category={category}")
        if event_type:
            params.append(f"event_type={event_type}")
        if agent_id:
            params.append(f"agent_id={agent_id}")
        if correlation_id:
            params.append(f"correlation_id={correlation_id}")
        query = "&".join(params)
        return self._client._request("GET", f"/v1/security/events?{query}")

    def get_event(self, event_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/security/events/{event_id}")

    def get_related_events(self, event_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/security/events/{event_id}/related")

    def list_alerts(self, status: str | None = None, severity: str | None = None, limit: int = 50) -> dict[str, Any]:
        params = [f"limit={limit}"]
        if status:
            params.append(f"status={status}")
        if severity:
            params.append(f"severity={severity}")
        query = "&".join(params)
        return self._client._request("GET", f"/v1/security/alerts?{query}")

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/security/alerts/{alert_id}")

    def acknowledge_alert(self, alert_id: str) -> dict[str, Any]:
        return self._client._request("POST", f"/v1/security/alerts/{alert_id}/acknowledge")

    def resolve_alert(self, alert_id: str, note: str | None = None) -> dict[str, Any]:
        body = {"resolution_note": note} if note else {}
        return self._client._request("POST", f"/v1/security/alerts/{alert_id}/resolve", body=body)

    def list_rules(self) -> list[dict[str, Any]]:
        return self._client._request("GET", "/v1/security/rules")

    def list_exports(self) -> list[dict[str, Any]]:
        return self._client._request("GET", "/v1/security/exports")


class PoliciesClient:
    def __init__(self, client: AgentTrust):
        self._client = client

    def list(self) -> list[dict[str, Any]]:
        return self._client._request("GET", "/v1/policies")

    def get(self, policy_id: str) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/policies/{policy_id}")

    def create(
        self,
        name: str,
        description: str | None = None,
        category: str = "General",
        initial_yaml_source: str | None = None,
        target: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = {
            "name": name,
            "description": description,
            "category": category,
            "initial_yaml_source": initial_yaml_source,
            "target": target or {},
        }
        return self._client._request("POST", "/v1/policies", body=body)

    def validate(self, yaml_source: str) -> dict[str, Any]:
        return self._client._request("POST", "/v1/policies/validate", body={"yaml_source": yaml_source})

    def simulate(
        self,
        context: dict[str, Any],
        yaml_source: str | None = None,
        policy_id: str | None = None,
        version_number: int | None = None,
    ) -> dict[str, Any]:
        body = {
            "context": context,
            "yaml_source": yaml_source,
            "policy_id": policy_id,
            "version_number": version_number,
        }
        return self._client._request("POST", "/v1/policies/simulate", body=body)

    def list_versions(self, policy_id: str) -> list[dict[str, Any]]:
        return self._client._request("GET", f"/v1/policies/{policy_id}/versions")

    def create_version(self, policy_id: str, yaml_source: str, change_description: str | None = None) -> dict[str, Any]:
        return self._client._request(
            "POST",
            f"/v1/policies/{policy_id}/versions",
            body={"yaml_source": yaml_source, "change_description": change_description},
        )

    def publish_version(self, policy_id: str, version_number: int, sync_gateways: bool = True) -> dict[str, Any]:
        return self._client._request(
            "POST",
            f"/v1/policies/{policy_id}/publish",
            body={"version_number": version_number, "sync_gateways": sync_gateways},
        )

    def rollback_version(self, policy_id: str, target_version: int, reason: str, sync_gateways: bool = True) -> dict[str, Any]:
        return self._client._request(
            "POST",
            f"/v1/policies/{policy_id}/rollback",
            body={"target_version": target_version, "reason": reason, "sync_gateways": sync_gateways},
        )

    def diff(self, policy_id: str, v1: int, v2: int) -> dict[str, Any]:
        return self._client._request("GET", f"/v1/policies/{policy_id}/diff?v1={v1}&v2={v2}")

    def impact(
        self,
        policy_id: str,
        candidate_yaml_source: str,
        baseline_version: int | None = None,
        sample_requests: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        body = {
            "candidate_yaml_source": candidate_yaml_source,
            "baseline_version": baseline_version,
            "sample_requests": sample_requests,
        }
        return self._client._request("POST", f"/v1/policies/{policy_id}/impact", body=body)



