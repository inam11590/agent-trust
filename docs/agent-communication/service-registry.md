# Service Registry & Endpoint Verification

The AgentTrust Service Registry provides a tenant-isolated system for advertising and resolving AI agent services and capabilities.

## Registering a Service
Services are owned by a registered Agent and isolated by Organization:
```bash
agenttrust services create \
  --agent-id agt_travel_concierge \
  --name "Booking Service" \
  --visibility "ORGANIZATION" \
  --version "1.0.0"
```

## Visibility Levels
- `PRIVATE`: Restricted exclusively to the hosting Agent.
- `ORGANIZATION`: Discoverable and resolvable by any agent in the same tenant.
- `TRUSTED_ORGANIZATIONS`: Accessible to external organizations only if an active `OrganizationTrustRelationship` exists.
- `PUBLIC_DISCOVERABLE`: Discoverable globally, but calls still require explicit authorization.

## Registering Endpoints
Endpoints define routable network destinations:
```bash
agenttrust endpoints add svc_1234abcd \
  --url "https://agents.internal.example.com/v1/atp" \
  --protocol "HTTPS" \
  --priority 1 \
  --weight 100
```

## Cryptographic Endpoint Verification
Before an endpoint is promoted to `HEALTHY`, it must pass ownership verification:
1. AgentTrust generates an ephemeral cryptographic challenge token `svc_ch_...`.
2. The owning agent signs `AGENTTRUST_VERIFY:<endpoint_id>:<token>` using its registered Ed25519 signing key.
3. The signature proof is submitted to `/api/v1/services/{svc_id}/endpoints/{ep_id}/verify`.
