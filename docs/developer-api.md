# AgentTrust Developer API

The developer API lets a server ask AgentTrust for an authorization decision.
Keep API keys on the server. Never put them in browser or mobile application
code.

Organization dashboard requests send `X-Organization-ID`. Keys created in that
workspace are permanently scoped to that organization; the SDK does not need to
send the organization header because the API key already contains the scope.

## Create a key

Sign in to the web dashboard, open **Developers**, and create a key. AgentTrust
shows the complete `at_live_...` value once. Copy it immediately. The database
keeps a SHA-256 hash and a short display prefix, not the complete key.

For a direct API call, use a dashboard JWT:

```http
POST /developer/api-keys
Authorization: Bearer <dashboard-jwt>
Content-Type: application/json

{"name":"Production Backend","organization_id":null}
```

## Authorize an action

```bash
curl -X POST http://127.0.0.1:8000/api/v1/authorize \
  -H "X-API-Key: $AGENTTRUST_API_KEY" \
  -H "Idempotency-Key: checkout-123" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agt_xxxxx","action":"purchase","resource":"flight","amount":420,"currency":"USD"}'
```

```json
{"request_id":"req_xxxxx","status":"APPROVED","reason":"Permission valid"}
```

`status` can be `APPROVED`, `REJECTED`, or `PENDING`. A pending request requires
the user to approve or reject it in AgentTrust. Read its latest status with:

```http
GET /api/v1/authorization-requests/req_xxxxx
X-API-Key: at_live_xxxxx
```

Only the API key that created a request can read its status. Reusing an
`Idempotency-Key` with the same request returns the first result. Reusing it
with different data returns HTTP 409. The default limit is 100 requests per
minute for each key and can be changed with
`DEVELOPER_RATE_LIMIT_PER_MINUTE`.

## SDKs

- Python: `sdk/python`
- Node.js with TypeScript: `sdk/node`
- Java 17+: `sdk/java`

Each client supports authorization and status lookup. Set
`AGENTTRUST_API_KEY` in the server process instead of writing a key in source
code.

## Webhooks

An organization owner can configure one endpoint with `POST /developer/webhook`.
The signing secret is returned when configured and only its hash is stored.
AgentTrust sends `authorization.approved` and `authorization.rejected` events
after a user decides a pending request. The `AgentTrust-Signature` header has
this form:

```text
t=<unix-time>,v1=<hex-hmac-sha256>
```

Verify HMAC-SHA256 over `<unix-time>.<raw-request-body>` with the signing
secret, and reject old timestamps. Production webhook URLs must use HTTPS and
must resolve to public network addresses. Failed attempts are recorded with a
future retry time; a background retry worker is planned for a later step.

The current rate limiter runs inside one API process. Use a shared store such
as Redis before running multiple API instances.
