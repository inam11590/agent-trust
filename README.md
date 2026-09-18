# AgentTrust

AgentTrust is a trust and permission system for AI agents. It will check agent
ownership, allowed actions, spending limits, and permission expiry before an
action is approved. It does not process real payments.

## Current scope: Step 15

AgentTrust now includes the backend trust flow, audit history, manual approvals,
a responsive Next.js dashboard, a Flutter mobile app, and the first developer
platform. Organization owners can invite admins, developers, and viewers with
backend-enforced roles and isolated workspace data. Server applications can use
scoped API keys, the versioned API, and small Python, Node.js, or Java SDKs. No
payment or external action is performed. Important authorization and security
events now create private in-app notifications and queued email/push deliveries.
Permission-valid requests now receive a transparent rule-based risk score.
High-risk requests can require manual approval and critical requests can be
rejected by workspace policy. No machine-learning prediction is used.
Organizations now receive a Free subscription plan, monthly authorization usage
metering, and server-enforced limits for agents, API keys, team seats, and
webhooks. The billing dashboard uses a local test provider by default and can be
connected only to Paddle sandbox in this step. No live charge or card storage is
enabled. See [docs/billing.md](docs/billing.md).

Step 15 adds deployment containers, staging configuration, CI checks, liveness
and readiness endpoints, safe JSON request logs, correlation IDs, protected
metrics, Redis-backed distributed rate limits, backup/restore procedures, and
an incident/rollback playbook. External production services and credentials
must still be configured before going live. See [deployment guide](docs/DEPLOYMENT.md)
and [production checklist](docs/PRODUCTION_CHECKLIST.md).

The planned stack is FastAPI, PostgreSQL, SQLAlchemy, Alembic, Pydantic, and JWT
for the backend, Next.js with TypeScript for web, and Flutter for Android/iOS.
Dependencies for future features will be added when those features are built.

## Repository structure

```text
Agent-Trust/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── agents.py
│   │   │   ├── audit_logs.py
│   │   │   ├── auth.py
│   │   │   ├── authorization.py
│   │   │   ├── authorization_requests.py
│   │   │   ├── developer.py
│   │   │   ├── dependencies.py
│   │   │   ├── errors.py
│   │   │   ├── health.py
│   │   │   ├── notifications.py
│   │   │   ├── organizations.py
│   │   │   ├── permissions.py
│   │   │   └── risk.py
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py
│   │   │   └── security.py
│   │   ├── database/              # Base metadata, engine and sessions
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   └── session.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── user.py
│   │   │   ├── organization.py
│   │   │   ├── agent.py
│   │   │   ├── audit_log.py
│   │   │   ├── authorization_request.py
│   │   │   ├── developer.py
│   │   │   ├── notification.py
│   │   │   └── permission.py
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── agent.py
│   │   │   ├── audit_log.py
│   │   │   ├── auth.py
│   │   │   ├── authorization.py
│   │   │   ├── authorization_request.py
│   │   │   ├── developer.py
│   │   │   ├── organization.py
│   │   │   ├── notification.py
│   │   │   ├── permission.py
│   │   │   ├── risk.py
│   │   │   └── user.py
│   │   └── services/
│   │       ├── __init__.py
│   │       ├── agents.py
│   │       ├── audit_logs.py
│   │       ├── auth.py
│   │       ├── authorization.py
│   │       ├── authorization_requests.py
│   │       ├── api_keys.py
│   │       ├── developer.py
│   │       ├── organization_context.py
│   │       ├── organizations.py
│   │       ├── notification_delivery.py
│   │       ├── notification_providers.py
│   │       ├── notification_service.py
│   │       ├── rate_limit.py
│   │       ├── risk_assessments.py
│   │       ├── risk_engine.py
│   │       ├── security_events.py
│   │       ├── webhooks.py
│   │       └── permissions.py
│   │   ├── workers/notifications.py
│   ├── tests/
│   │   ├── test_agents.py
│   │   ├── test_auth.py
│   │   ├── test_audit_logs.py
│   │   ├── test_audit_log_schema.py
│   │   ├── test_authorization.py
│   │   ├── test_authorization_schema.py
│   │   ├── test_authorization_requests.py
│   │   ├── test_config.py
│   │   ├── test_database.py
│   │   ├── test_database_health.py
│   │   ├── test_developer_platform.py
│   │   ├── test_health.py
│   │   ├── test_organization_security.py
│   │   ├── test_notifications.py
│   │   ├── test_permission_schema.py
│   │   ├── test_permissions.py
│   │   ├── test_risk_engine.py
│   │   └── test_security.py
│   ├── alembic/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   │       ├── 0001_initial_models.py
│   │       ├── 0002_case_insensitive_email.py
│   │       ├── 0003_permissions.py
│   │       ├── 0004_audit_logs.py
│   │       ├── 0005_agent_description.py
│   │       ├── 0006_revoked_agent_status.py
│   │       ├── 0007_manual_authorization_requests.py
│   │       ├── 0008_developer_platform.py
│   │       ├── 0009_organization_teams_security.py
│   │       ├── 0010_audit_organization_scope.py
│   │       ├── 0011_notifications.py
│   │       ├── 0012_risk_engine.py
│   │       ├── 0013_billing.py
│   │       └── 0014_production_indexes.py
│   ├── alembic.ini
│   ├── compose.yaml
│   ├── Dockerfile
│   ├── .env.example
│   ├── requirements.txt
│   └── requirements-dev.txt
├── web/                         # Next.js dashboard and production Dockerfile
├── mobile/                      # Notification list, badge, settings, deep links
├── sdk/
│   ├── python/
│   ├── node/
│   └── java/
├── docs/
│   ├── developer-api.md
│   ├── notifications.md
│   ├── organization-security.md
│   ├── DEPLOYMENT.md
│   ├── BACKUPS.md
│   ├── PRODUCTION_CHECKLIST.md
│   ├── INCIDENT_RESPONSE.md
│   └── ROLLBACK.md
├── scripts/                     # Backup, restore, and safe smoke benchmark
├── compose.yaml                 # Local full stack
├── compose.staging.yaml         # Isolated staging overlay
├── .github/workflows/ci.yml
├── .gitignore
└── README.md
```

## Run locally

Requires Python 3.12 or newer and PostgreSQL (local setup uses PostgreSQL 17
through Docker Desktop). Run commands from the repository root. If the virtual
environment already exists, reuse it.

### Windows PowerShell

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
if (!(Test-Path .env)) { Copy-Item .env.example .env }
# Set POSTGRES_USER, POSTGRES_PASSWORD, and a random JWT_SECRET_KEY (32+ bytes)
# in your private .env first.
docker compose up -d --wait db
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Virtual environment activation is optional; these commands do not require a
PowerShell execution-policy change. Copy `.env.example` only on first setup;
preserve an existing `.env`.

### macOS / Linux

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cp -n .env.example .env
# Set POSTGRES_USER, POSTGRES_PASSWORD, and a random JWT_SECRET_KEY (32+ bytes)
# in your private .env first.
docker compose up -d --wait db
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/health. Expected HTTP 200 response:

```json
{"status": "ok", "service": "AgentTrust API"}
```

Interactive API docs: http://127.0.0.1:8000/docs. Stop the server with Ctrl+C.
The original health endpoint still checks only that the API responds.
`GET /health/database` executes `SELECT 1` against PostgreSQL and returns:

```json
{"status": "ok", "database": "PostgreSQL"}
```

If credentials are missing or PostgreSQL is unavailable, the database endpoint
returns HTTP 503 with `{"detail": "Database unavailable"}`. It never exposes
driver errors or credentials. This checks connectivity, not migration status.

## Authentication API

All authentication requests use JSON. Registration requires a valid email, a
name, and a password between 15 and 128 characters. The API normalizes email
addresses to lowercase and enforces case-insensitive uniqueness in PostgreSQL.

Register a user:

```http
POST /auth/register
Content-Type: application/json

{
  "email": "owner@example.com",
  "password": "use-a-long-private-password",
  "full_name": "Example Owner"
}
```

A successful registration returns HTTP 201 with public user fields. It never
returns the password hash. A duplicate email returns HTTP 409:

```json
{"detail": "Email is already registered"}
```

Log in:

```http
POST /auth/login
Content-Type: application/json

{
  "email": "owner@example.com",
  "password": "use-a-long-private-password"
}
```

The response contains a 15-minute bearer token:

```json
{
  "access_token": "<signed-jwt>",
  "token_type": "bearer",
  "expires_in": 900
}
```

Use the token to read the current user:

```http
GET /users/me
Authorization: Bearer <signed-jwt>
```

Missing, expired, malformed, or invalid tokens return HTTP 401. Disabled or
deleted users cannot use an existing token. Login deliberately returns the same
error for an unknown email, a wrong password, and an inactive account. This
avoids revealing which email addresses have accounts.

## Developer platform

Logged-in users can create and revoke API keys from the **Developers** page.
The complete secret is shown once. Server applications call
`POST /api/v1/authorize` with `X-API-Key`, then poll
`GET /api/v1/authorization-requests/{request_id}` when a decision is pending.
See [the developer API guide](docs/developer-api.md) for API, idempotency, SDK,
rate-limit, and signed-webhook examples.

## Agent API

All agent routes require the bearer token returned by `/auth/login`.

Create an agent:

```http
POST /agents
Authorization: Bearer <signed-jwt>
Content-Type: application/json

{
  "name": "Travel Assistant"
}
```

Example HTTP 201 response:

```json
{
  "id": "e80752b1-3432-4851-914b-b27fe36b0ead",
  "name": "Travel Assistant",
  "agent_identifier": "agt_8f2e1a4c9b7d6e3f10293847",
  "owner_id": "65f78183-7201-4f1d-b4bc-23e083a63ec5",
  "organization_id": null,
  "status": "inactive",
  "created_at": "2026-09-12T10:00:00Z",
  "updated_at": "2026-09-12T10:00:00Z"
}
```

The server generates the public ID as `agt_` followed by 24 random hexadecimal
characters. Clients cannot choose the ID, owner, or status. A newly registered
agent starts as `inactive`, following the database model created in Step 2.

List the current user's agents:

```http
GET /agents
Authorization: Bearer <signed-jwt>
```

Read one agent by its public ID:

```http
GET /agents/agt_8f2e1a4c9b7d6e3f10293847
Authorization: Bearer <signed-jwt>
```

Users receive only agents they own. Reading another user's agent returns the
same HTTP 404 response as an unknown ID. `organization_id` is optional, but when
provided it must refer to an organization owned by the logged-in user. Owners
can update an agent's name, description, and lifecycle status with
`PATCH /agents/<public-agent-id>`. Revocation cannot be reversed through the API.

## Permission API

All permission routes require a valid bearer token. Grant a permission to an
agent owned by the current user:

```http
POST /permissions
Authorization: Bearer <signed-jwt>
Content-Type: application/json

{
  "agent_id": "e80752b1-3432-4851-914b-b27fe36b0ead",
  "action": "purchase",
  "resource": "flight",
  "maximum_amount": "500.00",
  "currency": "USD",
  "valid_from": "2026-09-12T10:00:00Z",
  "expires_at": "2026-09-13T10:00:00Z"
}
```

The API returns HTTP 201 with a UUID permission ID, the owner and agent IDs,
the scope, time window, status, and timestamps. Monetary values are returned as
JSON strings to preserve exact decimal values.

List or read the current user's permissions:

```http
GET /permissions
Authorization: Bearer <signed-jwt>

GET /permissions/<permission-uuid>
Authorization: Bearer <signed-jwt>
```

Revoke a permission:

```http
POST /permissions/<permission-uuid>/revoke
Authorization: Bearer <signed-jwt>
```

Revocation is idempotent and takes effect as soon as it is saved. Active
permissions become `expired` when their expiry time is reached and they are
read. Security checks also compare the current time directly, so an expired
permission is unusable even before that status label is persisted.

`maximum_amount` must be positive and supports up to four decimal places. Amount
and currency must either both be present or both be absent. Currency is stored
as an uppercase three-letter code. The API validates the format but does not
maintain a currency catalog. `expires_at` must be timezone-aware, in the future,
and later than `valid_from`. Actions and resources use lowercase identifiers
such as `purchase` and `flight`.

Users can grant permissions only to agents they own. Reading or revoking another
user's permission returns the same HTTP 404 response as a missing permission.
This step stores and manages grants; it does not call airlines, charge cards,
connect payments, or execute agent actions.

## Authorization engine

`POST /authorize` requires the owner's bearer token. Agent-specific credentials
do not exist yet, so the engine accepts decisions only in the authenticated
owner's scope.

```http
POST /authorize
Authorization: Bearer <signed-jwt>
Content-Type: application/json

{
  "agent_id": "agt_8f2e1a4c9b7d6e3f10293847",
  "action": "purchase",
  "resource": "flight",
  "amount": "420.00",
  "currency": "USD"
}
```

When one complete permission matches:

```json
{
  "request_id": "req_7f831a4c9b7d6e3f10293847",
  "decision": "APPROVED",
  "reason": "Permission valid"
}
```

When a check fails, the request itself is still valid and the endpoint returns
HTTP 200 with a rejection decision:

```json
{
  "request_id": "req_9c201a4c9b7d6e3f10293847",
  "decision": "REJECTED",
  "reason": "Amount exceeds allowed limit"
}
```

The engine checks that the public agent ID belongs to the logged-in owner and
that the agent is active. It then finds permissions belonging to the same owner
and agent. Action and resource must match exactly after lowercase normalization.
The permission must have started, must not be expired, and must not be revoked.

For monetary requests, amount and currency are required together. The currency
must match and the amount must be less than or equal to the permission's limit.
A limited permission cannot be used by omitting the request amount. A permission
without an amount limit can authorize only a request that also has no amount.
Every single permission is evaluated as a whole, so the engine never combines a
currency from one grant with an amount limit from another grant.

Possible rejection reasons include `Agent not found`, `Agent is not active`,
`No permission found`, `Action not permitted`, `Resource not permitted`,
`Permission has not started`, `Permission expired`, `Permission revoked`,
`Amount is required for this permission`, `Permission does not allow an amount`,
`Currency does not match`, and `Amount exceeds allowed limit`.

Each HTTP 200 authorization result includes a new opaque request ID. The service
saves the result before returning it, including rejected results. Invalid JSON,
failed input validation, and failed login do not reach the authorization engine,
so they are not authorization audit events.

## Audit log API

All audit routes require the owner's bearer token. They are read-only:

```http
GET /audit-logs?page=1&page_size=20
Authorization: Bearer <signed-jwt>

GET /audit-logs/<audit-log-uuid>
Authorization: Bearer <signed-jwt>

GET /agents/agt_8f2e1a4c9b7d6e3f10293847/audit-logs
Authorization: Bearer <signed-jwt>
```

The list endpoints return `items`, `page`, `page_size`, `total`, and
`total_pages`. Page size defaults to 20 and cannot exceed 100. Optional query
filters are `decision`, `agent_id`, `action`, `resource`, `start_date`, and
`end_date`. Dates must include a timezone.

```http
GET /audit-logs?decision=REJECTED&action=purchase&resource=flight
Authorization: Bearer <signed-jwt>
```

An audit item contains the request ID, owner ID, optional internal agent and
permission IDs, public agent identifier, action, resource, optional amount and
currency, decision, reason, and timestamps. The public agent identifier is kept
as a historical snapshot, so a rejected request for an unknown agent can still
be recorded safely. Passwords, password hashes, JWTs, and secret keys are never
stored in an audit row.

Queries always include the logged-in user's ID. Another user therefore receives
an empty list or HTTP 404 instead of seeing someone else's history. There are no
POST, PATCH, PUT, or DELETE audit endpoints for normal users.

## Configuration

Settings load from `backend/.env`; environment variables take precedence.
`APP_ENV` accepts `development`, `local`, `test`, `staging`, or `production`. Set `JWT_SECRET_KEY` to a
unique random value containing at least 32 bytes. The API refuses authentication
requests when the key is missing and refuses to start with a short configured
key. `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` defaults to 15 and accepts 1 through 60.
`JWT_ISSUER` and `JWT_AUDIENCE` identify tokens issued for this API.

Set `POSTGRES_HOST`,
`POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` for your
database. `POSTGRES_CONNECT_TIMEOUT` defaults to 5 seconds. `POSTGRES_SSLMODE`
defaults to `prefer` for local development; use `verify-full` with a trusted
certificate for remote production connections. Credentials remain blank in
`.env.example`. Keep real values only in your private, Git-ignored `.env` or
deployment secrets. Do not print database URLs with passwords.

Docker Compose binds PostgreSQL only to `127.0.0.1` and stores its data in a named
volume. It is for local development; its bootstrap role has administrator rights.
For an existing PostgreSQL installation, create the database and a dedicated
role yourself, fill in `.env`, skip Docker, and run the same Alembic command.
Changing `.env` does not change credentials in an already initialized database.
Use `docker compose stop db` to stop the local database while preserving data.

The API does not create tables automatically. Run `alembic upgrade head` before
using the database. `alembic current` shows the installed revision and
`alembic check` checks for differences between models and the migrated schema.

## Database tables

| Table | Purpose |
| --- | --- |
| `users` | UUID, unique email, password hash, full name, active flag, timestamps |
| `organizations` | UUID, name, required owner linked to `users`, timestamps |
| `agents` | UUID, name, description, unique identifier, required owner, optional organization, status, timestamps |
| `permissions` | Owner, agent, action, resource, optional amount/currency limit, validity window, status, timestamps |
| `audit_logs` | Append-only authorization request snapshots, decision, reason, and owner-scoped links |
| `alembic_version` | Tracks the applied migration; managed by Alembic |

Foreign keys prevent links to nonexistent records. Deleting an owner with
organizations or agents is blocked. Deleting an organization keeps its agents
and clears their organization link. Agent status is `active`, `inactive`,
`suspended`, or `revoked`; new agents default to `inactive`. The authorization
endpoint requires an active agent. Owners manage lifecycle state from the agent
details page, and revoked agents cannot be reactivated.

UUIDs are generated by SQLAlchemy. PostgreSQL initializes timezone-aware
timestamps; SQLAlchemy updates `updated_at` when issuing updates. Direct SQL
writers must explicitly update that timestamp. Email uniqueness is enforced
case-insensitively by migration `0002`.

Passwords are converted to salted Argon2id hashes before database storage. JWTs
are signed with HS256 and require subject, issue time, expiry, issuer, audience,
and token-type claims. New access tokens have a database-backed session and can
be revoked immediately. Disabling a user also blocks protected routes. There
are no refresh tokens, social login, or password-reset flow yet.

Configuration follows the [FastAPI settings documentation](https://fastapi.tiangolo.com/advanced/settings/).

## Basic checks

From `backend/`, on Windows:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
.\.venv\Scripts\python.exe -m pip check
# Run against a migrated LOCAL development database; test rows are rolled back.
$env:RUN_DATABASE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
Remove-Item Env:RUN_DATABASE_TESTS
```

On macOS/Linux use `.venv/bin/python` in place of the Windows Python path.
On macOS/Linux enable database tests with `RUN_DATABASE_TESTS=1 .venv/bin/python
-m pytest tests -q -p no:cacheprovider` (on one line). Database tests are skipped
unless explicitly enabled. Tests cover health responses, safe failure messages,
configuration, relationships, uniqueness, foreign keys, statuses, timestamps,
registration, password hashing, login, JWT validation, protected routes, and
inactive or deleted accounts. Agent tests cover generated identifiers, creation,
listing, detail lookup, owner isolation, organization ownership, invalid input,
identifier collision retries, and inactive users. Permission tests cover exact
money values, date windows, ownership, listing, detail lookup, revocation,
expiry, future activation, database constraints, and nullable money limits.
Authorization tests cover every approval and rejection branch, exact-limit
approval, ownership isolation, non-monetary grants, and multiple permissions.
Audit tests cover approved and rejected persistence, exact reasons, unique
request IDs, ownership isolation, filters, agent history, pagination, unknown
agents, authentication, and the absence of edit/delete routes.
Pytest caching is disabled here to avoid the local sandbox cache-write issue.

Migration setup follows the [Alembic documentation](https://alembic.sqlalchemy.org/en/latest/tutorial.html).
The authentication design follows the [FastAPI JWT security guide](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/).
## Web dashboard

The dashboard uses Next.js App Router, TypeScript, Tailwind CSS, and reusable UI
components. Copy `web/.env.example` to `web/.env.local`. `AGENTTRUST_API_URL` is
the preferred server-side backend URL. `NEXT_PUBLIC_API_URL` is a local fallback
and must never contain credentials.

Next.js exchanges login credentials with FastAPI and stores the returned JWT in
an HTTP-only, same-site cookie. Browser JavaScript cannot read the token. All
dashboard calls go through `/api/backend`, where Next.js adds the bearer token.
FastAPI still performs every ownership check.

Run the dashboard from `web/`:

```powershell
if (!(Test-Path .env.local)) { Copy-Item .env.example .env.local }
npm install
npm run dev
```

Open http://127.0.0.1:3000. Validate it with `npm run lint`, `npm run
typecheck`, `npm test`, and `npm run build`.

Step 16 still performs no real external actions or live payments. Billing stays
in test or Paddle Sandbox mode, and risk scoring uses transparent rules rather
than a trained machine-learning model. See
[`docs/risk-engine.md`](docs/risk-engine.md) for scoring and policy details.

## Step 16 account security

Set a unique `MFA_ENCRYPTION_KEY` in the ignored `backend/.env` before using MFA
or SSO. Generate one locally with:

```powershell
cd backend
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the printed key into `backend/.env` or a managed secret store; do not put it
in source code or logs. Keep the key backed up securely because existing
encrypted MFA and SSO secrets require it. Run migrations with
`.\.venv\Scripts\alembic.exe upgrade head`. The web dashboard's **Security**
page handles authenticator setup, one-time recovery codes, sessions, and event
history. Organization owners can configure MFA, SSO, and a purchase-approval
threshold from **Security → Organization security**.
The purchase threshold has an explicit currency. Purchases in another currency
require human approval until an owner sets a matching rule; the service does
not perform exchange-rate conversion.

OIDC SSO needs an external provider registration. Set `API_PUBLIC_URL` to the
browser-reachable HTTPS API origin in staging/production, and register
`{API_PUBLIC_URL}/auth/sso/callback` as the provider redirect URI. Enter the
provider issuer, discovery URL, client ID, and client secret in the owner page;
test the connection before enabling it. Only existing active organization
members with a verified provider email can sign in. The current automated SSO
test uses a mock provider; real enterprise providers still need manual setup and
interoperability testing. The owner retains a recovery sign-in path if SSO is
required. See [compliance foundation](docs/compliance/SECURITY_CONTROLS.md) for
implemented controls and remaining operational work.

## Step 17 agent signing

Agents can now register Ed25519 **public** signing keys in **Agents → Agent
details → Signing keys**. Developer API authorization for an agent with any
registered signing key requires its matching private-key signature, a fresh
timestamp, and an unused nonce. Existing API keys remain required. Unsigned
requests for agents without a signing key remain available during migration.
The private key stays with the developer and is never stored by AgentTrust.
See [agent signing](docs/AGENT_SIGNING.md) for the exact v1 format, SDK examples,
rotation, emergency revocation, replay behavior, and test commands. Run
`alembic upgrade head` to apply the signing-key and replay tables.
