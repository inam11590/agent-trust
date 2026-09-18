# AgentTrust deployment guide

## Architecture

Internet traffic terminates TLS at a trusted load balancer or reverse proxy. It
routes browser traffic to the Next.js container and API traffic to FastAPI.
FastAPI and the notification worker use managed PostgreSQL. Redis contains only
temporary distributed rate-limit counters. The worker claims durable notification
jobs from PostgreSQL with `FOR UPDATE SKIP LOCKED`. Permissions, audit logs, risk
assessments, authorization history, billing state, and usage stay in PostgreSQL.

Flutter and all SDKs connect to the public HTTPS FastAPI URL. Developer and
billing webhooks are signed. Billing remains local-test or Paddle Sandbox only.

## Environments

Development, test, staging, and production use separate databases, Redis
instances, secrets, domains, and provider projects. Copy the matching example
file to an untracked secret store or platform environment. Never copy production
data or secrets into staging.

Staging uses `compose.yaml` plus `compose.staging.yaml`. Copy
`backend/.env.staging.example` to the ignored `backend/.env.staging`, then fill
the blank secrets with staging-only values. Its `POSTGRES_USER`,
`POSTGRES_PASSWORD`, and `STAGING_WEB_APP_URL` values are also read by Compose.
The staging example runs a separate local PostgreSQL and Redis stack; for a
shared staging environment, use separately provisioned managed services instead.
Its localhost port is for infrastructure checks. For browser sign-in, put an HTTPS
reverse proxy in front, set `STAGING_HTTPS=true` for the web build, and use the
staging HTTPS domain. Never send login credentials to the localhost HTTP port.

```sh
docker compose --env-file backend/.env.staging -f compose.yaml -f compose.staging.yaml config
docker compose --env-file backend/.env.staging -f compose.yaml -f compose.staging.yaml up -d --build
```

Production should use a container service, managed PostgreSQL, managed Redis,
encrypted object storage for backups, and an HTTPS load balancer. Do not expose
PostgreSQL, Redis, `/metrics`, or container management ports to the internet.
Restrict worker outbound traffic at the network layer to approved webhook,
email, push, and billing destinations. URL checks alone cannot stop every DNS
rebinding or routing change. Apply edge rate limits to public authentication,
authorization, and signed webhook endpoints as another protection layer.

## Safe deployment

1. Build immutable API, worker, and web images from one commit.
2. Run CI and vulnerability/secret scans.
3. Test the migration on a current backup in staging.
4. Run `alembic upgrade head` as a one-off job.
5. Deploy API and worker containers without development reload.
6. Wait for `/health/ready`, then send traffic.
7. Monitor errors, latency, authorization decisions, jobs, and webhooks.

Use at least two API replicas after Redis rate limiting is enabled. Run one API
worker per container so the process-local metrics endpoint represents that
container; scrape every replica and aggregate in Prometheus. Start with a
PostgreSQL pool of 10 plus 10 overflow connections per API container and reduce it
if the database connection budget is smaller. `pool_pre_ping` checks borrowed
connections and `pool_recycle` replaces old connections.

Only configure `FORWARDED_ALLOW_IPS` with the private address range of the trusted
load balancer. The load balancer must replace incoming forwarded headers. HTTPS
deployments set `AGENTTRUST_HTTPS=true` as a web Docker build argument; local HTTP keeps it
false. The Next.js server requires `AGENTTRUST_API_URL` in production mode, which
may be a private HTTP container URL behind the TLS-terminating proxy. The session
cookie remains HttpOnly, Secure, SameSite=Lax, and host-scoped.
The load balancer must reject public plain-HTTP authentication traffic or redirect
it to HTTPS before it reaches AgentTrust. HTTPS
monitors should check `/health/live` every minute and `/health/ready` every minute,
alerting after two consecutive failures.

`/metrics` requires `X-Metrics-Token` in staging and production and should also be
blocked by the private network. Sentry is disabled when `SENTRY_DSN` is empty.
When enabled, PII collection stays disabled; do not add request bodies, auth
headers, tokens, or secrets as Sentry context.

## Failure policy

- PostgreSQL failure: readiness and database operations return 503; no decision is fabricated.
- Redis failure: distributed rate limiting fails closed; readiness returns 503.
- Risk evaluation exception: the authorization request fails; it is never silently approved.
- Notification provider failure: the durable job is retried by the worker and authorization remains complete.
- Developer webhook timeout: the delivery is marked failed for retry; the saved decision remains authoritative.

## External setup

Create separate staging and production PostgreSQL and Redis services, DNS names,
TLS certificates, secret-store entries, Sentry project, email/FCM projects, and
uptime checks. Keep Paddle in Sandbox. Configure sandbox products, prices, and a
signed webhook endpoint. Live billing is outside Step 15.
