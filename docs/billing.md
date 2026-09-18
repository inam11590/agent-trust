# Billing, plans, and usage

Step 14 adds organization plans and quota enforcement. It does not charge real
money. `BILLING_PROVIDER=test` is the default and returns local test links.
`paddle_sandbox` is the only external provider mode implemented; the client
rejects any API base URL except `https://sandbox-api.paddle.com`.

Every organization receives the Free plan. Limits are checked on the server
before creating agents, API keys, invitations, or webhooks. Developer API
authorization requests use a PostgreSQL row lock and a unique monthly usage row,
so concurrent requests cannot pass a quota by racing. Reusing the same API
idempotency key returns the stored result and does not increment usage again.

## Endpoints

- `GET /billing/plans`
- `GET /billing/subscription` with `X-Organization-ID`
- `GET /billing/usage` with `X-Organization-ID`
- `POST /billing/checkout` with `{ "plan_code": "starter" }`
- `POST /billing/portal`
- `POST /billing/cancel` (organization owner only)
- `POST /billing/webhook` (provider only; signed raw body)

The browser submits a plan code. The backend maps it to a configured sandbox
price ID, preventing a browser from choosing an amount. A checkout redirect is
not proof of payment. The subscription changes only after a valid signed webhook.

## Local test configuration

Set a private `BILLING_WEBHOOK_SECRET` in `backend/.env`. Generate a test
signature as HMAC-SHA256 over `timestamp:raw_request_body`, and send
`Paddle-Signature: ts=<timestamp>;h1=<digest>`. Timestamps outside the configured
tolerance and modified bodies are rejected. Provider event IDs are stored with a
unique constraint, so retries are safe.

For Paddle sandbox, also set `BILLING_PROVIDER=paddle_sandbox`, a sandbox API
key, and the Starter and Business sandbox price IDs. Configure the Paddle
sandbox webhook destination as `POST /billing/webhook`. Do not put these values
in source control.

Payment failures enter a seven-day grace period by default. Existing agents,
logs, permissions, and security history are never deleted by downgrade or
cancellation. At the end of a confirmed cancellation, the provider webhook
moves the organization to Free and future resource creation follows Free limits.
