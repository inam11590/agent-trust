# Organization Teams and Security

Step 11 adds organization workspaces. A request selects one workspace with the
`X-Organization-ID` header. When the header is missing, AgentTrust uses the
user's personal workspace. The backend validates membership on every request;
changing a browser value cannot grant access.

## Roles

| Action | Owner | Admin | Developer | Viewer |
|---|---:|---:|---:|---:|
| View agents and permissions | Yes | Yes | Yes | Yes |
| Manage agents and permissions | Yes | Yes | No | No |
| View authorization audit logs | Yes | Yes | Yes | Yes |
| Decide manual authorization requests | Yes | Yes | No | No |
| Create or revoke API keys | Yes | Yes | Own keys | No |
| View developer request logs | Yes | Yes | Own keys | No |
| Manage webhooks | Yes | Yes | No | No |
| Invite members | Yes | Yes | No | No |
| Change or remove non-owner members | Yes | Yes | No | No |
| Change organization settings | Yes | No | No | No |

Normal invitations can create admin, developer, or viewer members. Owner
transfer is not implemented. The owner cannot be removed or demoted, so an
organization cannot lose its only owner.

## Invitation flow

Create an invitation:

```http
POST /organizations/<organization-id>/invitations
Authorization: Bearer <access-token>
Content-Type: application/json

{"email":"developer@example.com","role":"developer"}
```

Invitation tokens use cryptographic randomness. Only SHA-256 token hashes are
stored. Tokens expire after seven days by default and can be used once. The
signed-in account email must match the invited email when
`INVITATION_BIND_EMAIL=true`.

Local and test environments return a temporary invitation URL in the response.
Production responses never return it and AgentTrust never writes it to logs.
Real email delivery is not part of this step.

Accept an invitation:

```http
POST /invitations/accept
Authorization: Bearer <access-token>
Content-Type: application/json

{"token":"<invitation-token>"}
```

## Organization context

These resources use the selected organization context:

- agents
- permissions
- authorization audit logs
- manual authorization requests
- developer API keys and request logs
- webhooks

An organization API key is also bound to one organization. A key created by a
removed member, or by a member changed to viewer, stops working immediately.

## Authentication protection

Passwords continue to use Argon2id and are never logged or returned. Login
errors use the same message for an unknown email, wrong password, locked
account, and inactive account. Repeated failures temporarily lock a known
account. Login and registration also have configurable per-process rate limits.

JWT access tokens contain only the user identifier, timestamps, issuer,
audience, and token type. They expire after 15 minutes by default. There are no
refresh tokens in the current project.

The Next.js dashboard stores the JWT in an HTTP-only, SameSite cookie. Browser
mutation routes check the request origin before forwarding to FastAPI. This is
the CSRF protection for the cookie-backed dashboard. Mobile and SDK clients use
bearer tokens or API keys in headers, so browsers do not attach those
credentials automatically.

## Network security

FastAPI CORS accepts only exact origins from `CORS_ALLOWED_ORIGINS`. Production
must not use a wildcard origin with credentials. Both FastAPI and Next.js send
frame protection, content type protection, referrer policy, permissions policy,
and Content Security Policy headers. FastAPI also sends HSTS in production.

Webhook messages use HMAC-SHA256 over `<timestamp>.<raw-body>`. Receivers should
compare signatures in constant time and reject timestamps older than
`WEBHOOK_SIGNATURE_TOLERANCE_SECONDS`. Endpoint URLs are checked again before
delivery; production requires HTTPS and a public network destination.

## Current limits

- Invitation emails are not sent yet.
- Owner transfer is not implemented.
- Login, registration, and developer rate limits live in one API process. A
  shared Redis limiter is needed before running multiple instances.
- Failed webhook deliveries are stored with a next retry time, but a background
  retry worker is still needed.
- The Flutter app continues to use the personal workspace. Organization
  switching is available in the web dashboard and backend API.
- The static Next.js CSP permits inline scripts required by the current Next.js
  rendering setup. A nonce-based CSP can tighten this later.
