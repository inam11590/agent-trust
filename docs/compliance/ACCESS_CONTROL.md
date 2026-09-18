# Access control (engineering draft)

The API authenticates user JWTs and checks the backing session on each request. Organization work is selected by organization ID and checked against active membership. Owner-only capabilities cover security policy and SSO configuration. Developers and viewers cannot change these controls. Organization MFA and SSO requirements are enforced for organization requests; the owner retains a password-plus-MFA recovery path when SSO is required.

Recent password and, when enabled, MFA verification is required for security policy and SSO changes, API key creation, and subscription cancellation. A new authenticated session starts with a five-minute step-up window. Review this window and all sensitive routes before production release.

The OIDC login path never creates an account from a domain match. It requires a verified email in a signed provider ID token and an existing active organization membership. An allowed domain is an additional filter, not proof of identity. SSO owners must configure a tested connection before enabling SSO enforcement.

Access reviews should compare active organization memberships, roles, API keys, SSO connections, and sessions at a defined cadence. Revocations should be recorded and verified in the API, not just the user interface.
