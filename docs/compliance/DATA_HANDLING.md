# Data handling and lifecycle (engineering draft)

| Class | Examples | Handling |
| --- | --- | --- |
| PUBLIC | Published marketing text | Approved for public release |
| INTERNAL | Non-sensitive operational notes | Staff access only |
| CONFIDENTIAL | Authorization audit logs, security events, organization records | Tenant-scoped access, encryption in transit, restricted export |
| SECRET | Password hashes, API key hashes, MFA secrets, SSO client secrets, billing provider secrets, encryption keys | Never display after creation; restricted service access; no logs or routine exports |

Passwords and API keys use one-way hashes. TOTP and OIDC client secrets must be reversible for server verification and are encrypted using an application key supplied by the environment or a production secret manager. JWTs and recovery codes are never stored in readable form. Browser tokens are held in HttpOnly cookies; mobile tokens use the platform secure store.

Retention is a policy decision, not an automatic deletion job today. The environment exposes `AUDIT_RETENTION_DAYS` and `SECURITY_EVENT_RETENTION_DAYS` (default 365) and `NOTIFICATION_DELIVERY_RETENTION_DAYS` (default 30) as policy values for future reviewed cleanup. They **do not currently delete records**. MFA challenges and SSO attempts/tickets need an expiry-plus-grace policy. Legal holds and contractual requirements take priority. No audit or security records should be deleted by a routine job until exceptions, backup handling, and approvals are implemented and tested.

Organization export foundation: a future owner-requested job should require recent step-up, record a security event, use an allowlist of safe fields, stream a tenant-scoped encrypted archive, expire the download, and exclude all SECRET fields. No public bulk-export endpoint exists yet.

Account/organization deletion foundation: request → step-up → owner confirmation → grace period → background anonymization/deletion with audit and legal-hold checks. No immediate hard-delete button is implemented. Backups need a documented expiry and restoration process before deletion can be claimed complete.
