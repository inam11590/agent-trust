# Security controls inventory (engineering draft)

This is an internal implementation checklist, not a certification or legal compliance claim. Each control needs an owner, operating evidence, and independent review before an enterprise assurance statement is made.

| Control | Current technical evidence | Open work |
| --- | --- | --- |
| Password protection | Argon2 password hashes; password change requires current password and MFA when enabled, then revokes other sessions | Password reset and compromised-password response |
| Account MFA | TOTP secret encrypted with `MFA_ENCRYPTION_KEY`; one-use hashed recovery codes; challenge rate limit and temporary lock | Key rotation and operational recovery review |
| Sessions | Opaque JWT identifier hashed in PostgreSQL; expiry and revocation checked on every user request | Device reputation and production-scale cleanup |
| SSO | OIDC code + PKCE, signed ID token and issuer/audience/nonce checks; existing membership required | Real provider interoperability tests and egress controls |
| Authorization | Permission, risk, and organization policy in deny-first order; audit log records decisions | External security assessment |
| Visibility | Security events and user/owner filtered pages; existing metrics and audit logs | Alert routing and retention procedures |
| Transport | Staging/production deployment must terminate HTTPS | Verify TLS at every deployment edge |

Evidence should include migration revisions, automated test output, change review, configuration snapshots without secrets, and incident exercise records. Retain evidence in a restricted store. Never copy passwords, tokens, API keys, MFA secrets, or provider secrets into evidence.
