# Backup policy (engineering draft)

Use the existing [backup](../BACKUPS.md) and [restore](../ROLLBACK.md) runbooks. PostgreSQL backup coverage must include users, agents, permissions, audit logs, sessions, MFA records, organization policy, and SSO connection records. Encryption keys must be retained separately in a managed secret store; without the correct key, encrypted MFA and SSO data cannot be restored for use.

Define backup frequency, retention, access, encryption, off-site storage, and restore-time objectives before production release. Test restoring into an isolated environment, run Alembic checks, verify tenant boundaries and audit history, and record the result. A backup file is CONFIDENTIAL or SECRET depending on its contents and key exposure.
