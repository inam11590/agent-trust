# PostgreSQL backup and restore

Use managed PostgreSQL point-in-time recovery when available. Also keep encrypted
logical backups in private object storage. Initial policy: one backup daily, keep
7 daily copies and 4 weekly copies. Configure the schedule and retention in the
managed provider and alert on missed backups.

At least monthly, restore a recent backup into a new isolated staging database:

1. Confirm the destination is empty and contains no production clients.
2. Create a clean staging database whose name ends in `_restore`. Set
   `STAGING_DATABASE_URL`, set `ALLOW_STAGING_RESTORE=yes`, then run
   `scripts/restore_postgres.sh backup.dump` with staging-only credentials.
3. Run `alembic upgrade head` against the restored database.
4. Check `/health/ready` and verify users, organizations, agents, permissions,
   audit logs, authorization requests, notifications, risk, and billing tables.
5. Delete the isolated database using the provider's approved process.

Never restore unmasked production data to a developer laptop. Encrypt backup
files in transit and at rest, restrict access, and test restoration rather than
assuming a successful upload is usable.
