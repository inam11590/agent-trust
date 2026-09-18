# Rollback procedure

1. Stop routing new traffic to the failing application revision.
2. Confirm the previous image is compatible with the current database schema.
3. Deploy the previous immutable API, worker, and web images.
4. Restore the previous environment configuration from the secret manager when needed.
5. Check liveness, readiness, login, authorization, worker delivery, dashboard, and metrics.

Do not automatically downgrade an Alembic migration. A migration may have moved
or removed data even when application rollback is safe. Prefer a forward fix. If
a database rollback is unavoidable, restore a verified encrypted backup into a
new database, validate it, and switch traffic under an approved incident plan.
