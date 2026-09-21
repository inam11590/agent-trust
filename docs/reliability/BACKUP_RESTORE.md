# Operational Runbook: Backup & Restore

This document defines the backup, integrity verification, and isolated disaster restore procedures for AgentTrust.

---

## 1. Backup Strategy Overview

1. **What is Backed Up**:
   - PostgreSQL schema, tables, constraints, sequences, and indexes.
   - Core entities: Organizations, Users, Agents, Signing Keys (public metadata and certificates only), Permissions, Policies, Delegations, Cross-Org Trust, Enterprise Gateways, Config Bundles, Audit Logs, Security Events, Nonces, Idempotency Records.
2. **What is NEVER Backed Up by Control Plane**:
   - Agent Private Keys (agents generate and hold their private keys locally; Control Plane never possesses them).
   - Gateway Private Keys (held in enterprise `.sidecar_keys/` with 0600 permissions).
   - Plaintext passwords or ephemeral Redis cache keys.
3. **Integrity Protection**:
   - Every backup is packaged alongside a SHA-256 integrity manifest (`backup_manifest.json`) recording checksum, record counts, and database schema version.
   - Restores reject any archive whose SHA-256 digest fails to match the manifest.

---

## 2. Backup Creation

Using the provided backup manager script:
```bash
python scripts/backup_manager.py create --output-dir ./backups
```
This produces:
- `backups/agenttrust_backup_YYYYMMDD_HHMMSS.dump`: Custom compressed PostgreSQL dump.
- `backups/agenttrust_backup_YYYYMMDD_HHMMSS.manifest.json`: Verification manifest containing:
  ```json
  {
    "backup_file": "agenttrust_backup_20260921_120000.dump",
    "sha256": "4a7d...391b",
    "created_at": "2026-09-21T12:00:00Z",
    "schema_version": "0026",
    "table_counts": {
      "organizations": 12,
      "users": 45,
      "agents": 80,
      "agent_signing_keys": 95,
      "audit_logs": 10420
    }
  }
  ```

---

## 3. Backup Integrity Verification

Before any restore operation, verify archive integrity without touching any database:
```bash
python scripts/backup_manager.py verify --manifest backups/agenttrust_backup_20260921_120000.manifest.json
```
Validation checks:
1. File existence and size.
2. SHA-256 checksum recalculation against manifest value.
3. Valid PostgreSQL custom format archive header (via `pg_restore --list`).

---

## 4. Isolated Restore Procedure

> [!CAUTION]
> **Safety Rule**: Restore tests must **NEVER** run against production databases. The restore utility enforces that the target database name must end in `_restore` and that `ALLOW_STAGING_RESTORE=yes` is explicitly declared.

Execute restore verification into an isolated database:
```bash
export STAGING_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/agenttrust_restore"
export ALLOW_STAGING_RESTORE=yes

python scripts/restore_verifier.py restore \
  --manifest backups/agenttrust_backup_20260921_120000.manifest.json \
  --target-db "$STAGING_DATABASE_URL"
```

The restore script executes the following automated verification steps:
1. Verifies SHA-256 checksum of the archive.
2. Connects to the isolated destination database.
3. Cleans existing objects and imports the backup.
4. Executes database migrations (`alembic upgrade head`) if any pending versions exist.
5. Performs **Security State Durability Verification**:
   - `SELECT COUNT(*) FROM agent_signing_keys WHERE status = 'revoked'` matches manifest count.
   - `SELECT COUNT(*) FROM cross_org_trust WHERE status = 'revoked'` matches manifest count.
   - `SELECT COUNT(*) FROM enterprise_gateways WHERE status = 'revoked'` matches manifest count.
   - Verifies pending human approvals remain in `PENDING_APPROVAL` status.
   - Verifies replay nonces remain present to prevent replay attacks against restored state.
