# Operational Runbook: Regional Failback

This runbook describes the careful procedure for returning primary control to the original Primary Region after an outage has been resolved, preventing stale writes, data loss, and split-brain conditions.

---

## 1. Pre-Conditions for Failback

Failback is **never emergency-driven**. It must only be performed during a scheduled maintenance window after thorough verification:

1. **Root Cause Resolved**: The physical or network failure that caused the original primary region outage is confirmed resolved.
2. **Infrastructure Stability**: Primary region network, database host, and Redis instances have run cleanly for at least 2 consecutive hours.
3. **Standby Data Synchronization**: Re-establish replication from the currently active Secondary Region back to the restored Primary Region:
   - Use `pg_rewind` or rebuild the restored primary as a streaming replica of the secondary.
   - Confirm WAL replication lag between Secondary (Current Primary) and Primary (New Standby) is zero bytes.

---

## 2. Step-by-Step Failback Sequence

### Step 1: Quiesce Traffic & Enter Maintenance
1. Notify operators and schedule a 5-minute low-traffic maintenance window.
2. Optionally enable maintenance mode on the edge load balancer.

### Step 2: Fence the Secondary Region
1. Switch Secondary Region application to read-only standby:
   ```bash
   export REGION_ROLE=standby
   export REGION_FENCING_ENABLED=true
   ```
2. Wait 30 seconds for in-flight database transactions and worker jobs to complete.
3. Ensure the last WAL transaction from the secondary is flushed and replayed on the primary.

### Step 3: Promote Restored Primary
1. Promote PostgreSQL on the restored Primary Region to Read-Write Primary:
   ```bash
   pg_ctl promote -D /var/lib/postgresql/data
   ```
2. Update primary control plane environment:
   ```bash
   export REGION_ROLE=primary
   export REGION_FENCING_ENABLED=false
   ```
3. Restart API nodes and workers in the restored Primary Region.

### Step 4: Re-point Traffic
1. Update DNS / Global Traffic Router to point back to the Primary Region.
2. Verify `/health/ready` and `/health/region` return `OPERATIONAL` and `primary`.

### Step 5: Re-configure Secondary as Standby
1. Re-establish streaming replication from the newly restored Primary to the Secondary Region.
2. Verify continuous replication is healthy.

---

## 3. Post-Failback Security Reconciliation

Run the automated security state audit to verify that no access grants or revocations were lost:
```bash
agenttrust reliability status
agenttrust region status
```
Verify:
- All credential revocations during the failover window remain enforced.
- All signing key rotations remain enforced.
- Audit logs captured during failover in the secondary have been replicated to the primary.
