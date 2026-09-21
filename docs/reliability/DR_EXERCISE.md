# Disaster Recovery (DR) Exercise Guide & Report Template

This guide provides the protocol for conducting disaster recovery exercises and measuring actual Recovery Point Objective (RPO) and Recovery Time Objective (RTO).

---

## 1. Exercise Protocol

### Safety Invariants
- DR exercises must **NEVER** run directly against the live production primary database.
- Exercises must run in a staging environment or an isolated sandbox database.
- Production data must not be destroyed or overwritten during simulations.

### Execution Steps
1. **Prepare Isolated Test Environment**:
   - Spin up isolated PostgreSQL and Redis instances.
   - Seed with realistic AgentTrust test data (organizations, agents, signing keys, active revocations, pending approvals, and replay nonces).
2. **Record Start Timestamp ($T_0$)**.
3. **Simulate Disaster**:
   - Scenario A: Abrupt PostgreSQL crash / process termination.
   - Scenario B: Redis outage during signed request traffic.
   - Scenario C: Primary Region failure (simulate regional failover to secondary).
4. **Execute Recovery Runbook**:
   - Restore from backup or promote standby replica.
   - Recover API and worker connections.
5. **Record Recovery Timestamp ($T_{\text{recovered}}$)**.
   - Compute measured **RTO** = $T_{\text{recovered}} - T_0$.
6. **Verify Data Loss**:
   - Compare pre-disaster state vs restored state.
   - Compute measured **RPO** = timestamp of disaster minus timestamp of latest recovered transaction.
7. **Run Smoke & Security Invariant Tests**:
   - Revoked credentials remain revoked.
   - Pending approvals remain pending.
   - Replay nonces remain rejected.

---

## 2. DR Exercise Report Template

```markdown
# Disaster Recovery Exercise Report

- **Date / Time**: YYYY-MM-DD HH:MM:SS UTC
- **Exercise Lead**: [Name / Team]
- **Environment**: [STAGING / ISOLATED TEST / SIMULATED MULTI-REGION]
- **Scenario Tested**: [e.g., PostgreSQL Crash & Restore / Simulated Regional Failover]

### Measurements
- **Exercise Start Time**: YYYY-MM-DD HH:MM:SS UTC
- **Recovery Complete Time**: YYYY-MM-DD HH:MM:SS UTC
- **Measured RTO (Recovery Time)**: XX minutes / seconds
- **Measured RPO (Data Loss Window)**: XX minutes / seconds (or 0 transactions lost)

### Verification Checklist
- [ ] Database restored and migrations verified
- [ ] /health/live and /health/ready return HTTP 200 OK
- [ ] Revoked credentials remain REVOKED (No resurrection)
- [ ] Revoked signing keys remain REVOKED
- [ ] Pending human approvals remain PENDING (No unauthorized approvals)
- [ ] Anti-replay protection prevents reuse of pre-disaster nonces
- [ ] Webhook delivery resumes without duplicate execution
- [ ] Enterprise Gateway successfully syncs configuration

### Findings & Action Items
1. [Finding 1]: [Corrective Action & Owner]
2. [Finding 2]: [Corrective Action & Owner]
```
