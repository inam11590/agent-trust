# Incident Response Framework

This document outlines the operational incident response procedure for AgentTrust outages, degraded performance, and security events.

---

## 1. Severity Classifications

| Severity | Definition | Examples | Response Target |
| :--- | :--- | :--- | :--- |
| **SEV1 (Critical Outage)** | Complete service outage or critical security vulnerability affecting multiple organizations. | Entire primary region down; database failure; replay protection offline; signature verification failure. | Immediate response (< 15 mins). Continuous paging until resolved. |
| **SEV2 (Degraded)** | Significant feature degradation or single customer/agent impact without complete system outage. | Background worker backlog > 1,000 jobs; email notifications delayed; external billing webhook failures; single replica crash. | Response < 1 hour. Business hours/escalation. |
| **SEV3 (Minor / Informational)** | Minor glitch or performance anomaly with available workaround. | Slow non-critical dashboard queries; documentation error; rate limit threshold warning. | Next business day. |

---

## 2. Incident Lifecycle (The 6 Stages)

```
+------------+       +------------+       +------------+
| 1. DETECT  |  -->  | 2. ASSESS  |  -->  | 3. CONTAIN |
+------------+       +------------+       +------------+
                                                 |
+------------+       +------------+              v
| 6. DOCUMENT|  <--  | 5. VERIFY  |  <--  +------------+
+------------+       +------------+       | 4. RECOVER |
                                          +------------+
```

1. **DETECT**:
   - Automated alerts fire (e.g. `/health/ready` failing, 5xx rate > 1%, Redis unreachable).
   - User report via incident channel.
2. **ASSESS**:
   - Determine severity (SEV1, SEV2, SEV3).
   - Designate Incident Commander (IC) and Communications Lead.
   - Confirm affected components (API, DB, Redis, Workers, Region).
3. **CONTAIN**:
   - Prevent cascading failures.
   - If security compromised: fence affected region or isolate compromised agent/key.
   - If Redis down: ensure signed requests fail closed (`REPLAY_PROTECTION_UNAVAILABLE`).
4. **RECOVER**:
   - Execute established runbook:
     - API issue: scale or restart containers.
     - Database issue: restart or promote standby replica.
     - Region issue: execute `REGION_FAILOVER_RUNBOOK.md`.
5. **VERIFY**:
   - Run recovery smoke tests:
     - Health checks (`/health/live`, `/health/ready`, `/health/region`).
     - Signed ATP request verification.
     - Anti-replay rejection test.
     - Revocation integrity check.
6. **DOCUMENT (Post-Mortem)**:
   - Within 48 hours, conduct a blameless post-mortem.
   - Document: Timeline, Root Cause, Impact, What went well, What went poorly, Action items with owners.
