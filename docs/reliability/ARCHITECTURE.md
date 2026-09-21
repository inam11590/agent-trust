# AgentTrust Reliability Architecture

This document explains the reliability, high availability, and disaster recovery architecture of AgentTrust in clear, simple English.

---

## 1. Core Concepts in Simple English

### What is High Availability (HA)?
High Availability means the system keeps working even if a single component (such as a server, container, worker, or database connection) crashes or fails. Instead of relying on a single instance of a service, multiple identical instances run simultaneously behind a load balancer. If one fails, traffic automatically shifts to the healthy ones without users noticing.

### What is an Availability Zone (AZ)?
An Availability Zone is an isolated physical data center (or cluster of data centers) within a region, equipped with independent power, cooling, and networking. If lightning strikes or a power grid fails in one AZ, systems in another AZ continue running without interruption.

### What is a Region?
A Region is a distinct geographic area (such as North Virginia `us-east-1` or Frankfurt `eu-central-1`) containing multiple Availability Zones. Regions are separated by hundreds or thousands of miles. Complete regional outages (e.g., massive undersea fiber cuts or extreme weather disasters) are rare, but multi-region planning ensures business continuity if an entire region becomes unavailable.

### What is Failover?
Failover is the operational process of redirecting traffic and workload from an unhealthy system to a healthy backup system.
- **Local Failover**: A load balancer stops sending requests to a crashed API container and routes only to healthy containers.
- **Regional Failover**: Moving operations from a failed Primary Region to a Standby Secondary Region.

### What is Backup?
A Backup is a durable, point-in-time copy of database records, configurations, and cryptographic metadata stored safely in a separate storage system. A backup is not proven until it has been successfully restored and verified.

### What is Restore?
Restore is the process of taking a saved backup and recreating a fully functional, consistent database or service environment.

### What is Disaster Recovery (DR)?
Disaster Recovery is the complete set of policies, tools, and runbooks designed to restore operations and data access following catastrophic events (such as regional data center destruction, widespread ransomware, or severe database corruption).

### What is RPO (Recovery Point Objective)?
RPO answers: **"How much recent data can we accept losing after a disaster?"**
- If RPO is 15 minutes, it means a disaster might cause up to 15 minutes of recent data to be lost.
- In AgentTrust, security-critical changes (such as credential or trust revocations) demand an RPO as close to zero as technically achievable to prevent security holes.

### What is RTO (Recovery Time Objective)?
RTO answers: **"How long can recovery take before operations resume?"**
- If RTO is 30 minutes, it means systems must be recovered, verified, and serving traffic within 30 minutes of a declared disaster.

---

## 2. Failure Behaviors (What Happens When...)

| Failure Scenario | Immediate System Behavior | Safety & Security Impact | Recovery Action |
| :--- | :--- | :--- | :--- |
| **One API Replica Dies** | Load balancer detects failed health check (`/health/live`), stops sending traffic to that replica. | **No impact**. Other replicas handle traffic. Sessions and requests are stateless. | Container orchestrator restarts the failed replica. |
| **All API Replicas in One AZ Die** | Cross-AZ load balancing automatically routes 100% of traffic to API replicas in the surviving AZ. | **No impact** if remaining AZ has sufficient capacity. | Orchestrator scales replicas in surviving AZ. |
| **PostgreSQL Primary Dies** | API connections fail. Health readiness probe (`/health/ready`) returns HTTP 503. | **Fail closed**. No unauthorized approvals or policy bypasses occur. Stale data is never used to grant access. | Standby DB promoted to primary; API connection pool auto-reconnects with `pool_pre_ping`. |
| **Redis Outage** | Replay protection and rate limiting engines detect Redis failure. | **Fail closed**. Signed requests requiring anti-replay return `REPLAY_PROTECTION_UNAVAILABLE` (HTTP 503). Security checks never fail open. | Redis Sentinel/Cluster auto-failover, or restart Redis. API resumes normal operation. |
| **One Background Worker Dies** | Worker terminates mid-task. Unacknowledged jobs return to queue or remain locked until lease expires. | **No job loss**. Handlers use idempotent transaction keys (`skip_locked=True`) so retry does not duplicate actions. | Worker process restarts and continues processing queue backlog. |
| **One Entire Region Dies** | Primary Control Plane becomes completely unreachable. Gateways switch to Secondary endpoint or use Step 23 offline safety rules (`FAIL_CLOSED` / `LIMITED_OFFLINE`). | **Fail closed**. Security checks remain enforced. Nonces and revocations are preserved. No split-brain writes. | Execute `REGION_FAILOVER_RUNBOOK.md` to promote Secondary Region. |

---

## 3. Failure Domains & Single Points of Failure (SPOF) Analysis

| Component | Nature | Single Point of Failure? | Mitigation / Architecture |
| :--- | :--- | :--- | :--- |
| **FastAPI Nodes** | Stateless | **No** | Multiple replicas behind load balancer with health probes. |
| **Next.js Web UI** | Stateless | **No** | Multi-replica container deployment or CDN-backed edge hosting. |
| **PostgreSQL** | Stateful | **Mitigated** | Primary + synchronous/asynchronous standby replicas across AZs, automated failover, regular backups. |
| **Redis** | Stateful (Cache & Nonce) | **Mitigated** | Redis HA (Sentinel / Cluster / Managed HA) with fail-closed anti-replay enforcement. |
| **Background Workers** | Stateless Workers | **No** | Multi-worker replicas pulling jobs via `FOR UPDATE SKIP LOCKED`. |
| **Scheduler** | Singleton Task | **Mitigated** | Distributed lock with bounded lease or single leader election. |
| **Enterprise Gateway** | Local Data Plane | **No** | Distributed locally per enterprise/cluster. Runs independently of cloud control plane. |
| **DNS / Traffic Routing**| Infrastructure | **Mitigated** | Anycast DNS with health-checked failover routing. |
| **External Providers** | Outbound Dependencies | **Mitigated** | Circuit breaker, bounded timeouts, asynchronous delivery via dead-letter queues. |

---

## 4. Service State Classification

```
+----------------------------------------------------------------------------------------------------+
|                                    SERVICE STATE CLASSIFICATION                                    |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|    [ STATELESS ]                                [ STATEFUL ]               [ EXTERNAL ]            |
|    - FastAPI Request Nodes                      - PostgreSQL Primary       - Email (SMTP/SES)      |
|    - Background Worker Tasks                    - PostgreSQL Standby       - Push (FCM)            |
|    - Web Dashboard (Next.js)                    - Redis (Nonce/RateLimit)  - External Agent APIs   |
|    - CLI Client                                                            - Billing Provider      |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

1. **STATELESS (FastAPI API nodes, Next.js Web)**:
   - Contains no process-local session state.
   - Contains no process-local authorization state.
   - Contains no in-memory anti-replay state.
   - Any request can be served safely by any replica at any moment.
2. **STATEFUL (PostgreSQL, Redis)**:
   - **PostgreSQL**: Authoritative source of truth for organizations, agents, permissions, delegations, credentials, revocations, approvals, and audit records.
   - **Redis**: Fast anti-replay store, distributed rate limiting, ephemeral caching.
3. **EXTERNAL DEPENDENCIES (Email, FCM, Billing, Peer Gateways)**:
   - Protected by bounded timeouts, circuit breakers, and exponential backoff retry.

---

## 5. Consistency Classification Matrix

| Data Domain | Required Consistency | Can Stale Replica Be Used? | Behavior If Primary Unavailable |
| :--- | :--- | :--- | :--- |
| **Credential Revocation** | **STRONG / IMMEDIATE** | **NEVER** | Fail closed. Revocations must be authoritative. |
| **Signing Key Revocation**| **STRONG / IMMEDIATE** | **NEVER** | Fail closed. |
| **Agent Suspension** | **STRONG / IMMEDIATE** | **NEVER** | Fail closed. |
| **Trust Revocation** | **STRONG / IMMEDIATE** | **NEVER** | Fail closed. |
| **Multi-Party Approvals**| **STRONG / IMMEDIATE** | **NEVER** | Remain PENDING. Never auto-approve. |
| **Anti-Replay Nonces** | **STRONG / IMMEDIATE** | **NEVER** | Fail closed (`REPLAY_PROTECTION_UNAVAILABLE`). |
| **Policy Updates** | **STRONG / MONOTONIC** | No (must verify monotonic version) | Reject older config bundles. |
| **Audit Logs** | **STRONG / DURABLE** | N/A (Append-only write) | Buffer in durable outbox/queue. |
| **Billing Records** | **STRONG / IDEMPOTENT** | No | Idempotent key protects against double charge. |
| **Dashboard Analytics** | **EVENTUAL** | **YES** (Cached / Replica acceptable) | Degrade gracefully, show cached metrics. |
| **Activity Feed** | **EVENTUAL** | **YES** (Read replica acceptable) | Serve slightly delayed list. |

---

## 6. Multi-Region Strategy: Active / Passive

### Why Active / Passive Single-Primary?
AgentTrust is a security control plane. It authorizes actions, enforces delegations, holds multi-party human approvals, and registers cryptographic revocations.
If two regions are both writable at the same time (**Active / Active**), network partitions create **split-brain** conditions:
- An administrator in Region A revokes an agent.
- Simultaneously, in Region B, that same agent is granted a delegation.
- During a partition, resolving this conflict deterministically is mathematically and operationally dangerous.

Therefore, AgentTrust adopts an **Active / Passive (Single-Primary Write)** model:
1. **Primary Region**: All state-modifying requests (revocations, approvals, delegations, enrollments) execute authoritatively in the primary region.
2. **Standby Region**: Maintains warm replicas of PostgreSQL and configurations. Mutating requests in the standby region are strictly fenced with `REGION_STANDBY_READ_ONLY`.
3. **Promotion**: Controlled, runbook-driven failover promotes the Standby region to Primary only after confirming the old primary is completely fenced.
