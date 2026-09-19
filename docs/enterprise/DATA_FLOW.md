# Enterprise Gateway Data Flow & Privacy Invariant Specification

## 1. Zero-Trust Payload Privacy Model

In enterprise environments handling sensitive financial records, PII, healthcare data, or proprietary LLM interactions, **raw business payloads must NEVER flow through the central Control Plane**.

AgentTrust enforces this invariant through architectural separation:

| Data Type | Sent to Control Plane? | Processed Locally by Sidecar? | Reason |
| :--- | :---: | :---: | :--- |
| **Agent Prompt & Business Payload** | **NEVER** | **YES** | Enforces privacy; never leaves VPC |
| **Transaction Amount & Currency** | **NEVER** (unless audited) | **YES** | Local policy evaluator validates limits |
| **Agent Signing Public Keys** | **YES** | **YES** | Identity registry distribution |
| **Organizational Policies** | **YES** | **YES** | Compiled into signed monotonic bundles |
| **Revocation Lists (CRLs)** | **YES** | **YES** | Distributed to invalidate compromised entities |
| **Sidecar Health Counters (Aggregate)** | **YES** | **YES** | Telemetry (uptime, request count, skew) |

---

## 2. Primary Data Flows

### Flow A: Configuration Bundle Compilation & Distribution (Control Plane -> Data Plane)

```
[Control Plane Engine]
         │ 1. Compile Org Policies, Agents, Revocations
         ▼
[Bundle Compiler]
         │ 2. Compute Canonical SHA-256 Hash
         │ 3. Sign with Control Plane Ed25519 Root Key
         │ 4. Assign Monotonic Version (v_current + 1)
         ▼
[HTTPS CDN / Control Plane API]
         │
         │ GET /v1/gateways/{id}/config/bundle
         ▼
[Sidecar Sync Worker]
         │ 5. Validate TLS certificate & Hostname
         │ 6. Verify Ed25519 signature of Control Plane
         │ 7. Assert Monotonicity: v_bundle > v_active
         │ 8. Atomic disk write (.sidecar_cache/config_cache.json)
         │ 9. Hot-reload local memory evaluator
         ▼
[Local Evaluator Active Memory]
```

### Flow B: Sub-Millisecond Local In-Pod Authorization (Agent -> Sidecar)

```
[AI Agent Container]
         │ POST http://127.0.0.1:8080/v1/local/authorize
         │ Headers: X-Agent-ID, X-Signature, X-Timestamp, X-Nonce
         ▼
[Sidecar HTTP Engine]
         │ 1. Verify Timestamp within ±5s drift window
         │ 2. Check Nonce against memory LRU cache (Anti-Replay)
         │ 3. Verify Agent Ed25519 signature over request
         │ 4. Evaluate local policy bundle:
         │    - Agent active & unrevoked?
         │    - Action permitted on resource?
         │    - Financial amount within delegated limit?
         │    - ATC/1.0 verifiable credential valid?
         │ 5. Decision: APPROVED (200 OK) or REJECTED (403 Forbidden)
         ▼
[AI Agent Container] (Receives decision in < 0.5ms)
```

### Flow C: Outbound ATP/1.0 Message Routing (Sidecar -> Target Gateway / Agent)

```
[AI Agent Container]
         │ POST http://127.0.0.1:8080/atp/v1/messages
         │ Body: ATP/1.0 Envelope (target, capability, payload)
         ▼
[Sidecar Outbound Router]
         │ 1. Verify Agent authority for requested capability
         │ 2. Validate Target URL & enforce SSRF Defense:
         │    - Reject 127.0.0.1 / localhost
         │    - Reject 169.254.169.254 (Cloud metadata)
         │    - Reject 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (Unless DIRECT_PRIVATE enabled)
         │ 3. Compute SHA-256 payload digest
         │ 4. Attach Gateway Attestation Header signed by Sidecar Ed25519 key
         │ 5. Mutual TLS HTTP/2 connection to destination
         ▼
[Target Agent / Enterprise Gateway]
```

### Flow D: Aggregate Health & Telemetry Heartbeats (Sidecar -> Control Plane)

```
[Sidecar Background Reporter] (Every 30s)
         │ 1. Collect sanitized aggregate counters:
         │    - uptime_seconds
         │    - evaluations_total, approved, rejected
         │    - cached_policies_count
         │    - clock_skew_ms
         │ 2. Sign heartbeat payload with Sidecar Ed25519 private key
         │ 3. POST /v1/gateways/{id}/heartbeat
         ▼
[Control Plane]
         │ 4. Verify Sidecar Ed25519 signature
         │ 5. Record gateway health & update status
```
