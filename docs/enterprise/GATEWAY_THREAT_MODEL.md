# Enterprise Gateway & Sidecar Threat Model (STRIDE)

## 1. System Scope & Trust Boundaries

The Enterprise Gateway and Sidecar data plane operate across four distinct trust boundaries:

1. **Boundary 1: Local Pod / Host IPC**: Communication between the AI Agent container and the Sidecar (`127.0.0.1:8080`).
2. **Boundary 2: Data Plane to Control Plane**: Sync polling and aggregate heartbeat reporting over mutual TLS.
3. **Boundary 3: Outbound Egress**: Inter-agent or cross-gateway ATP/1.0 communication across public or private networks.
4. **Boundary 4: Node Storage**: Local filesystem cache (`.sidecar_cache`) and key directory (`.sidecar_keys`).

---

## 2. STRIDE Threat Analysis & Mitigations

### 1. Spoofing Identity

* **Threat**: An attacker or rogue workload impersonates an authorized AI agent to request unauthorized permissions.
* **Mitigation**:
  * Every authorization request must bear an Ed25519 signature computed over the canonical request payload, canonical timestamp, and high-entropy nonce.
  * Sidecars verify the signature against the agent's public key provisioned in the signed Control Plane configuration bundle.
  * Nonces are verified against a local in-memory sliding window cache to prevent replay.

### 2. Tampering

* **Threat 2.1 (In-Flight Policy Tampering)**: An adversary intercepts or modifies configuration bundles in transit between Control Plane and Sidecar.
  * **Mitigation**: Every bundle is signed with the Control Plane's Ed25519 root signing key. Sidecars independently verify the signature before applying or storing any bundle.
* **Threat 2.2 (Local Cache Tampering)**: An attacker with pod access attempts to alter the local `.sidecar_cache/config_cache.json` file.
  * **Mitigation**: When loading from disk, the sidecar verifies the bundle's Ed25519 signature and SHA-256 content hash against the embedded signature. Corrupted or modified cache files are discarded.

### 3. Repudiation

* **Threat**: A compromised gateway or agent denies having authorized or dispatched a transaction.
* **Mitigation**:
  * Every decision is accompanied by a cryptographic attestation header (`Gateway-Attestation`) signed by the local gateway's private Ed25519 key.
  * Outbound ATP envelopes include the original agent's `ATP-SIG/1` signature and the gateway's routing attestation.

### 4. Information Disclosure (Privacy Violation)

* **Threat**: Business payloads, LLM prompts, confidential financial values, or PII leak to the central Control Plane or external monitoring services.
* **Mitigation**:
  * Strict Data Plane separation: In-pod authorization requests (`/v1/local/authorize`) are processed entirely inside the local node memory.
  * Telemetry heartbeats to the Control Plane include **only sanitized statistical counters** (uptime, evaluation count, clock skew). Prompt texts and business payloads are architecturally excluded.

### 5. Denial of Service (DoS)

* **Threat**: An attacker severs connectivity between the Sidecar and Control Plane to disable autonomous operations or force fail-open conditions.
* **Mitigation**:
  * Cached `LIMITED_OFFLINE` operation allows verified low-risk operations to proceed uninterrupted during network partitions.
  * High-risk operations (> $5,000 or admin actions) fail closed, preventing exploitation during outages.
  * Sidecar memory footprint is capped (< 128MB) with fixed-size LRU replay caches to prevent memory exhaustion attacks.

### 6. Elevation of Privilege (Rollback Attack)

* **Threat**: An attacker captures a signed configuration bundle from yesterday (when a now-revoked agent key was still valid) and replays it to the sidecar.
* **Mitigation**:
  * Monotonic version checking: Sidecars enforce `bundle.version > current_version`.
  * The sidecar refuses any bundle where `version <= current_version`, stopping replay attacks dead in their tracks.
  * Configuration bundles carry an expiration timestamp (`bundle_ttl_seconds`).

---

## 3. SSRF (Server-Side Request Forgery) Defense

When an autonomous agent requests the sidecar to route an outbound ATP/1.0 message to an external agent endpoint:

1. The sidecar resolves the destination IP address.
2. The IP is checked against forbidden address ranges:
   * `127.0.0.0/8` (Loopback)
   * `169.254.169.254` (Cloud Instance Metadata Service - IMDSv1/v2)
   * `0.0.0.0/8`, `224.0.0.0/4` (Multicast, broadcast)
   * `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private RFC1918 networks)
3. If `DIRECT_PRIVATE_ENABLED=false` (default), all internal network targets are blocked with `400 Bad Request (SSRF blocked)`.
4. Only valid public HTTPS endpoints or explicitly allowlisted cluster gateways are permitted.
