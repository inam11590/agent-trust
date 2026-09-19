# Enterprise Gateway Offline Safety & Anti-Rollback Security

## 1. The Fallacy of "Allow-All" Offline Mode

A frequent security failure in distributed agent architectures is "failing open" when a central server cannot be reached. In an autonomous agent system, an allow-all offline mode would mean an attacker could simply disconnect an agent or sever the network to execute arbitrary unauthorized transactions, drain corporate funds, or bypass revocation lists.

**AgentTrust strictly forbids any "allow-all" offline mode.**

Under no circumstances will a sidecar or edge gateway approve an action merely because the Control Plane is unreachable.

---

## 2. Policy Modes: FAIL_CLOSED vs LIMITED_OFFLINE

Every enterprise gateway is configured with an explicit offline policy:

### A. `FAIL_CLOSED` (Default & Highly Recommended)

* **Behavior**: If the sidecar is offline or cannot guarantee fresh control plane state, all requests that cannot be deterministically verified against an active, unexpired cryptographic configuration bundle are immediately rejected (`403 Forbidden`).
* **Intended For**: High-security corporate environments, financial transactions, database mutations, external cloud actions, and regulated healthcare deployments.

### B. `LIMITED_OFFLINE` (Restricted Cached Mode)

* **Behavior**: When the Control Plane is unreachable, the sidecar may continue evaluating requests **ONLY IF ALL** of the following conditions are met:
  1. The cached configuration bundle has not expired (`bundle_age < bundle_ttl_seconds`).
  2. The action is marked read-only or low-risk (`risk_score <= 30`).
  3. The agent is explicitly listed as active in the cached bundle and has not been revoked.
  4. The financial transaction amount does **NOT** exceed the low-risk threshold ($5,000 USD equivalent).
  5. The action does **NOT** require human approval (`requires_approval == false`).

* **CRITICAL FAIL-CLOSED ESCALATIONS (Always Rejected Offline)**:
  * Any action with `amount > 5000`.
  * Any administrative or credential-issuance capability.
  * Any action requiring multi-party approval.
  * Any request from an agent revoked in the local cache or missing from the bundle.

---

## 3. Monotonic Anti-Rollback Protection

When an agent or key is revoked, the Control Plane issues an updated configuration bundle. An attacker with network control might attempt a **Rollback Replay Attack**, re-sending a validly signed older configuration bundle from before the revocation occurred.

To prevent this:

1. **Monotonic Version Number**:
   Every bundle is published with a strictly increasing integer version: `v1, v2, v3...`.

2. **Sidecar Version Gate**:
   The sidecar asserts:
   $$\text{version}_{\text{incoming}} > \text{version}_{\text{current}}$$
   Any bundle where $\text{version}_{\text{incoming}} \le \text{version}_{\text{current}}$ is unconditionally rejected with an anti-rollback security event logged.

3. **Safe Rollback Protocol**:
   If an administrator needs to revert policies to an earlier state (e.g., rolling back from `v4` to `v2` due to an operational bug), the Control Plane **does not publish the old `v2` bundle**.
   Instead, the Control Plane retrieves the payload of `v2` and issues it as **`v5`**, signed freshly with the current timestamp. The sidecar accepts `v5 > v4` while restoring the desired policy definitions.

---

## 4. Cache Expiration & TTL Enforcement

* Sidecars persist their active configuration bundle to local disk cache (`.sidecar_cache/config_cache.json`).
* If the sidecar restarts while the network is down, it reads the local disk cache.
* If `current_time - bundle.published_at > bundle_ttl_seconds` (default: 86400 seconds / 24 hours), the cache is marked **STALE**.
* Stale caches revert immediately to **FAIL_CLOSED** until connectivity to the Control Plane is restored.
