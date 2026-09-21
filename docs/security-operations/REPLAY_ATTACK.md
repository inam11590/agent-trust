# Incident Runbook: Replay Attack Handling

## Alert Identifier
- **Rule ID**: ule_replay_burst
- **Severity**: HIGH

## Symptoms
Repeated gent_replay_detected events within a short time window (default: >= 3 events in 300 seconds) for the same Agent or source IP.

## Investigation Steps
1. **Identify Target & Origin**:
   - Locate the gent_id and originating IP or Gateway from the alert metadata.
2. **Analyze Nonce & Timestamps**:
   - Check if the repeated requests contain identical nonces (
once_reused) or expired timestamps (	imestamp_skew_exceeded).
   - If timestamp skew is positive, verify whether the client clock has drifted.
   - If exact nonces are reused across distinct IP addresses, an adversary may have intercepted network traffic.
3. **Inspect Transport Security**:
   - Confirm whether mTLS or TLS 1.3 was active on the ingress gateway.
   - Verify if unencrypted network intermediaries could have recorded and re-transmitted signed HTTP headers.
4. **Remediation & Containment**:
   - If clock skew: Inform the agent operator to sync NTP clocks.
   - If active interception: Rotate the Agent's signing key immediately via /dashboard/agents/{id} or the CLI (genttrust keys rotate).
   - If malicious source: Blacklist the client IP at the firewall / WAF.
5. **Post-Incident**:
   - Verify that all replayed requests were successfully denied with HTTP 401/403.
   - Resolve the alert with resolution note: Investigated replay source; key rotated; client traffic verified safe.
