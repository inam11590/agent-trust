# ATP/1.0 Agent-to-Agent Calling Pipeline

## Protocol Overview
Agent-to-agent capability execution uses the AgentTrust Protocol (**ATP/1.0**) and AgentTrust Credential (**ATC/1.0**) specifications.

## Zero-Trust Resolution Flow
```
Caller Agent ---> POST /services/resolve ---> Prioritized Endpoints
                  (Checks: Lifecycles, Trust, Visibility, Environment)
```

## Invalidation & Security Checks
During invocation (`POST /services/call`):
1. **Loop Detection**: Rejects call if target agent appears in `X-AgentTrust-Call-Chain`.
2. **Depth Check**: Rejects call if `depth >= MAX_CALL_DEPTH` (default: 5).
3. **Caller Signature**: Verifies ATP-SIG/1 Ed25519 signature over request envelope.
4. **ATC/1.0 Credential**: Verifies cryptographically verifiable identity and capabilities.
5. **APL/1.0 Policy Evaluation**: Checks deterministic policy rules.
6. **Risk Assessment**: High-risk calls or amounts exceeding autonomous thresholds trigger `PENDING_APPROVAL`.
7. **Deterministic Dispatch**: Routes to highest priority healthy endpoint.
8. **Response Integrity**: Verifies response binds to original request ID and calculates payload hash.
