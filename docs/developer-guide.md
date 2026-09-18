# AgentTrust Developer Platform & Integration Guide

Welcome to the **AgentTrust Developer Platform**. AgentTrust provides cryptographic Agent Identity, cryptographically signed requests, dynamic permission gating, real-time risk assessment, and human-in-the-loop approvals for autonomous AI agents.

---

## 1. Architecture Overview

AgentTrust operates on a **Zero-Trust Autonomous Execution Model**:
1. **Agent Identity**: Every autonomous AI agent possesses a unique public-key identity (Ed25519) registered in AgentTrust.
2. **Signed Requests**: High-stakes agent actions (purchases, data access, transfers) are signed locally by the agent runtime using its private key. The private key never leaves the agent machine.
3. **Multi-Stage Gating**: The AgentTrust Authorization Engine verifies signature integrity, checks nonces for replay prevention, validates against active organization permissions, evaluates real-time risk, and triggers human approval when thresholds are exceeded.
4. **Human-in-the-Loop**: Authorized operators review pending authorizations on native mobile (iOS/Android) or dashboard interfaces with real-time push notifications.
5. **Webhooks**: Downstream systems receive cryptographically signed HMAC-SHA256 webhook deliveries detailing authorization outcomes.

```
+----------------+          Signed Request (Ed25519)          +--------------------+
| Autonomous AI  | -----------------------------------------> |    AgentTrust      |
|  Agent Runtime |                                            | Authorization Gate |
+----------------+                                            +--------------------+
        |                                                                |
 [Private Key]                                                  [Verify Signature]
 (Never Leaves Host)                                            [Check Nonce Replay]
                                                                [Evaluate Risk/Rules]
                                                                         |
                                                      +------------------+------------------+
                                                      |                                     |
                                               Status: APPROVED                       Status: PENDING
                                                      |                                     |
                                            [Execute Agent Task]                     [Mobile / Push UI]
                                                      ^                                     |
                                                      |                               [Human Approves]
                                                      +-------------------------------------+
```

---

## 2. 10-Minute Integration Flow

Integrate your first agent in under 10 minutes:

### Step 1: Install SDK / CLI
```bash
pip install agenttrust
```

### Step 2: Configure Sandbox Credentials
```bash
agenttrust configure --api-key at_test_your_key_here --base-url https://api.agenttrust.example
```

### Step 3: Generate Local Keypair
```bash
agenttrust keys generate --name flight_bot
# Outputs:
#   Key ID:      key_ag_9c28e47b85f1e403d12b0e9a
#   Fingerprint: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
#   Private Key: ./keys/flight_bot_private.pem
#   Public Key:  ./keys/flight_bot_public.pem
```

### Step 4: Register Agent & Key
```bash
agenttrust agents create --name "Flight Booking Assistant" --environment sandbox
agenttrust keys register --agent-id agt_your_agent_id --public-key-path ./keys/flight_bot_public.pem
```

### Step 5: Authorize Action
```bash
agenttrust authorize \
  --agent-id agt_your_agent_id \
  --action purchase \
  --resource flight \
  --amount 300 \
  --currency USD \
  --key-id key_ag_9c28e47b85f1e403d12b0e9a \
  --private-key-path ./keys/flight_bot_private.pem
# Output:
#   Decision:   APPROVED
#   Request ID: req_9f31ab2c4e51
#   Reason:     Action allowed within permission limits
```

---

## 3. Sandbox vs Production Isolation

AgentTrust maintains strict cryptographic, architectural, and data isolation between the Sandbox and Production environments:

| Feature | Sandbox (`at_test_...`) | Production (`at_live_...`) |
| :--- | :--- | :--- |
| **Key Prefix** | `at_test_` (72 characters) | `at_live_` (72 characters) |
| **Cross-Tenant Access** | Strictly prohibited (404/Rejected) | Strictly prohibited (404/Rejected) |
| **Billing Quota** | Completely bypassed (no monthly charge) | Enforces monthly authorization tier |
| **Risk History** | Isolated test logs (never poisons prod score)| Real historical risk profiling |
| **Audit Logs** | Filtered by `environment=sandbox` | Filtered by `environment=production` |
| **Webhooks** | Tagged with `test_mode: true` | Production event stream |

---

## 4. Cryptographic Agent Identity & Ed25519 Request Signing

AgentTrust uses standard Ed25519 (RFC 8032) asymmetric signatures.

### Canonical String Format
```
v1\n{METHOD}\n{PATH}\n{AGENT_ID}\n{KEY_ID}\n{TIMESTAMP}\n{NONCE}\n{SHA256(BODY)}\n
```

### Required Signed HTTP Headers
1. `X-Agent-ID`: Registered agent identifier (`agt_...`)
2. `X-Agent-Key-ID`: Registered signing key identifier (`key_ag_...`)
3. `X-Agent-Timestamp`: UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
4. `X-Agent-Nonce`: Unique per-request nonce (`nonce_...`, 32 hex chars)
5. `X-Agent-Signature`: Base64-encoded Ed25519 signature
6. `X-Agent-Signature-Version`: Must equal `v1`

### Security Guarantees
* **Clock Window**: Requests must be submitted within 300 seconds (5 minutes) of generation.
* **Replay Defense**: Nonces are atomically registered in Redis / Postgres. Reused nonces trigger `REPLAY_DETECTED` immediately.

---

## 5. Browser-Local Signing in API Playground

The AgentTrust Developer Portal API Playground enables interactive testing of cryptographic signing directly in the web browser using the native **Web Crypto API**:
* Private keys are generated or imported in browser memory.
* The canonical request is constructed and signed locally in JavaScript.
* **Security Invariant**: Private key bytes are NEVER transmitted over the network or logged to server telemetry.

---

## 6. Permission Policies & Templates

Permissions grant agents scoped authority to perform sensitive operations.

### Standard Templates
1. **flight_purchase**:
   * Action: `purchase`
   * Resource: `flight`
   * Limit: `$500.00 USD`
   * Human Approval: False (Auto-approved under limit)
2. **document_access**:
   * Action: `read`
   * Resource: `document`
   * Limit: Unlimited
   * Human Approval: False

---

## 7. Authorization Decisions

Each request evaluated by AgentTrust returns one of four statuses:

1. **APPROVED**: Action complies with active permissions, signature verified, and risk score is acceptable. Agent may proceed.
2. **PENDING**: Action requires manual human operator approval (permission flag or high risk). Mobile push notification dispatched.
3. **REJECTED**: Action violates limits, unauthorized resource, or unauthenticated agent.
4. **EXPIRED**: Request in PENDING status timed out without human operator response.

---

## 8. Webhook Events & HMAC-SHA256 Signatures

Deliveries contain header `X-AgentTrust-Signature` formatted as `t={timestamp},v1={hex_hmac}`.

### Verifying Signatures in Python
```python
import hashlib, hmac

def verify_webhook(secret: str, raw_body: bytes, header_signature: str) -> bool:
    parts = dict(kv.split('=', 1) for kv in header_signature.split(','))
    timestamp, sig = parts['t'], parts['v1']
    expected = hmac.new(secret.encode(), f'{timestamp}.'.encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)
```

---

## 9. AgentTrust CLI Guide

```bash
# Configure CLI
agenttrust configure --api-key at_test_... --base-url https://api.agenttrust.example

# Generate Keypair
agenttrust keys generate --output-dir ./keys --name prod_agent

# Register Public Key
agenttrust keys register --agent-id agt_1234 --public-key-path ./keys/prod_agent_public.pem

# Authorize Action
agenttrust authorize --agent-id agt_1234 --action purchase --resource server --amount 120 --currency USD

# System Doctor & Diagnostics
agenttrust doctor
```

---

## 10. Python SDK Integration Guide

```python
from agenttrust import AgentTrust

client = AgentTrust('at_test_' + 'a' * 64, base_url='https://api.agenttrust.example')

# Unsigned authorization
res = client.authorize(
    agent_id='agt_assistant',
    action='purchase',
    resource='flight',
    amount=300.0,
    currency='USD',
    idempotency_key='order_9871',
)
print(res.status, res.reason)

# Cryptographically signed authorization
agent = client.agent(
    agent_id='agt_assistant',
    key_id='key_ag_9c28e47b85f1e403d12b0e9a',
    private_key_path='./keys/flight_bot_private.pem',
)
signed_res = agent.authorize(action='purchase', resource='flight', amount=300.0, currency='USD')
print(signed_res.status)
```

---

## 11. Node / TypeScript SDK Integration Guide

```typescript
import { AgentTrust } from '@agenttrust/sdk';

const client = new AgentTrust({
  apiKey: 'at_test_' + 'a'.repeat(64),
  baseUrl: 'https://api.agenttrust.example',
});

// Authorize action
const result = await client.authorize({
  agentId: 'agt_assistant',
  action: 'purchase',
  resource: 'flight',
  amount: 300,
  currency: 'USD',
});
console.log(result.status, result.reason);
```

---

## 12. Java SDK Integration Guide

```java
import com.agenttrust.AgentTrustClient;
import com.agenttrust.AuthorizationRequest;
import com.agenttrust.AuthorizationResult;
import java.math.BigDecimal;

AgentTrustClient client = new AgentTrustClient("at_test_...", "https://api.agenttrust.example", Duration.ofSeconds(10));

AuthorizationResult result = client.authorize(new AuthorizationRequest(
    "agt_assistant",
    "purchase",
    "flight",
    BigDecimal.valueOf(300.00),
    "USD",
    "order_123"
));
System.out.println("Decision: " + result.status());
```

---

## 13. API Logs, Diagnostics & Observability

Developers can inspect live or sandbox executions using:
* `GET /developer/logs?environment=sandbox&status=REJECTED`
* `GET /developer/logs/{request_id}`
* `agenttrust doctor` for local environment verification

---

## 14. Sandbox Scenarios Deep Dive

The sandbox includes 5 one-click scenario tests:
1. **Scenario 1 ($300 Flight)**: Evaluates normal approval within $500 limit -> `APPROVED`.
2. **Scenario 2 ($450 Hotel with Manual Approval)**: Evaluates permission policy requiring human approval -> `PENDING`.
3. **Scenario 3 ($700 Flight Exceeding Limit)**: Evaluates strict limit breach rejection -> `REJECTED`.
4. **Scenario 4 (Tampered Signature)**: Evaluates cryptographic defense against modified request bytes -> `INVALID_AGENT_SIGNATURE`.
5. **Scenario 5 (Replay Attack)**: Evaluates nonce reuse defense -> `REPLAY_DETECTED`.

---

## 15. Complete Machine-Readable Error Catalog

| Error Code | HTTP Status | Root Cause | Resolution |
| :--- | :--- | :--- | :--- |
| `INVALID_API_KEY` | 401 | Missing, malformed, or inactive API key. | Check key prefix (`at_test_` or `at_live_`) and status. |
| `FORBIDDEN` | 403 | Insufficient role permissions or tenant scope mismatch. | Check organization membership and user role. |
| `RATE_LIMIT_EXCEEDED`| 429 | Exceeded per-minute API request quota. | Implement exponential backoff or upgrade tier. |
| `INVALID_AGENT_SIGNATURE`| 401 | Cryptographic signature mismatch or corrupted payload. | Ensure exact body bytes are signed with matching private key. |
| `AGENT_SIGNATURE_REQUIRED`| 401 | Agent has registered signing keys, but headers omitted. | Supply Ed25519 signature headers (`X-Agent-*`). |
| `REPLAY_DETECTED` | 401 | Request nonce already consumed within timestamp window. | Generate unique cryptographic nonce per request. |
| `REQUEST_TIMESTAMP_INVALID`| 401 | Clock drift exceeded allowable window (> 300s). | Synchronize host clock with NTP. |
| `SIGNING_KEY_REVOKED` | 401 | The signing key has been explicitly revoked. | Rotate to a new active key. |
| `SIGNING_KEY_EXPIRED` | 401 | The signing key validity period elapsed. | Generate and register a new keypair. |
| `UNKNOWN_AGENT_SIGNATURE_VERSION` | 401 | Unsupported signature version in header. | Set `X-Agent-Signature-Version: v1`. |
| `PERMISSION_NOT_FOUND`| 404 | No active permission granted for action/resource. | Grant permission template to agent in portal. |
| `AMOUNT_EXCEEDED` | 403 | Request amount exceeds maximum authorized limit. | Request higher limit permission or submit for human review. |
| `IDEMPOTENCY_CONFLICT`| 409 | Reused idempotency key with different payload. | Use unique key per distinct operation. |

---

## 16. Production Readiness Checklist & Go-Live Procedures

Before requesting production access, developers must satisfy the 8-point checklist:
1. **Multi-Factor Authentication (MFA)**: Enabled on developer account.
2. **Organization Profile**: Organization name and billing information completed.
3. **Cryptographic Identity**: At least one active Ed25519 signing key registered.
4. **Webhook Endpoint**: Configured and verified with successful HMAC test event.
5. **SDK Integration Tested**: Verified using official Python, Node, or Java client.
6. **Sandbox Authorization Tested**: At least one successful authorization in sandbox.
7. **Security Contact**: Operational contact email specified.
8. **Appropriate Subscription Tier**: Organization subscribed to suitable plan.

Submit request via `POST /developer/production-access/request` or the Developer Portal UI.

