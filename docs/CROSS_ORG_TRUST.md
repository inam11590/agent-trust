# Secure Cross-Organization Agent-to-Agent Trust

## 1. Overview and Core Philosophy

In modern multi-agent systems, AI agents belonging to independent organizations must frequently collaborate—for instance, an enterprise travel agent from Organization A (e.g., SkyTravel) booking accommodations with a reservation agent from Organization B (e.g., HotelCorp).

AgentTrust implements **Step 20: Secure Cross-Organization Agent-to-Agent Trust** grounded in strict **Zero-Implicit-Trust**:
- **Default is NO TRUST**: Organizations have zero implicit trust. Even if both organizations are verified customers of AgentTrust, their agents cannot communicate or invoke actions on each other without an explicit, mutually agreed trust relationship.
- **Directional Enforcement**: Trust is strictly directional. If Organization A trusts Organization B, that gives Organization B no permission to execute actions against Organization A.
- **Mutual Agreement**: Trust relationships are requested by one organization and must be explicitly accepted by the partner organization before activation.
- **Strongest Restriction Always Wins**: When an action is requested, the system computes the intersection of constraints across:
  1. Source agent root permissions & delegation limits.
  2. Source organization outbound trust policies.
  3. Bilateral agreed trust relationship limits.
  4. Target organization inbound target policies.
  5. Target agent registered capability limits.
  The narrowest amount limit and the strictest approval stage rule unconditionally.
- **Dual Decoupled Privacy-Preserving Audit Logs**: Each organization receives only its own audit log. Source org logs outbound activity; target org logs inbound activity. Internal policies, team members, risk scores, and private keys never cross organizational boundaries.
- **Immediate Cascade Revocation**: Either party can unilaterally revoke the trust relationship at any time. Revocation takes effect instantly, terminating all active external connections and rejecting any pending authorizations.

---

## 2. Cryptographic Request Signing (v2 Protocol)

Every cross-organization agent authorization request MUST be cryptographically bound to both organizations and both agents using Ed25519 asymmetric signatures.

### Canonical v2 String Format

The canonical string binds the signature version (`v2`), the HTTP method, request path, source/target organizations, source/target agents, signing key ID, ISO8601 UTC timestamp, cryptographic nonce, and the SHA-256 digest of the raw HTTP request body:

```
v2
<HTTP_METHOD>
<REQUEST_PATH>
<SOURCE_ORGANIZATION_UUID>
<TARGET_ORGANIZATION_UUID>
<SOURCE_AGENT_UUID>
<TARGET_AGENT_UUID>
<SIGNING_KEY_ID>
<TIMESTAMP_ISO8601_UTC>
<NONCE>
<SHA256_BODY_HEX>
```

### Required HTTP Headers
- `X-Agent-ID`: Source Agent UUID.
- `X-Agent-Key-ID`: Key identifier (e.g. `key_ag_...`).
- `X-Agent-Timestamp`: UTC timestamp (valid within 5 minutes / 300 seconds).
- `X-Agent-Nonce`: Cryptographic nonce (enforced atomically against replays).
- `X-Agent-Signature`: Base64-encoded Ed25519 signature of the canonical v2 string.
- `X-Agent-Signature-Version`: Must equal `"v2"`.
- `X-Source-Org-ID`: Source Organization UUID.
- `X-Target-Org-ID`: Target Organization UUID.
- `X-Target-Agent-ID`: Target Agent UUID.

---

## 3. The 11-Step Evaluation Pipeline

When an agent requests authorization via `/api/v1/cross-org/authorize`, AgentTrust evaluates the following 11-step pipeline:

```
[1. Cryptographic v2 Signature Verification]
                │
[2. Source & Target Organization Status Check (Active, Non-Deleted)]
                │
[3. Source & Target Agent Status Check (Active, Owned by respective orgs)]
                │
[4. External Target Policy Check (Source org allows calling target org)]
                │
[5. Source Agent Permission & Delegation Validation]
                │
[6. Trust Relationship Validation (Directional, Active, Non-Expired)]
                │
[7. External Agent Connection Verification (EAC Active)]
                │
[8. Action & Resource Whitelist Verification (Agreed Trust Policy)]
                │
[9. Strongest Restriction Computation (Narrowest Max Amount, Currency Match)]
                │
[10. Risk Engine Evaluation (Anti-Velocity, Pattern Checks)]
                │
[11. Multi-Party Approval Determination (SOURCE, TARGET, BOTH)]
```

---

## 4. Multi-Party Approvals

Cross-organization policies support three approval requirements:
- `SOURCE`: Only administrators of the calling organization must review and approve.
- `TARGET`: Only administrators of the receiving organization must review and approve.
- `BOTH`: Both organizations must independently review and approve before the action status transitions from `PENDING` to `APPROVED`.

If either party rejects a pending request, the entire authorization request is immediately `REJECTED`. Neither organization can override the other's rejection.

---

## 5. Partner Directory & Discovery

Organizations can publish an **Organization Public Profile** to the directory containing:
- Display name and public description.
- Verification badge (`is_verified`).
- List of published capabilities (e.g. `flight_booking`, `hotel_reservation`, `currency_exchange`).
- Public contact details.

Other organizations can search the directory and initiate a trust request without exposing any private agent details or internal policy rules.
