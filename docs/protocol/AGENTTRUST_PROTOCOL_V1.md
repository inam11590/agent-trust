# AgentTrust Protocol Specification (ATP/1.0)

> **Notice**: AgentTrust Protocol (ATP/1.0) is an internal AgentTrust open protocol specification designed for secure, auditable, and zero-implicit-trust multi-agent interaction. It is not an international or industry standard.

---

## 1. Protocol Architecture & Philosophy

The AgentTrust Protocol (ATP/1.0) defines a vendor-neutral, LLM-agnostic communication standard for AI agents operating across security boundaries.

### Design Principles
1. **Zero-Implicit-Trust**: No agent or organization is trusted by default. Every communication must be authenticated, authorized, policy-checked, and logged.
2. **Framework & Model Agnostic**: ATP/1.0 does not depend on OpenAI, Anthropic, Google, Microsoft, LangChain, CrewAI, AutoGen, or any single model provider. It acts as an ambient security envelope around any AI engine.
3. **Decoupled Privacy Boundaries**: Organizations only share public descriptors and intentionally published capabilities. Internal policies, team members, risk weights, and API keys are never disclosed.
4. **End-to-End Cryptographic Integrity**: All requests are signed locally by the calling agent using Ed25519. The AgentTrust Gateway verifies signatures, enforces policies, and issues a short-lived Gateway Attestation token before routing.

---

## 2. Agent Addressing

An AgentTrust agent is identified globally by an immutable URI scheme:

```
atp://<organization_public_id>/<agent_public_id>
```

### Examples:
- `atp://org_skytravel/agt_travel` — Travel Assistant agent belonging to SkyTravel.
- `atp://org_hotelcorp/agt_hotel` — Hotel Booking agent belonging to HotelCorp.

> [!NOTE]
> An agent address identifies the recipient or sender. It does **not** constitute authentication by itself; every message must carry an accompanying cryptographic signature (`ATP-SIG/1`).

---

## 3. Agent Descriptors & Public Discovery

Organizations publish safe descriptors for external discovery without exposing sensitive internals.

### Agent Descriptor Schema
```json
{
  "protocol": "ATP/1.0",
  "agent_id": "agt_hotel",
  "organization_id": "org_hotelcorp",
  "name": "HotelCorp Booking Agent",
  "description": "Automated hotel availability search and room reservation agent",
  "status": "ACTIVE",
  "capabilities": [
    "hotel.search@1.0",
    "hotel.reserve@1.0"
  ]
}
```

### Discovery Endpoints
- `GET /atp/v1/agents/{agent_id}`: Returns the public Agent Descriptor.
- `GET /atp/v1/agents/{agent_id}/capabilities`: Returns the versioned capability manifest.

---

## 4. Capability Manifest & Schemas

Capabilities declare what an agent *may* be asked to do. **A capability does NOT grant permission.** Both capability registration and bilateral authorization must pass before an action is executed.

### Manifest Example
```json
{
  "protocol": "ATP/1.0",
  "agent": "atp://org_hotelcorp/agt_hotel",
  "capabilities": [
    {
      "name": "hotel.search",
      "version": "1.0",
      "description": "Query hotel room availability and rates"
    },
    {
      "name": "hotel.reserve",
      "version": "1.0",
      "description": "Reserve a hotel room with payment guarantee",
      "input_schema": {
        "type": "object",
        "required": ["hotel_id", "room_type", "check_in", "check_out", "amount", "currency"],
        "properties": {
          "hotel_id": { "type": "string" },
          "room_type": { "type": "string" },
          "check_in": { "type": "string", "format": "date" },
          "check_out": { "type": "string", "format": "date" },
          "guests": { "type": "integer", "minimum": 1 },
          "amount": { "type": "number", "minimum": 0 },
          "currency": { "type": "string", "pattern": "^[A-Z]{3}$" }
        }
      },
      "output_schema": {
        "type": "object",
        "required": ["reservation_id", "status"],
        "properties": {
          "reservation_id": { "type": "string" },
          "status": { "type": "string", "enum": ["CONFIRMED", "PENDING", "FAILED"] }
        }
      }
    }
  ]
}
```

---

## 5. Protocol Message Envelope

All communications pass through a standardized, deterministic JSON envelope.

```json
{
  "atp_version": "1.0",
  "message_id": "msg_01h7x89abcde0123456789ab",
  "message_type": "request",
  "source": {
    "organization_id": "org_skytravel",
    "agent_id": "agt_travel"
  },
  "target": {
    "organization_id": "org_hotelcorp",
    "agent_id": "agt_hotel"
  },
  "capability": "hotel.reserve@1.0",
  "timestamp": "2026-09-19T10:00:00Z",
  "nonce": "nonce_7f8e9d0a1b2c3d4e5f6a7b8c",
  "idempotency_key": "idem_booking_98765",
  "payload": {
    "hotel_id": "hotel_grand_hyatt",
    "room_type": "deluxe_king",
    "check_in": "2026-10-01",
    "check_out": "2026-10-05",
    "guests": 2,
    "amount": 450.00,
    "currency": "USD"
  }
}
```

### Supported Message Types
- `request`: An agent requesting execution of a capability.
- `response`: Target agent replying with results after Gateway authorization.
- `error`: Explains authorization, protocol, or execution failure.
- `status`: Querying asynchronous progress of an in-flight request.

---

## 6. Cryptographic Signing Profile: ATP-SIG/1

Every protected ATP request requires an Ed25519 signature generated across a deterministic canonical string.

### Canonical String Format
```
ATP-SIG/1
<MESSAGE_ID>
<MESSAGE_TYPE>
<SOURCE_ORG_ID>
<SOURCE_AGENT_ID>
<TARGET_ORG_ID>
<TARGET_AGENT_ID>
<CAPABILITY>
<TIMESTAMP_ISO8601_UTC>
<NONCE>
<SHA256_PAYLOAD_HEX>
```

### Required Protocol Headers
* `X-ATP-Version`: `1.0`
* `X-ATP-Message-ID`: `msg_...`
* `X-ATP-Key-ID`: `key_ag_...`
* `X-ATP-Timestamp`: ISO8601 UTC timestamp (must be within $\pm 300$ seconds).
* `X-ATP-Nonce`: Unique per-request nonce (enforced atomically against replays).
* `X-ATP-Signature`: Base64 Ed25519 signature over canonical representation.
* `X-ATP-Signature-Version`: `ATP-SIG/1`

---

## 7. Short-Lived Gateway Attestation

When an ATP message is approved, the Gateway generates a signed attestation token attached to the outbound request:

```json
{
  "attestation_id": "atp_attest_01h8abcde",
  "gateway_id": "gateway_primary",
  "request_id": "req_01h8abcdef",
  "source_agent": "atp://org_skytravel/agt_travel",
  "target_agent": "atp://org_hotelcorp/agt_hotel",
  "capability": "hotel.reserve@1.0",
  "decision": "APPROVED",
  "issued_at": "2026-09-19T10:00:01Z",
  "expires_at": "2026-09-19T10:01:01Z"
}
```
* **Attestation TTL**: 60 seconds (strictly short-lived, never permanent).
* **Gateway Signature**: Signed with the Gateway's private Ed25519 key so target endpoints can verify authenticity without needing access to source organization credentials.

---

## 8. Anti-Replay and Idempotency

* **Nonce**: Cryptographic single-use token preventing network replay attacks. Tracked in Redis/PostgreSQL with automatic TTL.
* **Idempotency Key**: Business transaction deduplication token ensuring identical API operations return cached results without double charging or duplicate actions.
