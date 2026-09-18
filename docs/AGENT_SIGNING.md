# Agent signing (v1)

Agent signing proves that a developer application holding an agent's **private key** sent an unchanged request. AgentTrust stores only the matching **public key**. An API key still identifies the developer or organization; the signature identifies the particular agent. A valid signature does not grant permission by itself. Permission, risk, and organization rules still decide the result.

This first version uses **Ed25519** through established libraries: Python `cryptography`, Node's `node:crypto`, and Java 21's Ed25519 provider. Ed25519 has small keys and deterministic signatures and is supported by all three existing SDK languages. No signature mathematics is implemented by AgentTrust.

## Register a public key

Generate a private key on the developer machine. For example, with OpenSSL:

```sh
openssl genpkey -algorithm Ed25519 -out agent-private.pem
```

Protect that file with operating-system permissions; exclude it from Git. For production, prefer a managed secret store or KMS/HSM where it can sign without exporting the key. AgentTrust cannot recover the private key. The SDKs read a local PKCS#8 PEM private key and never send it to the server.

Export the raw 32-byte public key as base64. The Python `cryptography` library can do this without sending the private key anywhere:

```python
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
key = serialization.load_pem_private_key(Path("agent-private.pem").read_bytes(), password=None)
raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print(base64.b64encode(raw).decode())
```

Sign in to AgentTrust, open **Agents → Agent details → Signing keys**, and paste only the public key. The API is `POST /agents/{agent_uuid}/signing-keys` with `{"algorithm":"Ed25519","public_key":"<base64 of 32 raw bytes>","expires_at":null}`. The response includes a public `key_id`, status, and SHA-256 fingerprint. Owner/admin access and recent identity verification are required. A private-key field is rejected. The same public key cannot be assigned to a second agent. At most three active or rotating keys are allowed by default.

## Signed authorization

The Python SDK is the shortest example:

```python
from agenttrust import AgentTrust

client = AgentTrust(api_key="<API key>", base_url="https://your-agenttrust-api.example")
travel = client.agent(agent_id="agt_<24 lowercase hex>", key_id="key_ag_<24 lowercase hex>",
                      private_key_path="/secure/path/agent-private.pem")
result = travel.authorize(action="purchase", resource="flight", amount=420, currency="USD")
```

The Node SDK uses `client.agent({ agentId, keyId, privateKeyPath }).authorize(...)`. The Java SDK uses `client.agent(agentId, keyId, Path.of(...)).authorize(request)`. Existing API-key calls remain available for agents **without** a registered signing key during migration. Once a key is registered for an agent, unsigned developer authorization for that agent is rejected. The user-authenticated console `/authorize` route remains a separate human tool.

The signed endpoint is `POST /api/v1/authorize`. It requires `X-API-Key` plus these headers:

| Header | Value |
| --- | --- |
| `X-Agent-ID` | Public `agt_...` identifier; must match the JSON body |
| `X-Agent-Key-ID` | Registered `key_ag_...` identifier |
| `X-Agent-Timestamp` | UTC seconds, e.g. `2026-09-16T10:00:00Z` |
| `X-Agent-Nonce` | `nonce_` plus 32 lowercase hex characters from 16 random bytes |
| `X-Agent-Signature` | Base64 of the 64-byte Ed25519 signature |
| `X-Agent-Signature-Version` | Exactly `v1` |

The **exact bytes sent on the wire** are hashed with SHA-256. JSON key order and spaces are not normalized. Sign the same serialized byte buffer that the HTTP client sends. There is no request query string in v1; the only signed endpoint has a fixed path. The canonical message is ASCII text, in this exact order, with one LF after **every** line including the last:

```text
v1
POST
/api/v1/authorize
<agent ID>
<key ID>
<timestamp>
<nonce>
<lowercase hexadecimal SHA-256 of exact body bytes>
```

The method and path prevent reuse on another operation. The agent and key IDs prevent header substitution. The body hash detects a changed amount or any other byte change. Unknown versions fail. The server accepts timestamps within ±300 seconds by default (`AGENT_SIGNATURE_CLOCK_WINDOW_SECONDS`). Body size is capped at 65,536 bytes by default (`AGENT_SIGNED_BODY_MAX_BYTES`).

After signature verification, the server atomically records the key ID and nonce hash. Redis uses `SET ... NX EX` with a TTL longer than the full possible timestamp acceptance period. PostgreSQL also enforces a unique nonce record, so early Redis eviction cannot permit replay. If configured Redis is unavailable, the request fails closed. Invalid signatures never reserve a nonce, preventing unauthenticated cache poisoning. Expired PostgreSQL nonce records are cleaned in bounded worker batches and opportunistically. No raw signature or private key is saved. The final authorization audit or pending request keeps only `signature_verified`, `signing_key_id`, and `signature_version`.

## Rotate, revoke, and recover

To rotate, generate a **new** private/public pair locally and call `POST /agents/{agent_uuid}/signing-keys/{old_key_id}/rotate` with the new public key. Both keys work temporarily; the old one is marked `ROTATING`. Deploy the new private key, then call `POST /agents/{agent_uuid}/signing-keys/{old_key_id}/revoke`. A revoked key fails immediately on subsequent requests. Optional key expiry is enforced at verification; the worker queues a warning seven days beforehand by default. The dashboard shows the key status, last use, and expiry.

If a private key may have leaked: revoke it immediately, create a new pair locally, register the new public key, deploy the new private key securely, and review security events and audit logs. API-key revocation is separate; do that as well if the API key may have leaked. Never copy the private key into a support ticket, chat, log, or dashboard.

The shared [test-only vector](test-vectors/agent-signing-v1.properties) fixes a deterministic test key, body, canonical message, and signature. It exists only for interoperability tests and must never be used for a real agent. Python, Node, and Java tests compare their output to this vector.

## Operational limits

Production Redis should use a non-evicting policy; the supplied Compose file uses `noeviction`. PostgreSQL remains the authoritative replay guard. The legacy unsigned path for agents without a signing key is a migration window, not a guarantee that every previously registered agent is already cryptographically identified. Register keys for all agents and reject unsigned clients before making that claim. HTTPS, secure private-key storage, clock synchronization, Redis/PostgreSQL health, and external security review are deployment responsibilities.

## Local checks

From the repository root, with PostgreSQL running and `backend/.env` configured:

```powershell
cd backend
.\.venv\Scripts\alembic.exe upgrade head
$env:RUN_DATABASE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q
cd ..\web
npm run lint
npm run typecheck
npm test
npm run build
cd ..\mobile
flutter analyze
flutter test
```

Run SDK checks from `sdk/python` with `PYTHONPATH=src` and `python -m unittest discover tests`; from `sdk/node` with `npm test`; and from `sdk/java` with Java 21: `javac -d build src/main/java/com/agenttrust/*.java src/test/java/com/agenttrust/*.java` then `java -cp build com.agenttrust.ClientTest`. From the repository root, run `python scripts/check_private_keys.py` and `python scripts/benchmark_agent_signing.py` (the latter needs `cryptography`). These tests use only the explicitly marked test vector, never production keys.
