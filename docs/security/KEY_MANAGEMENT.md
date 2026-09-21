# AgentTrust Cryptographic Key Lifecycle & KMS Architecture

This document describes the key lifecycle, purpose separation, KMS/HSM abstraction, rotation protocols, and compromised key handling in AgentTrust.

---

## 1. Key Purpose Separation

To prevent algorithm confusion and cross-protocol privilege escalation, cryptographic keys are strictly partitioned by designated purpose:

- `AGENT_SIGNING`: Used by autonomous agents to cryptographically sign ATP/1.0 messages and execution payloads.
- `GATEWAY_SIGNING`: Used by Enterprise Gateways and Sidecars to authenticate gateway-level assertions and proxy actions.
- `CONTROL_PLANE_SIGNING`: Used by the central Control Plane to sign configuration bundles, topology manifests, and routing directives.
- `CREDENTIAL_ISSUER_SIGNING`: Used to issue verifiable ATC/1.0 delegation tokens and cryptographic identity credentials.
- `WEBHOOK_SIGNING`: Used to generate HMAC/Ed25519 signatures on outgoing event delivery payloads.
- `APPROVAL_SIGNING`: Used in multi-party approval workflows to witness stakeholder signatures.

A key provisioned for `WEBHOOK_SIGNING` can never be substituted to sign an `AGENT_SIGNING` ATP message or issue an `ATC/1.0` token.

---

## 2. Key Lifecycle States

Every cryptographic key exists in exactly one state:

```
 [PENDING] 
     │
     ▼
  [ACTIVE] ───────────────┐
     │                    │
     ▼ (Rotation)         ▼ (Emergency Compromise)
 [ROTATING]          [COMPROMISED]
     │
     ▼
 [RETIRED] ──► [REVOKED]
```

1. **PENDING**: Key generated in KMS/keystore, awaiting activation and public key distribution.
2. **ACTIVE**: Authoritative key used for signing new payloads and verifying existing ones.
3. **ROTATING**: A new key has been issued; this key is retained strictly for verification during the migration window.
4. **RETIRED**: No longer used for signing. Can only verify historical messages within audit retention rules.
5. **REVOKED**: Invalidated due to planned deprecation or lifecycle expiration. All verification attempts reject this key.
6. **COMPROMISED**: **Emergency state**. Signing is instantaneously blocked. Verification fails immediately with `KEY_COMPROMISED`.

---

## 3. Abstract KeyProvider & KMS/HSM Foundation

Private keys must never leave the security boundary of the provider:

```python
class KeyProvider(ABC):
    @abstractmethod
    def sign(self, data: bytes, key_id: str) -> bytes:
        """Sign data using the specified key ID without exporting private key material."""
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, key_id: str) -> bool:
        """Verify signature against the specified key."""
        pass

    @abstractmethod
    def get_public_key(self, key_id: str) -> str:
        """Return public key in standard PEM or Base64 format."""
        pass

    @abstractmethod
    def rotate(self, key_id: str) -> KeyMetadata:
        """Issue a new key for this purpose, marking old key as ROTATING."""
        pass

    @abstractmethod
    def revoke(self, key_id: str, reason: str, compromised: bool = False) -> None:
        """Revoke key. If compromised=True, invalidate instantaneously across all nodes."""
        pass

    @abstractmethod
    def status(self, key_id: str) -> KeyMetadata:
        """Return public metadata (ID, purpose, status, algorithm, timestamps)."""
        pass
```

### Provider Classes:
- **LocalKeyProvider**: In-memory software Ed25519 key manager used for local unit testing and development.
- **MockKmsKeyProvider**: KMS emulator providing identical interfaces to AWS KMS or GCP Cloud KMS, clearly labeled `TEST / MOCK ONLY`.
- **Cloud KMS Driver**: In production, delegates `sign()` and `verify()` calls directly to hardware-backed KMS endpoints (e.g. AWS KMS `kms:Sign`, GCP `projects.locations.keyRings.cryptoKeys.asymmetricSign`).

---

## 4. Key Compromise Protocol

When an alert or administrator flags a key as compromised:
1. Provider state updates to `COMPROMISED`.
2. Any subsequent `sign()` invocation raises `KeyCompromisedError` immediately.
3. `verify()` calls return `False` and log `SECURITY_EVENT: SIGNATURE_REJECTED_KEY_COMPROMISED`.
4. Event is broadcast to Redis pub/sub and recorded in the immutable security audit log.
