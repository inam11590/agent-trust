# AgentTrust Verifiable Agent Credentials Specification (ATC/1.0)

Version: `ATC/1.0`  
Signing Profile: `ATC-SIG/1`  
Algorithm: `Ed25519`

---

## 1. Abstract

The **AgentTrust Verifiable Agent Credentials (ATC/1.0)** specification defines a vendor-neutral, cryptographically verifiable credential format for autonomous AI agents. Credentials attest to specific, machine-verifiable claims issued by authorized organization identity issuers—such as an agent's organizational membership or registered published capabilities.

> **CRITICAL SECURITY INVARIANT**  
> A credential asserts cryptographic authenticity of claims by an issuer. **A credential NEVER equals permission, trust, or authorization.** Credential verification occurs prior to evaluation by the AgentTrust authorization, trust, risk, policy, and human-in-the-loop approval engines.

---

## 2. Terminology

- **Issuer (`iss_...`)**: The trusted identity authority that cryptographically signs a credential using an active Ed25519 key.
- **Subject (`agt_...`)**: The specific AI agent described by the credential.
- **Holder**: The agent or gateway presenting the credential during an ATP/1.0 protocol exchange.
- **Verifier**: The AgentTrust Gateway or receiving agent validating the signature, temporal bounds, and revocation status of the credential.
- **Credential (`cred_...`)**: The tamper-evident JSON object containing the claims, metadata, and cryptographic proof.

---

## 3. Credential Types

Step 22 defines two primary credential types:

1. **`AgentIdentityCredential`**:
   - Proves that an agent is officially registered under an organization according to the issuer.
   - Claims:
     - `organization_id`: Organization public identifier.
     - `organization_membership`: Boolean flag (`true`).
     - `agent_identifier`: Agent public slug or ID.
2. **`AgentCapabilityCredential`**:
   - Attests that the issuer confirms the agent has been published for specific registered capabilities.
   - Claims:
     - `capabilities`: Array of capability descriptors matching Step 21 capabilities (e.g., `["hotel.search@1.0", "hotel.reserve@1.0"]`).

---

## 4. Credential Wire Format (JSON)

```json
{
  "credential_version": "ATC/1.0",
  "credential_id": "cred_01j9a8b7c6d5e4f3a2b1c0d9e8",
  "credential_type": "AgentIdentityCredential",
  "issuer": "iss_hotelcorp_primary",
  "subject": {
    "organization_id": "org_hotelcorp",
    "agent_id": "agt_hotel_booking"
  },
  "environment": "production",
  "issued_at": "2026-09-19T12:00:00Z",
  "not_before": "2026-09-19T12:00:00Z",
  "expires_at": "2026-10-19T12:00:00Z",
  "claims": {
    "organization_membership": true,
    "agent_identifier": "agt_hotel_booking"
  },
  "proof": {
    "type": "ATC-SIG/1",
    "algorithm": "Ed25519",
    "key_id": "iss_key_hotelcorp_01",
    "signature": "base64-encoded-signature=="
  }
}
```

---

## 5. Canonicalization & Signature (`ATC-SIG/1`)

To ensure deterministic, cross-language signature generation and verification across Python, TypeScript/Node.js, and Java, `ATC-SIG/1` canonicalizes the security-critical fields into a 12-line ASCII string separated by Unix newlines (`\n`) and terminated with a trailing newline:

```
ATC-SIG/1\n
{credential_version}\n
{credential_id}\n
{issuer_id}\n
{subject_organization_id}\n
{subject_agent_id}\n
{credential_type}\n
{issued_at}\n
{not_before}\n
{expires_at}\n
{environment}\n
{claims_sha256}\n
```

### Notes:
- `{not_before}`: Formatted as ISO-8601 UTC string, or empty string `""` if not specified.
- `{claims_sha256}`: The lowercase hexadecimal SHA-256 digest of the canonical JSON claims string, formatted with sorted keys and no whitespace (`separators=(',', ':')`).

---

## 6. Verification Flow & Machine-Readable Error Codes

A verifier MUST execute the following sequence:

1. **Schema & Version**: Ensure `credential_version == "ATC/1.0"`. Else fail with `CREDENTIAL_SCHEMA_UNSUPPORTED`.
2. **Temporal Bounds**:
   - If current time `< not_before - 30s skew`: Fail with `CREDENTIAL_NOT_YET_VALID`.
   - If current time `> expires_at + 30s skew`: Fail with `CREDENTIAL_EXPIRED`.
3. **Issuer Status**: Lookup issuer in Trust Registry.
   - If not found: Fail with `CREDENTIAL_ISSUER_UNKNOWN`.
   - If `status == SUSPENDED`: Fail with `CREDENTIAL_ISSUER_SUSPENDED`.
   - If `status == REVOKED`: Fail with `CREDENTIAL_ISSUER_REVOKED`.
4. **Signing Key**:
   - If key revoked or unknown: Fail with `CREDENTIAL_SIGNING_KEY_REVOKED`.
5. **Cryptographic Proof**: Verify Ed25519 signature over canonical bytes.
   - If invalid: Fail with `CREDENTIAL_SIGNATURE_INVALID`.
6. **Revocation Registry**: Check credential revocation status.
   - If revoked: Fail with `CREDENTIAL_REVOKED`.
7. **Subject & Organization Validation**:
   - If subject agent does not exist or is inactive: Fail with `CREDENTIAL_SUBJECT_INVALID`.
   - If claims do not match registered metadata: Fail with `CREDENTIAL_CLAIM_INVALID`.
8. **Environment Isolation**:
   - If `environment == "sandbox"` and verification occurs in production context: Fail with `SANDBOX_CREDENTIAL_IN_PRODUCTION`.
