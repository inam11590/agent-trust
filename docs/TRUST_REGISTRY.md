# AgentTrust Trust Registry Guide

This guide explains the AgentTrust Trust Registry in simple English.

---

## 1. What is the Trust Registry?

The **Trust Registry** is a secure directory where organizations publish their public identity and verification keys. It allows any verifier to check whether an issuer is genuine, active, and authorized to issue credentials for autonomous AI agents.

The Trust Registry stores **only public identity information**:
- Issuer name and public identifier (`iss_...`)
- Organization identifier (`org_...`)
- Active and past public signing keys
- Status (`ACTIVE`, `SUSPENDED`, `REVOKED`)

It does **not** store private company information, passwords, or private keys.

---

## 2. What is an Issuer?

An **Issuer** is an organization's identity authority that signs credentials for its AI agents.
For example, HotelCorp might have an issuer called `HotelCorp Agent Issuer` (`iss_hotelcorp_primary`).

An issuer:
- Has an Ed25519 signing keypair.
- Can only issue credentials for agents registered to its own organization.
- Can be `ACTIVE`, `SUSPENDED`, or `REVOKED` by organization owners or administrators.

---

## 3. What is a Credential?

A **Credential** is a digitally signed document that proves specific claims about an AI agent.
For example:
- "This Agent belongs to HotelCorp." (`AgentIdentityCredential`)
- "This Agent is registered for `hotel.search@1.0`." (`AgentCapabilityCredential`)

### What a Credential Proves:
- The claims inside the credential were signed by an authorized issuer.
- The claims have not been tampered with or modified.
- The credential was issued at a specific time and is not expired or revoked.

### What a Credential DOES NOT Prove:
- It does **not** mean the agent has permission to perform an action.
- It does **not** replace organization trust or authorization.
- It does **not** guarantee the agent will behave safely.
- It is **not** an API key.

---

## 4. How are Credentials Verified?

When an agent presents a credential to the AgentTrust Gateway, the gateway checks:
1. **Issuer Active?**: Looks up the issuer in the Trust Registry.
2. **Signature Valid?**: Uses the issuer's public key to verify the Ed25519 signature.
3. **Not Expired?**: Checks that the current time is between `not_before` and `expires_at`.
4. **Not Revoked?**: Checks the Credential Status Registry.
5. **Subject Match?**: Ensures the credential belongs to the agent sending the request.
6. **Then Normal Authorization**: Only after the credential passes verification does the gateway evaluate permissions, policies, risk scores, and human approvals.

---

## 5. Key Rotation & Revocation

- **Key Rotation**: Issuers can generate a new signing key (`Key B`) while keeping `Key A` valid for existing credentials. New credentials will be signed with `Key B`.
- **Key Revocation**: If a private key is compromised, revoking it immediately invalidates all credentials signed by that key.
- **Credential Revocation**: An administrator can immediately revoke an individual credential at any time via the API or dashboard.
