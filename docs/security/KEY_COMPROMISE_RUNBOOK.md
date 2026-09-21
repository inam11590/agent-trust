# Incident Response Runbook: Cryptographic Key Compromise

This runbook defines the emergency procedures to follow when an asymmetric signing key (Agent, Gateway, Issuer, or Control Plane) is compromised or suspected of unauthorized exposure.

---

## Key Compromise Invariants

1. **Instant Signing Halt**: A key marked `COMPROMISED` must immediately cease all new signature operations.
2. **Instant Verification Failure**: Any incoming ATP message or ATC credential signed with a compromised key must be rejected with HTTP 401 / `KEY_COMPROMISED`.
3. **No Grace Period**: Unlike normal key rotation (which maintains a transition window), compromised keys receive **zero grace period**.

---

## Step-by-Step Emergency Workflow

```
[ Step 1: Declare Key Compromise Event ]
                   │
                   ▼
[ Step 2: Invoke key_provider.revoke(key_id, compromised=True) ]
                   │
                   ▼
[ Step 3: Broadcast Instant Revocation via Redis / Webhooks ]
                   │
                   ▼
[ Step 4: Issue Replacement Key for Purpose ]
                   │
                   ▼
[ Step 5: Reprovision Agent / Gateway with New Key ]
                   │
                   ▼
[ Step 6: Identify & Invalidate Compromised Assertions ]
```

### Phase 1: Immediate Triage (0 to 10 Minutes)

1. **Invoke the Key Compromise API**:
   ```bash
   curl -X POST "https://api.agenttrust.internal/v1/security/keys/<KEY_ID>/compromise" \
     -H "Authorization: Bearer <SECURITY_ADMIN_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"reason": "Private key exposed in public artifact"}'
   ```
   Or via CLI:
   ```bash
   agenttrust security keys compromise <KEY_ID> --reason "Suspected exfiltration"
   ```

2. **Verify Provider State**:
   Confirm that `key_provider.status(key_id).status == KeyStatus.COMPROMISED`.
   Verify that any attempt to call `key_provider.sign(..., key_id)` throws `KeyCompromisedError`.

3. **Purge Verifier Caches**:
   Ensure all Gateways, Sidecars, and Control Plane nodes flush cached public keys for `<KEY_ID>`.

---

### Phase 2: Key Replacement & Reprovisioning (10 to 30 Minutes)

1. **Generate Replacement Key for the Specific Purpose**:
   ```bash
   agenttrust security keys rotate <KEY_ID> --emergency
   ```
2. **Distribute New Public Key**:
   Distribute the newly generated public key to Trust Registries, Gateways, and peer agents.
3. **Re-attest Gateway / Agent**:
   For Enterprise Gateways or Agents whose keys were revoked, trigger re-attestation to bind the agent identity to the newly generated key.

---

### Phase 3: Blast Radius Investigation (30 to 120 Minutes)

1. Query all ATP requests and ATC credentials signed by `<KEY_ID>` during the suspected window:
   ```sql
   SELECT id, agent_id, endpoint, created_at 
   FROM agent_audit_logs 
   WHERE signing_key_id = '<KEY_ID>' 
     AND created_at >= '<SUSPECTED_COMPROMISE_TIME>';
   ```
2. Invalidate any active delegation chains or cross-organization trust grants authorized by the compromised key.
3. Notify affected cross-organization partners and trust registry peers.
