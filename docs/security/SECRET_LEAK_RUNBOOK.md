# Incident Response Runbook: Secret Leakage & Exposure

This runbook guides engineers through the rapid containment, revocation, and remediation of leaked credentials in AgentTrust.

---

## Severity Assessment

- **CRITICAL**: Leaked `SECRET_KEY`, Database root password, Master KMS credentials, or Control Plane signing key.
- **HIGH**: Leaked Agent API key, Webhook signing key, or Redis password.
- **MEDIUM**: Leaked test credential or expired staging token.

---

## Step-by-Step Containment Workflow

```
[ Step 1: Detect & Confirm Leak ]
               │
               ▼
[ Step 2: Instant Revocation in Store ]
               │
               ▼
[ Step 3: Evict Local Caches (SecretCache.refresh_secret) ]
               │
               ▼
[ Step 4: Issue Replacement Secret ]
               │
               ▼
[ Step 5: Rolling Restart / Hot-Reload of Services ]
               │
               ▼
[ Step 6: Post-Incident Audit & Forensics ]
```

### Phase 1: Immediate Containment (T + 0 to 15 Minutes)

1. **Identify Leaked Credential Identifier**:
   Locate the specific credential ID, secret name, or API key prefix leaked in logs, public commits, or third-party disclosures.

2. **Revoke the Leaked Secret Immediately**:
   - **For API Keys**:
     ```bash
     agenttrust security api-key revoke --key-id <KEY_ID> --reason "Compromise disclosure"
     ```
   - **For Database Credentials**:
     Alter user password in PostgreSQL and rotate in Vault/Secrets Manager.
   - **For Central Application Secrets**:
     Update secret value in SecretProvider and trigger cache invalidation:
     ```python
     secret_provider.refresh_secret("SECRET_KEY")
     ```

3. **Purge Secret Caches Across Fleet**:
   Send cache invalidation signal via Redis pub/sub or trigger zero-downtime rolling restart of API and worker pods.

---

### Phase 2: Audit & Forensics (T + 15 to 60 Minutes)

1. **Review Audit Logs for Unauthorized Usage**:
   Query audit logs for any actions performed using the leaked key between the estimated leak timestamp and revocation:
   ```sql
   SELECT * FROM security_events 
   WHERE actor_id = '<COMPROMISED_KEY_OR_USER>' 
     AND created_at >= '<LEAK_START_TIMESTAMP>'
   ORDER BY created_at ASC;
   ```
2. **Inspect External Calls & Data Access**:
   Verify whether unauthorized delegates, configuration changes, or exfiltration occurred.
3. **Invalidate Sessions**:
   If user tokens or session secrets were exposed, invalidate all active refresh tokens and JWT sessions across the organization.

---

### Phase 3: Post-Mortem & Preventative Controls (T + 24 to 48 Hours)

1. Conduct blameless incident retrospective.
2. Verify why secret scanning failed to catch the credential before commit.
3. Add custom secret pattern to Gitleaks / `scripts/scan_secrets.py`.
4. Archive forensic evidence and submit compliance incident summary.
