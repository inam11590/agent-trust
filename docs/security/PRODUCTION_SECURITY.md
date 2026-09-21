# AgentTrust Production Security Architecture

This document describes the security baseline, architectural invariants, and operational protections enforced in production deployments of AgentTrust.

---

## 1. Security Architecture Baseline & Layered Defense

AgentTrust protects autonomous AI agents, enterprise gateways, sidecars, and cross-organizational delegations. Production security relies on a defense-in-depth model:

```
+-------------------------------------------------------------------------+
| Layer 1: Network & Edge Security                                        |
| - TLS 1.3 encryption (no development bypass permitted in production)    |
| - Reverse proxy / Load balancer with Trusted Host validation            |
| - Strict CORS policy (no wildcard origins with credentials)             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 2: HTTP & Application Perimeter                                   |
| - Security Headers: HSTS, X-Content-Type-Options, CSP, Referrer-Policy   |
| - Strict payload size enforcement (max request, ATP message, ATC token) |
| - Sliding-window rate limiting & brute-force throttling                 |
| - Path traversal, SSRF, SQLi, and Command Injection defenses            |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 3: Identity & Cryptographic Authorization                         |
| - ATP/1.0 signed requests with anti-replay nonces and timestamps        |
| - ATC/1.0 tamper-proof cryptographic credentials                        |
| - Asymmetric Ed25519 signing keys managed via KMS/HSM provider          |
| - Strict key purpose separation (Agent, Gateway, Issuer, Control Plane) |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 4: Core Secret & Key Management                                   |
| - Central SecretProvider abstraction (EnvSecretProvider, Vault/KMS)     |
| - In-memory TTL secret caching (zero plaintext written to disk)         |
| - Automated log & exception redaction (Authorization tokens, passwords) |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
| Layer 5: Data & Runtime Protection                                      |
| - Multi-stage minimal Docker images running as non-root (UID 10001)     |
| - Read-only root container filesystems with tmpfs scratch space         |
| - PostgreSQL with least privilege and encrypted connections             |
| - Redis with fail-closed replay protection                              |
+-------------------------------------------------------------------------+
```

---

## 2. Production Security Invariants

In `ENVIRONMENT=production`, AgentTrust enforces the following mandatory rules:

1. **Fail-Stop Startup Validation (`PRODUCTION_SECURITY_CONFIGURATION_INVALID`)**:
   If any dangerous development default or insecure setting is detected at boot time, the process immediately aborts. Insecure settings include:
   - `DEBUG=True`
   - Default, unset, or short secret keys (`< 32` characters or containing `changeme`, `secret`, `insecure`)
   - `ALLOW_INSECURE_TLS=True`
   - Wildcard CORS (`*`) while allowing credentials
   - Unrestricted host headers

2. **Zero Private Key Exposure**:
   Private cryptographic signing keys are strictly confined within the `KeyProvider` abstraction. APIs **never** return private keys, and signing occurs within the provider boundary.

3. **Log Sanitization Invariant**:
   All log formatters, error loggers, and exception handlers automatically sanitize sensitive data:
   - `Authorization: Bearer <token>` becomes `Authorization: Bearer [REDACTED]`
   - Database connection strings have passwords scrubbed
   - Query strings and JSON payloads containing passwords, tokens, or private keys are masked

4. **Replay Protection Fail-Closed**:
   If the fast replay store (Redis) is partitioned or unavailable, signed requests requiring replay verification **fail closed** (`REPLAY_PROTECTION_UNAVAILABLE`, HTTP 503). Security controls never fail open.

5. **Non-Root Container Runtime**:
   Production container images build from non-root templates and execute as UID `10001` (group `10001`). No Docker socket is mounted inside application containers.

---

## 3. Compliance and Verification Transparency

AgentTrust maintains complete honesty regarding security compliance:
- Features utilizing local software keystores are labeled **TEST / MOCK ONLY**.
- Cloud KMS / HSM support provides standard driver interfaces ready for AWS KMS, GCP Cloud KMS, or HashiCorp Vault.
- No unearned compliance badges (SOC 2, ISO 27001, FIPS 140-2/3, FedRAMP) are claimed until third-party attestation is conducted on customer deployment infrastructure.
