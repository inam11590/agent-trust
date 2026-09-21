# Security Observability Privacy & Data Minimization Policy

## Overview
AgentTrust is designed as a security governance and identity system, **not** a surveillance platform. The observability infrastructure adheres to strict data minimization principles to ensure customer confidentiality, compliance with privacy regulations (GDPR, CCPA), and prevention of secret leakage.

---

## What We Collect vs. What We NEVER Collect

### What We Collect
- **Cryptographic Identifiers**: Key IDs, Agent UUIDs, Gateway UUIDs, Credential UUIDs, Organization UUIDs.
- **Protocol Metadata**: Timestamps, nonces, signature algorithm names, request IDs, trace IDs, correlation IDs.
- **Decisions & Reasons**: Status (ALLOWED / DENIED), policy rule names, standardized reason codes (e.g. CREDENTIAL_EXPIRED, NONCE_REUSED).
- **Telemetry Aggregates**: Request volume per minute, deny ratios, error counts, latency measurements.
- **Payload Fingerprints**: SHA-256 digests of payloads when needed for non-repudiation audit proofs.

### What We NEVER Collect
- **Raw Prompts**: LLM prompt strings, user queries, instructions, or chain-of-thought texts.
- **Customer Documents**: Uploaded business files, PDFs, spreadsheets, or internal knowledge documents.
- **Raw Business Payloads**: Transaction details, customer financial data, personal health information, PII.
- **Private Keys & Secrets**: Asymmetric private keys, passwords, API secrets, bearer tokens, or recovery codes.

---

## Log & Event Redaction

All security events and system logs pass through automated redaction before persistence or transmission:
- Bearer tokens are masked as Bearer [REDACTED].
- Database connection strings have user passwords stripped.
- Asymmetric private key blocks (-----BEGIN PRIVATE KEY-----) are replaced with [REDACTED_PRIVATE_KEY].
- JSON metadata fields matching sensitive keys (password, secret, 	oken, pi_key) are scrubbed automatically.

---

## Multi-Tenant Privacy Isolation

Security events and alerts are strictly bound to an organization_id.
- Tenant A cannot view, filter, aggregate, or correlate events belonging to Tenant B.
- Global platform administrators only monitor aggregate system health metrics without access to cross-tenant business event specifics.
