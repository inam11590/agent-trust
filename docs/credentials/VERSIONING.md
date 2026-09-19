# AgentTrust Credential Versioning & Evolution (ATC/1.0)

## 1. Specification Versioning

AgentTrust Verifiable Agent Credentials use strict Semantic Versioning (`ATC/M.m`).

- **Current Version**: `ATC/1.0`
- **Signing Version**: `ATC-SIG/1`

### Rules
1. **Major Version (`ATC/1.x` vs `ATC/2.x`)**:
   - Changes to the canonical serialization algorithm, new signing schemes, or structural envelope reorganizations require a major version bump.
   - Verifiers must fail-closed if `credential_version` major version does not match supported versions (`CREDENTIAL_SCHEMA_UNSUPPORTED`).
2. **Minor Version (`ATC/1.1`)**:
   - Additive, backward-compatible claims may be introduced without invalidating `ATC/1.0` parsers.
3. **No Deprecations**:
   - `ATC/1.0` will be maintained and supported across all SDKs (Python, TypeScript, Java) throughout the v1 lifecycle.
