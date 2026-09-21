# AgentTrust Secret Management Architecture

This document details the secret classification, secret provider interface, lifecycle, caching, and rotation policies in AgentTrust.

---

## 1. Secret Classification

Secrets in AgentTrust are explicitly categorized into the following sensitivity tiers:

| Classification | Description | Examples | Handling Rules |
| :--- | :--- | :--- | :--- |
| **APPLICATION_SECRET** | Core application signing keys, session secrets, salts | `SECRET_KEY`, JWT secrets | In-memory only, rotated with overlapping grace period |
| **SERVICE_CREDENTIAL** | Credentials for internal infrastructure | PostgreSQL password, Redis password | Stored in dedicated secrets vault, injected via env/volume |
| **CRYPTOGRAPHIC_PRIVATE_KEY** | Asymmetric private keys for agents, gateways, credentials | Ed25519 private keys | Stored within KMS/HSM or isolated provider; never returned via API |
| **BOOTSTRAP_SECRET** | Initial tokens for onboarding gateways or sidecars | Enrollment tokens, initial setup keys | Short TTL, single-use or rate-limited strictly |
| **TEST_SECRET** | Mock secrets used strictly during test execution | Mock private keys, test JWT secrets | Forbidden in production; hardcoded values rejected at startup |
| **PUBLIC_KEY** | Public verification keys | Ed25519 public keys | Distributed publicly via JWKS or discovery endpoints |
| **PUBLIC_CONFIGURATION** | Non-sensitive runtime settings | CORS origins, port numbers, log levels | Stored in version-controlled config |

---

## 2. Central SecretProvider Interface

Applications must never read secrets from random filesystem locations or unvalidated environment blobs. Instead, all secret access passes through the `SecretProvider` interface:

```python
class SecretProvider(ABC):
    @abstractmethod
    def get_secret(self, name: str) -> str:
        """Fetch the current version of a secret."""
        pass

    @abstractmethod
    def get_secret_version(self, name: str, version: str) -> str:
        """Fetch a specific historical version of a secret."""
        pass

    @abstractmethod
    def refresh_secret(self, name: str) -> None:
        """Force a cache refresh of the named secret."""
        pass

    @abstractmethod
    def health(self) -> Dict[str, Any]:
        """Check availability of the underlying secret store."""
        pass
```

### Implementations:
1. **EnvSecretProvider (Development / Local)**:
   Reads from process environment variables and `.env`. Validates that production mode does not accept weak development defaults.
2. **VaultKmsSecretProvider (Production Pluggable)**:
   Integrates with HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager. Handles authentication via IAM / Kubernetes Service Account tokens.

---

## 3. In-Memory Caching Policy

To balance low latency with fast rotation propagation:
- Secrets are cached in memory for a configurable TTL (default: 300 seconds).
- **Zero Disk Plaintext**: Cached secrets are never written to disk, scratch files, or persistent volumes.
- **Cache Eviction**: Calling `refresh_secret(name)` or receiving a rotation webhook triggers immediate cache invalidation.

---

## 4. Secret Rotation Protocol

AgentTrust supports zero-downtime rotation:
1. **Database Credentials**: PostgreSQL supports two active user credentials concurrently during a rotation window. The new password is deployed, verified, and the old credential is deactivated after TTL expiry.
2. **Signing Secrets**: When rotating signing secrets, both the old and new secrets are valid for signature verification during the grace window ($\Delta t \ge 3600\text{s}$), but all newly issued signatures use the new secret immediately.
3. **Emergency Revocation**: If a secret is leaked, immediate invocation of the revocation protocol purges the cache and halts authorization using the old credential.
