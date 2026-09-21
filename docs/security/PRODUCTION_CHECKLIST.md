# AgentTrust Production Deployment Security Checklist

This checklist must be executed and verified before promoting any release to `ENVIRONMENT=production`.

---

## 1. Environment & Configuration Security

- [ ] `ENVIRONMENT` is explicitly set to `"production"`.
- [ ] `DEBUG` is set to `False`. (Startup fails if `DEBUG=True`).
- [ ] `SECRET_KEY` is generated cryptographically (min 64 chars) and fetched from central `SecretProvider`. Default keys like `changeme` or `secret` are rejected at boot.
- [ ] `ALLOW_INSECURE_TLS` is `False`.
- [ ] `CORS_ORIGINS` specifies explicit trusted domains. No wildcard `*` origins allowed when credentials are enabled.
- [ ] `ALLOWED_HOSTS` defines valid reverse-proxy hostnames. Untrusted hosts are blocked.

---

## 2. Cryptographic Keys & KMS

- [ ] Cryptographic keys are partitioned by purpose (`AGENT_SIGNING`, `GATEWAY_SIGNING`, etc.).
- [ ] Production keys are anchored in hardware-backed Cloud KMS or Vault.
- [ ] Private key bytes are never exported or accessible through API responses.
- [ ] Key rotation schedule is established (recommended: 90 days).

---

## 3. Network & Transport Security

- [ ] TLS 1.3 terminated at edge load balancer with valid CA-signed certificates.
- [ ] Strict Transport Security (HSTS) header enabled (`max-age=31536000; includeSubDomains; preload`).
- [ ] Security headers active: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.
- [ ] Inbound request payload size limits enforced (max 10MB general, max 2MB ATP messages).

---

## 4. Container & Runtime Security

- [ ] Container images built using multi-stage Dockerfiles.
- [ ] Container user is unprivileged (`UID 10001:10001`).
- [ ] Container root filesystem is mounted read-only (`read_only: true`).
- [ ] Ephemeral writes confined to tmpfs mounts (`/tmp`).
- [ ] Docker daemon socket (`/var/run/docker.sock`) is NOT mounted.
- [ ] Container vulnerability scan reports zero unresolved Critical or High vulnerabilities.

---

## 5. Database & Cache Hardening

- [ ] PostgreSQL connection uses SSL/TLS (`sslmode=verify-full`).
- [ ] PostgreSQL user account enforces least privilege (separate migrations user vs runtime user).
- [ ] Redis instance is password-protected and accessible only within private VPC subnet.
- [ ] Replay protection fail-closed behavior verified (requests reject if Redis is unreachable).

---

## 6. Observability & Logging Sanitization

- [ ] Log sanitization active: `Authorization: Bearer [REDACTED]`.
- [ ] Exception handlers mask internal stack traces and secrets in production responses.
- [ ] Central security event logging enabled for authentication failures, key rotations, and replay rejections.
- [ ] Alerting rules configured for `KEY_COMPROMISED` and rate-limit threshold breaches.

---

## 7. Supply Chain & Release Verification

- [ ] Release manifest verified with valid SHA-256 digests for all container images and packages.
- [ ] CycloneDX SBOM generated and archived for compliance audit.
- [ ] Dependency scans (`pip-audit`, `npm audit`) clean of high-severity advisories.
