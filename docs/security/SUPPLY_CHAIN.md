# AgentTrust Software Supply Chain Security

This document outlines the software supply chain architecture, dependency management, container hardening, SBOM generation, build provenance, and release integrity protocols for AgentTrust.

---

## 1. Supply Chain Architecture

AgentTrust implements supply chain security controls spanning source, build, package, and deployment stages:

```
[ Developer Commit ]
        │ (Signed Commits, Branch Protection, CODEOWNERS)
        ▼
[ CI/CD Pipeline (GitHub Actions) ]
   ├── Secret Scanning (Gitleaks / TruffleHog)
   ├── Dependency Vulnerability Scanning (pip-audit, npm audit)
   ├── Static Application Security Testing (SAST)
   ├── Software Bill of Materials (SBOM) Generation (CycloneDX)
   ├── Multi-Stage Minimal Docker Build (UID 10001)
   └── Artifact Digest & Manifest Signing (SHA-256)
        │
        ▼
[ Immutable Container Registry & Release Artifacts ]
        │
        ▼
[ Production Deployment Gate ]
   ├── Digest & Signature Verification
   ├── Read-only Root Filesystem Verification
   └── Fail-Stop Startup Security Validation
```

---

## 2. Dependency Locking & Vulnerability Scanning

- **Python**: Core dependencies are strictly pinned with explicit versions in `backend/requirements.txt` and lockfiles. Continuous vulnerability scans run via `pip-audit`.
- **Node.js**: Web dashboard and SDK dependencies use `package-lock.json` with strict cryptographic sub-resource integrity hashes. Continuous vulnerability scans run via `npm audit --audit-level=high`.
- **Policy**: Critical or High severity CVEs in direct runtime dependencies block release gates.

---

## 3. Container Hardening Invariants

All container images built for AgentTrust follow production container standards:
1. **Multi-Stage Builds**: Compilers, build dependencies, and temporary caches exist exclusively in the builder stage. The final runtime container contains only the minimal python/node runtime and runtime artifacts.
2. **Non-Root Execution**: Containers execute as unprivileged user `agenttrust` (`UID 10001`, `GID 10001`). No service runs as root.
3. **No Docker Socket**: The Docker daemon socket (`/var/run/docker.sock`) is never mounted into application containers.
4. **Read-Only Root Filesystem**: Root filesystem (`/`) is mounted read-only (`read_only: true`). Ephemeral writable areas are mounted explicitly as `tmpfs` at `/tmp` and `/run`.
5. **Dropped Linux Capabilities**: All capabilities dropped (`cap_drop: [ALL]`), granting only essential networking bindings if required.

---

## 4. Software Bill of Materials (SBOM) & Release Manifest

For every production release:
- A complete **CycloneDX** and **SPDX** JSON SBOM is generated documenting all direct and transitive dependencies, package URLs (PURLs), licenses, and cryptographic hashes.
- An immutable `release_manifest.json` is generated containing SHA-256 digests of all released artifacts (wheels, tarballs, docker container digests).
- Deployments verify the image digest against the release manifest prior to rolling deployment.
