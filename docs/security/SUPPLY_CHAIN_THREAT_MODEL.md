# Software Supply Chain Threat Model

This document identifies potential threat vectors across the AgentTrust software supply chain and details the preventative, detective, and corrective controls implemented to mitigate them.

---

## Threat Matrix & Mitigation Controls

| Threat Vector | Description | Potential Impact | Mitigating Controls |
| :--- | :--- | :--- | :--- |
| **T1: Upstream Dependency Compromise** | Malicious code injected into third-party PyPI / NPM packages | Remote Code Execution, secret exfiltration | Version pinning, lockfiles with integrity hashes, automated `pip-audit` / `npm audit` gates in CI |
| **T2: CI/CD Pipeline Tampering** | Unauthorized modification of GitHub Actions workflows or runner execution | Build injection, compromised release artifacts | Least-privilege `GITHUB_TOKEN` permissions, branch protection on `.github/`, two-person code review |
| **T3: Container Base Image Vulnerability** | Unpatched CVEs or backdoors present in upstream base container image | Container escape, lateral movement in cluster | Minimal base images (`python:3.11-slim`), multi-stage builds, non-root user (UID 10001), automated container scanning |
| **T4: Hardcoded Secrets in Source/Artifacts** | Developers accidentally commit API keys, private keys, or passwords | Unauthorized system access, lateral privilege escalation | Pre-commit git hooks, automated secret scanning in CI (Gitleaks), fail-stop production startup validator |
| **T5: Artifact Substitution & Tampering** | Man-in-the-middle or unauthorized push replacing container images or SDK packages | Deployment of backdoored code to production | SHA-256 digests in `release_manifest.json`, cryptographic artifact signing, container image digest pinning |
| **T6: Dependency Confusion / Typosquatting** | Public package registry hosting malicious package with internal name | Accidental download of rogue package | Explicit package index scoping, lockfiles, SBOM generation and verification |

---

## Continuous Verification

1. **Daily Automated Scans**: Dependency and container scans run on a scheduled nightly cron to detect newly published CVEs.
2. **Deterministic Builds**: Build steps produce reproducible artifacts verified via content-addressable SHA-256 hashes.
3. **Audit Trails**: Every release artifact links to a specific Git commit SHA and signed release tag.
