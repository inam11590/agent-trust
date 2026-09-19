# AgentTrust Protocol Versioning & Compatibility Guide

## 1. Version Semantics

The AgentTrust Protocol uses two independent versioning scopes:
1. **Protocol Envelope Version**: `ATP/1.0`
2. **Capability Version**: `<capability_name>@<version>` (e.g. `hotel.reserve@1.0`)

---

## 2. Protocol Version Compatibility

* **Current Active Version**: `ATP/1.0`
* **Version Negotiation**: The client indicates its supported protocol version in `atp_version: "1.0"` within the envelope and `X-ATP-Version: 1.0` header.
* **Incompatible Versions**: If an unsupported version (e.g. `2.0`) is supplied, the Gateway responds with error `ATP_VERSION_UNSUPPORTED` (HTTP 400).
* **No Security Downgrade**: The Gateway never automatically downgrades security or signature requirements to deprecated protocol levels.

---

## 3. Capability Evolution Rules

* **Minor Additions**: Optional parameters added to capability input schemas do not require a major version bump.
* **Breaking Changes**: Adding required fields, changing output structure, or modifying authorization semantics requires incrementing the capability major version (e.g. `hotel.reserve@2.0`).
* **Deprecation Notice**: Organizations must provide notice before disabling older capability versions on registered endpoints.
