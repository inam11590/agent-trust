# AgentTrust Policy Language 1.0 (APL/1.0) Specification

**Version:** 1.0  
**Status:** Canonical Standard  
**Maturity:** Production Ready  

---

## 1. Overview & Core Principles

AgentTrust Policy Language (APL/1.0) is a domain-specific, purely declarative Policy-as-Code language designed for governing autonomous AI agents in enterprise environments.

### Guiding Principles:
1. **Zero Arbitrary Code Execution:** The language contains no Turing-complete constructs, loops, recursion, or dynamic code evaluation (`eval`, `exec`, Python, JavaScript, shell, SQL, or regex DoS risks).
2. **Strict Type Safety:** Fields and operands are explicitly typed (`STRING`, `NUMBER`, `BOOLEAN`, `ENUM`, `TIMESTAMP`, `LIST`). Implicit type coercions between incompatible types are strictly disallowed.
3. **Deterministic Evaluation:** Given an identical policy version, context, and input, evaluation always yields the exact same decision, explanation, and trace.
4. **Fail-Closed Security Precedence:** Precedence order is mathematically defined: `DENY` > `REQUIRE_APPROVAL` > `ALLOW` > `NO_MATCH`. Default decision is `DENY` (or existing authorization layer fallback).
5. **Non-Overridable Platform Invariants:** APL/1.0 policies can restrict authority, but can **never** override platform security invariants such as revoked credentials, invalid cryptographic signatures, replay attacks, missing cross-organization trust, or SSRF protections.

---

## 2. Policy Document Schema

A policy document is written in YAML or JSON and compiles into a canonical normalized AST.

```yaml
version: "APL/1.0"
name: "Corporate Travel Flight Purchase Policy"
description: "Tiered approval policy for agent flight bookings."
target:
  capability: "purchase_flight"
  environment: "production"

rules:
  - id: "small_purchase"
    description: "Bookings up to $500 are authorized autonomously."
    when:
      all:
        - field: "action"
          operator: "eq"
          value: "purchase_flight"
        - field: "input.amount"
          operator: "lte"
          value: 500
    effect: "ALLOW"

  - id: "medium_purchase"
    description: "Bookings between $500 and $2,000 require human manager approval."
    when:
      all:
        - field: "action"
          operator: "eq"
          value: "purchase_flight"
        - field: "input.amount"
          operator: "gt"
          value: 500
        - field: "input.amount"
          operator: "lte"
          value: 2000
    effect: "REQUIRE_APPROVAL"

  - id: "large_purchase"
    description: "Bookings above $2,000 are rejected."
    when:
      all:
        - field: "action"
          operator: "eq"
          value: "purchase_flight"
        - field: "input.amount"
          operator: "gt"
          value: 2000
    effect: "DENY"

default_effect: "DENY"
```

---

## 3. Safe Field Registry

Policies may only reference approved fields registered in the canonical registry. Referencing unregistered fields results in a static validation error.

| Field | Type | Description |
|---|---|---|
| `agent.id` | STRING / UUID | Identifier of the requesting AI agent (`agt_...`) |
| `agent.type` | STRING | Functional role/type of the agent |
| `agent.organization_id` | STRING / UUID | Organization owning the agent |
| `action` | STRING | The capability action invoked (e.g., `purchase_flight`, `refund`) |
| `resource` | STRING | Target business resource (e.g., `flight`, `invoice`) |
| `input.amount` | NUMBER | Transaction monetary amount |
| `input.currency` | STRING / ENUM | 3-letter ISO-4217 currency code (`USD`, `EUR`, etc.) |
| `input.<field>` | ANY | Dynamic capability input payload attribute |
| `target.id` | STRING | Target peer or service identifier |
| `target.type` | STRING | Logical target system category |
| `credential.type` | STRING | Type of verifiable credential presented (`ATC/1.0`) |
| `credential.issuer` | STRING | Issuer ID of presented verifiable credential |
| `trust.status` | ENUM | Cross-organization trust status (`ACTIVE`, `NONE`) |
| `delegation.depth` | NUMBER | Length of agent-to-agent delegation chain |
| `risk.level` | ENUM | Risk score bucket (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `risk.score` | NUMBER | Numeric risk score (0 to 100) |
| `environment` | ENUM | Runtime tier (`production`, `staging`, `sandbox`) |
| `gateway.id` | STRING | Enterprise Gateway or Sidecar identifier (`gw_...`) |
| `time.hour` | NUMBER | Hour of invocation in UTC (0 to 23) |
| `time.day_of_week` | NUMBER | Day of week (1 = Monday, 7 = Sunday) |

---

## 4. Operators & Type Compatibility

| Operator | Supported Types | Meaning |
|---|---|---|
| `eq` | STRING, NUMBER, BOOLEAN, ENUM | Equality check |
| `neq` | STRING, NUMBER, BOOLEAN, ENUM | Inequality check |
| `gt` | NUMBER, TIMESTAMP | Greater than |
| `gte` | NUMBER, TIMESTAMP | Greater than or equal to |
| `lt` | NUMBER, TIMESTAMP | Less than |
| `lte` | NUMBER, TIMESTAMP | Less than or equal to |
| `in` | STRING, NUMBER, ENUM in LIST | Membership test |
| `not_in` | STRING, NUMBER, ENUM in LIST | Non-membership test |
| `exists` | ANY | Field is present and not null |
| `not_exists` | ANY | Field is absent or null |
| `starts_with` | STRING | String prefix matching (literal only, no regex) |
| `ends_with` | STRING | String suffix matching (literal only, no regex) |
| `contains` | STRING | Substring matching |

---

## 5. Boolean Logic Combinators

Conditions support structured combinators:
- `all`: All child conditions must evaluate to `True` (logical AND).
- `any`: At least one child condition must evaluate to `True` (logical OR).
- `not`: Inverts child condition (logical NOT).

Maximum condition nesting depth is **4 levels**.

---

## 6. Resource Limits & DoS Protection

To protect both Control Plane and Data Plane (Sidecars and Edge Gateways), the following hard limits are enforced during compilation:
- **Maximum Document Size:** 64 KB (65,536 bytes).
- **Maximum Rules per Policy:** 50 rules.
- **Maximum Conditions per Rule:** 20 conditions.
- **Maximum Nesting Depth:** 4 levels.
- **Maximum List Elements:** 100 items per list operand.
- **Regex:** Arbitrary regular expressions are prohibited to prevent catastrophic backtracking (ReDoS). Prefix/suffix/contains string matching is strictly literal.
