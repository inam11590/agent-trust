# AgentTrust Policy Authoring Guide (APL/1.0)

This guide explains how to write policies in very simple English.

---

## 1. What is an APL Policy?

An APL policy is a set of simple rules that tell AgentTrust when an AI agent can act automatically, when it must ask for human approval, and when it must be stopped.

Each rule has three parts:
1. **ID**: A unique name for the rule (for example, `small_purchase`).
2. **When**: The condition that triggers the rule (for example, `amount <= 500`).
3. **Effect**: What happens when the rule triggers (`ALLOW`, `REQUIRE_APPROVAL`, or `DENY`).

---

## 2. Decision Precedence: Safety First

If two rules match at the same time:
- **DENY** always wins over everything.
- **REQUIRE_APPROVAL** wins over **ALLOW**.
- **ALLOW** only happens if nothing denied or required approval.
- If no rule matches, the default decision is **DENY**.

---

## 3. Standard Templates

### Template 1: Purchase Tier Limit
```yaml
version: "APL/1.0"
name: "Purchase Approval Policy"
rules:
  - id: "low_amount"
    description: "Purchases up to 500 USD are approved immediately."
    when:
      all:
        - field: "input.amount"
          operator: "lte"
          value: 500
    effect: "ALLOW"

  - id: "medium_amount"
    description: "Purchases between 501 and 2000 USD need human approval."
    when:
      all:
        - field: "input.amount"
          operator: "gt"
          value: 500
        - field: "input.amount"
          operator: "lte"
          value: 2000
    effect: "REQUIRE_APPROVAL"

  - id: "high_amount"
    description: "Purchases above 2000 USD are blocked."
    when:
      all:
        - field: "input.amount"
          operator: "gt"
          value: 2000
    effect: "DENY"
```

### Template 2: Read-Only Agent Policy
```yaml
version: "APL/1.0"
name: "Read-Only Enforcer"
rules:
  - id: "allow_reads"
    description: "Allow read and search actions."
    when:
      any:
        - field: "action"
          operator: "starts_with"
          value: "get_"
        - field: "action"
          operator: "starts_with"
          value: "list_"
        - field: "action"
          operator: "starts_with"
          value: "search_"
    effect: "ALLOW"

  - id: "block_writes"
    description: "Block all write or mutation actions."
    when:
      any:
        - field: "action"
          operator: "starts_with"
          value: "create_"
        - field: "action"
          operator: "starts_with"
          value: "delete_"
        - field: "action"
          operator: "starts_with"
          value: "update_"
    effect: "DENY"
```

### Template 3: Business Hours Only
```yaml
version: "APL/1.0"
name: "Business Hours Policy"
rules:
  - id: "outside_hours_denied"
    description: "Block actions outside UTC business hours (8 AM - 6 PM)."
    when:
      any:
        - field: "time.hour"
          operator: "lt"
          value: 8
        - field: "time.hour"
          operator: "gte"
          value: 18
    effect: "DENY"
```
