"""Pre-configured standard policy templates for APL/1.0."""

from __future__ import annotations

from typing import Any, Dict, List

STANDARD_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "tpl_purchase_limits",
        "name": "Tiered Transaction / Purchase Limits",
        "description": "Autonomous execution under $500, human approval up to $5,000, and hard rejection above $5,000.",
        "category": "Financial Controls",
        "yaml_source": """version: "APL/1.0"
name: "Tiered Purchase Limits"
description: "Autonomous execution under $500, human approval up to $5,000, and rejection above $5,000."
target:
  environment: "production"

rules:
  - id: "small_transaction_auto_allow"
    description: "Transactions up to $500 execute autonomously."
    when:
      all:
        - field: "input.amount"
          operator: "lte"
          value: 500
    effect: "ALLOW"

  - id: "medium_transaction_requires_approval"
    description: "Transactions between $500 and $5,000 require human authorization."
    when:
      all:
        - field: "input.amount"
          operator: "gt"
          value: 500
        - field: "input.amount"
          operator: "lte"
          value: 5000
    effect: "REQUIRE_APPROVAL"

  - id: "large_transaction_deny"
    description: "Transactions exceeding $5,000 are blocked."
    when:
      all:
        - field: "input.amount"
          operator: "gt"
          value: 5000
    effect: "DENY"

default_effect: "DENY"
"""
    },
    {
        "id": "tpl_read_only_agent",
        "name": "Read-Only Inspection Agent",
        "description": "Restricts agent strictly to read-only capabilities and blocks destructive actions.",
        "category": "Least Privilege",
        "yaml_source": """version: "APL/1.0"
name: "Read-Only Agent Guardrail"
description: "Permits read operations while strictly denying mutation or deletion."
target:
  environment: "production"

rules:
  - id: "block_destructive_actions"
    description: "Explicitly block write, delete, and modify actions."
    when:
      any:
        - field: "action"
          operator: "starts_with"
          value: "delete"
        - field: "action"
          operator: "starts_with"
          value: "update"
        - field: "action"
          operator: "starts_with"
          value: "create"
    effect: "DENY"

  - id: "allow_read_queries"
    description: "Permit get, list, and read actions."
    when:
      any:
        - field: "action"
          operator: "starts_with"
          value: "get"
        - field: "action"
          operator: "starts_with"
          value: "list"
        - field: "action"
          operator: "starts_with"
          value: "read"
    effect: "ALLOW"

default_effect: "DENY"
"""
    },
    {
        "id": "tpl_risk_based_approval",
        "name": "Risk-Adaptive Human Approval",
        "description": "Demands human approval whenever risk score exceeds 70 or risk level is HIGH / CRITICAL.",
        "category": "Risk Management",
        "yaml_source": """version: "APL/1.0"
name: "Risk-Adaptive Human Approval"
description: "Requires approval when risk score is high."
target:
  environment: "production"

rules:
  - id: "escalate_high_risk"
    description: "Escalate to human review if risk score exceeds 70."
    when:
      any:
        - field: "risk.score"
          operator: "gt"
          value: 70
        - field: "risk.level"
          operator: "in"
          value: ["HIGH", "CRITICAL"]
    effect: "REQUIRE_APPROVAL"

  - id: "allow_low_risk"
    description: "Allow low-risk operations."
    when:
      all:
        - field: "risk.score"
          operator: "lte"
          value: 70
    effect: "ALLOW"

default_effect: "REQUIRE_APPROVAL"
"""
    },
    {
        "id": "tpl_business_hours",
        "name": "Business Hours Temporal Restriction",
        "description": "Permits sensitive operational actions only during working business hours (UTC 08:00 - 18:00, Mon-Fri).",
        "category": "Operational Controls",
        "yaml_source": """version: "APL/1.0"
name: "Business Hours Temporal Guardrail"
description: "Restricts execution to standard business hours."
target:
  environment: "production"

rules:
  - id: "block_off_hours"
    description: "Block execution on weekends or outside UTC 08:00 to 18:00."
    when:
      any:
        - field: "time.day_of_week"
          operator: "gt"
          value: 5
        - field: "time.hour"
          operator: "lt"
          value: 8
        - field: "time.hour"
          operator: "gt"
          value: 18
    effect: "DENY"

  - id: "allow_working_hours"
    description: "Permit actions during valid business window."
    when:
      all:
        - field: "time.day_of_week"
          operator: "lte"
          value: 5
        - field: "time.hour"
          operator: "gte"
          value: 8
        - field: "time.hour"
          operator: "lte"
          value: 18
    effect: "ALLOW"

default_effect: "DENY"
"""
    }
]


def list_templates() -> List[Dict[str, Any]]:
    return STANDARD_TEMPLATES


def get_template_by_id(template_id: str) -> Dict[str, Any] | None:
    for t in STANDARD_TEMPLATES:
        if t["id"] == template_id:
            return t
    return None
