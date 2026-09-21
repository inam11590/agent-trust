"""APL/1.0 Static Analysis and Policy Linter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from app.services.apl.schema import APLEffect, APLOperator


@dataclass
class LintIssue:
    code: str
    message: str
    rule_id: str | None
    severity: str  # "WARNING", "INFO", "SECURITY_RISK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "rule_id": self.rule_id,
            "severity": self.severity,
        }


class APLLinter:
    """Performs static analysis on normalized APL/1.0 AST to detect anti-patterns and security pitfalls."""

    def lint(self, ast: Dict[str, Any]) -> List[LintIssue]:
        issues: List[LintIssue] = []

        rules = ast.get("rules", [])
        default_effect = str(ast.get("default_effect", "DENY")).upper()

        if default_effect == APLEffect.ALLOW.value:
            issues.append(
                LintIssue(
                    code="LINT001_INSECURE_DEFAULT",
                    message="Policy specifies 'default_effect: ALLOW'. Industry best practice mandates fail-closed 'DENY'.",
                    rule_id=None,
                    severity="SECURITY_RISK"
                )
            )

        unconditional_rule_encountered = False
        unconditional_rule_id = None

        for idx, rule in enumerate(rules):
            rule_id = rule.get("id", f"rule_{idx}")
            effect = str(rule.get("effect", "")).upper()
            when = rule.get("when") or rule.get("conditions")

            # Check if this rule is dead code after a prior unconditional rule
            if unconditional_rule_encountered:
                issues.append(
                    LintIssue(
                        code="LINT002_DEAD_RULE",
                        message=f"Rule '{rule_id}' is unreachable because prior rule '{unconditional_rule_id}' matches unconditionally.",
                        rule_id=rule_id,
                        severity="WARNING"
                    )
                )

            # Check for unconditional ALLOW
            if not when:
                if effect == APLEffect.ALLOW.value:
                    issues.append(
                        LintIssue(
                            code="LINT003_OVERLY_BROAD_ALLOW",
                            message=f"Rule '{rule_id}' has no conditions and grants unconditional ALLOW authority.",
                            rule_id=rule_id,
                            severity="SECURITY_RISK"
                        )
                    )
                unconditional_rule_encountered = True
                unconditional_rule_id = rule_id
            else:
                # Check for impossible numeric bounds in conditions
                self._check_impossible_bounds(when, rule_id, issues)

        return issues

    def _check_impossible_bounds(self, when_node: Any, rule_id: str, issues: List[LintIssue]) -> None:
        """Inspect condition trees for mutually exclusive conditions."""
        if not isinstance(when_node, dict):
            return

        all_conditions = when_node.get("all")
        if isinstance(all_conditions, list):
            # Track gt/gte and lt/lte for fields
            ranges: Dict[str, Dict[str, float]] = {}
            for cond in all_conditions:
                if not isinstance(cond, dict):
                    continue
                f = cond.get("field")
                op = cond.get("operator")
                val = cond.get("value")
                if f and op and isinstance(val, (int, float)):
                    if f not in ranges:
                        ranges[f] = {}
                    if op in ("gt", "gte"):
                        ranges[f]["min"] = max(ranges[f].get("min", float("-inf")), float(val))
                    elif op in ("lt", "lte"):
                        ranges[f]["max"] = min(ranges[f].get("max", float("inf")), float(val))

            for field_name, bounds in ranges.items():
                if "min" in bounds and "max" in bounds:
                    if bounds["min"] > bounds["max"]:
                        issues.append(
                            LintIssue(
                                code="LINT004_CONTRADICTORY_BOUNDS",
                                message=f"Rule '{rule_id}' has impossible condition bounds on field '{field_name}': min {bounds['min']} > max {bounds['max']}.",
                                rule_id=rule_id,
                                severity="WARNING"
                            )
                        )
