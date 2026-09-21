"""APL/1.0 Deterministic Sandboxed Policy Evaluator."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.services.apl.schema import APLEffect, APLOperator


@dataclass
class ConditionTrace:
    field: str
    operator: str
    expected_value: Any
    actual_value: Any
    matched: bool
    path: str


@dataclass
class RuleEvaluationTrace:
    rule_id: str
    effect: str
    matched: bool
    description: str
    condition_traces: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class APLEvaluationResult:
    decision: str  # "ALLOW", "REQUIRE_APPROVAL", "DENY"
    matched_rules: List[Dict[str, Any]]
    unmatched_rules: List[str]
    default_effect_applied: bool
    explanation: str
    trace: List[Dict[str, Any]]
    evaluation_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "matched_rules": self.matched_rules,
            "unmatched_rules": self.unmatched_rules,
            "default_effect_applied": self.default_effect_applied,
            "explanation": self.explanation,
            "trace": self.trace,
            "evaluation_time_ms": round(self.evaluation_time_ms, 3),
        }


def resolve_field_value(context: Dict[str, Any], field_path: str) -> Any:
    """Resolve dot-notated field path from nested dictionary or direct key."""
    if not isinstance(context, dict):
        return None

    # First check exact direct key
    if field_path in context:
        return context[field_path]

    # Otherwise navigate dot-path
    parts = field_path.split(".")
    current: Any = context
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def evaluate_atomic_condition(
    field_name: str,
    operator: str,
    expected_value: Any,
    context: Dict[str, Any]
) -> Tuple[bool, Any]:
    """Evaluate single atomic condition against context."""
    actual_val = resolve_field_value(context, field_name)
    op = operator.lower().strip()

    if op == APLOperator.EXISTS.value:
        return (actual_val is not None), actual_val

    if op == APLOperator.NOT_EXISTS.value:
        return (actual_val is None), actual_val

    # If field is absent for other operators, it cannot match
    if actual_val is None:
        return False, actual_val

    # Equality
    if op == APLOperator.EQ.value:
        # Normalize numeric types if comparable (e.g. 500 == 500.0)
        return (actual_val == expected_value), actual_val

    if op == APLOperator.NEQ.value:
        return (actual_val != expected_value), actual_val

    # Numeric & range comparisons
    if op in (APLOperator.GT.value, APLOperator.GTE.value, APLOperator.LT.value, APLOperator.LTE.value):
        try:
            num_actual = float(actual_val)
            num_expected = float(expected_value)
            if op == APLOperator.GT.value:
                return (num_actual > num_expected), actual_val
            if op == APLOperator.GTE.value:
                return (num_actual >= num_expected), actual_val
            if op == APLOperator.LT.value:
                return (num_actual < num_expected), actual_val
            if op == APLOperator.LTE.value:
                return (num_actual <= num_expected), actual_val
        except (ValueError, TypeError):
            return False, actual_val

    # List membership
    if op == APLOperator.IN.value:
        if isinstance(expected_value, (list, tuple, set)):
            return (actual_val in expected_value), actual_val
        return False, actual_val

    if op == APLOperator.NOT_IN.value:
        if isinstance(expected_value, (list, tuple, set)):
            return (actual_val not in expected_value), actual_val
        return True, actual_val

    # String operations
    if op in (APLOperator.STARTS_WITH.value, APLOperator.ENDS_WITH.value, APLOperator.CONTAINS.value):
        str_actual = str(actual_val)
        str_expected = str(expected_value)
        if op == APLOperator.STARTS_WITH.value:
            return str_actual.startswith(str_expected), actual_val
        if op == APLOperator.ENDS_WITH.value:
            return str_actual.endswith(str_expected), actual_val
        if op == APLOperator.CONTAINS.value:
            return (str_expected in str_actual), actual_val

    return False, actual_val


def evaluate_condition_node(
    node: Any,
    context: Dict[str, Any],
    traces: List[Dict[str, Any]],
    path: str = "when"
) -> bool:
    """Recursively evaluate logical condition tree."""
    if not isinstance(node, dict):
        return False

    # Combinator: all (AND)
    if "all" in node:
        children = node["all"]
        if not isinstance(children, list) or len(children) == 0:
            return False
        all_passed = True
        for idx, child in enumerate(children):
            res = evaluate_condition_node(child, context, traces, f"{path}.all[{idx}]")
            if not res:
                all_passed = False
        return all_passed

    # Combinator: any (OR)
    if "any" in node:
        children = node["any"]
        if not isinstance(children, list) or len(children) == 0:
            return False
        any_passed = False
        for idx, child in enumerate(children):
            res = evaluate_condition_node(child, context, traces, f"{path}.any[{idx}]")
            if res:
                any_passed = True
        return any_passed

    # Combinator: not (NOT)
    if "not" in node:
        child = node["not"]
        res = evaluate_condition_node(child, context, traces, f"{path}.not")
        return not res

    # Atomic condition
    field_name = node.get("field", "")
    operator = node.get("operator", "eq")
    expected_value = node.get("value")

    matched, actual_val = evaluate_atomic_condition(field_name, operator, expected_value, context)
    traces.append({
        "path": path,
        "field": field_name,
        "operator": operator,
        "expected": expected_value,
        "actual": actual_val,
        "matched": matched
    })
    return matched


def evaluate_apl_policy(ast: Dict[str, Any], context: Dict[str, Any]) -> APLEvaluationResult:
    """
    Pure deterministic sandboxed evaluation of an APL/1.0 policy AST against authorization context.
    Precedence Order: DENY > REQUIRE_APPROVAL > ALLOW > NO_MATCH
    """
    start_time = time.perf_counter()

    # Verify target matching if target filters are declared
    target = ast.get("target") or {}
    for target_key, target_expected in target.items():
        if target_expected is not None:
            actual = resolve_field_value(context, target_key)
            if actual is not None and str(actual) != str(target_expected):
                # Policy does not apply to this target context
                duration = (time.perf_counter() - start_time) * 1000
                return APLEvaluationResult(
                    decision="NO_MATCH",
                    matched_rules=[],
                    unmatched_rules=[],
                    default_effect_applied=False,
                    explanation=f"Policy target '{target_key}' expected '{target_expected}' but context had '{actual}'. Policy did not trigger.",
                    trace=[],
                    evaluation_time_ms=duration
                )

    rules = ast.get("rules", [])
    default_effect = str(ast.get("default_effect", "DENY")).upper()

    matched_deny_rules: List[Dict[str, Any]] = []
    matched_approval_rules: List[Dict[str, Any]] = []
    matched_allow_rules: List[Dict[str, Any]] = []
    unmatched_rules: List[str] = []
    evaluation_traces: List[Dict[str, Any]] = []

    for idx, rule in enumerate(rules):
        rule_id = rule.get("id", f"rule_{idx}")
        effect = str(rule.get("effect", "")).upper()
        description = rule.get("description", "")
        when = rule.get("when") or rule.get("conditions")

        rule_traces: List[Dict[str, Any]] = []
        rule_matched = False

        if when is None:
            # Unconditional rule
            rule_matched = True
        else:
            rule_matched = evaluate_condition_node(when, context, rule_traces, path=f"rules[{rule_id}].when")

        evaluation_traces.append({
            "rule_id": rule_id,
            "effect": effect,
            "matched": rule_matched,
            "description": description,
            "condition_traces": rule_traces
        })

        rule_summary = {
            "id": rule_id,
            "effect": effect,
            "description": description
        }

        if rule_matched:
            if effect == APLEffect.DENY.value:
                matched_deny_rules.append(rule_summary)
            elif effect == APLEffect.REQUIRE_APPROVAL.value:
                matched_approval_rules.append(rule_summary)
            elif effect == APLEffect.ALLOW.value:
                matched_allow_rules.append(rule_summary)
        else:
            unmatched_rules.append(rule_id)

    # Apply mathematical precedence: DENY > REQUIRE_APPROVAL > ALLOW > default_effect
    default_applied = False
    if matched_deny_rules:
        decision = APLEffect.DENY.value
        all_matched = matched_deny_rules + matched_approval_rules + matched_allow_rules
        rule_names = ", ".join([r["id"] for r in matched_deny_rules])
        explanation = f"Denied by policy rule(s): [{rule_names}]. DENY takes strict precedence."
    elif matched_approval_rules:
        decision = APLEffect.REQUIRE_APPROVAL.value
        all_matched = matched_approval_rules + matched_allow_rules
        rule_names = ", ".join([r["id"] for r in matched_approval_rules])
        explanation = f"Human approval required by policy rule(s): [{rule_names}]."
    elif matched_allow_rules:
        decision = APLEffect.ALLOW.value
        all_matched = matched_allow_rules
        rule_names = ", ".join([r["id"] for r in matched_allow_rules])
        explanation = f"Authorized by policy rule(s): [{rule_names}]."
    else:
        decision = default_effect
        all_matched = []
        default_applied = True
        explanation = f"No rules matched context. Default policy effect '{default_effect}' applied."

    duration = (time.perf_counter() - start_time) * 1000

    return APLEvaluationResult(
        decision=decision,
        matched_rules=all_matched,
        unmatched_rules=unmatched_rules,
        default_effect_applied=default_applied,
        explanation=explanation,
        trace=evaluation_traces,
        evaluation_time_ms=duration
    )
