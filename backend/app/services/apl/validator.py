"""APL/1.0 Policy Document Semantic and Structural Validator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.services.apl.schema import (
    APLEffect,
    APLOperator,
    APLType,
    MAX_CONDITIONS_PER_RULE,
    MAX_LIST_ELEMENTS,
    MAX_NESTING_DEPTH,
    MAX_RULES_PER_POLICY,
    OPERATOR_TYPE_COMPATIBILITY,
    SAFE_FIELD_REGISTRY,
    get_field_type,
    is_known_field,
)


@dataclass
class ValidationIssue:
    message: str
    path: str
    severity: str = "ERROR"  # "ERROR" or "WARNING"


@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": [{"message": e.message, "path": e.path} for e in self.errors],
            "warnings": [{"message": w.message, "path": w.path} for w in self.warnings],
        }


class APLValidator:
    """Validates normalized APL/1.0 AST against structural, semantic, and type rules."""

    def __init__(self, allow_dynamic_input_fields: bool = True):
        self.allow_dynamic_input = allow_dynamic_input_fields

    def validate(self, ast: Dict[str, Any]) -> ValidationResult:
        errors: List[ValidationIssue] = []
        warnings: List[ValidationIssue] = []

        if not isinstance(ast, dict):
            return ValidationResult(
                is_valid=False,
                errors=[ValidationIssue("AST root must be a dictionary.", "root")]
            )

        # 1. Version check
        version = ast.get("version")
        if version != "APL/1.0":
            errors.append(ValidationIssue(f"Unsupported policy version: {version}", "version"))

        # 2. Name check
        name = ast.get("name")
        if not name or not isinstance(name, str) or len(name.strip()) == 0:
            errors.append(ValidationIssue("Policy name must be a non-empty string.", "name"))

        # 3. Default effect
        default_effect = str(ast.get("default_effect", "DENY")).upper()
        if default_effect not in {e.value for e in APLEffect}:
            errors.append(
                ValidationIssue(f"Invalid default_effect '{default_effect}'. Allowed: {[e.value for e in APLEffect]}", "default_effect")
            )

        # 4. Rules validation
        rules = ast.get("rules")
        if not isinstance(rules, list):
            errors.append(ValidationIssue("'rules' must be a list.", "rules"))
            return ValidationResult(is_valid=False, errors=errors, warnings=warnings)

        if len(rules) > MAX_RULES_PER_POLICY:
            errors.append(
                ValidationIssue(
                    f"Policy contains {len(rules)} rules, exceeding maximum limit of {MAX_RULES_PER_POLICY}.",
                    "rules"
                )
            )

        rule_ids: Set[str] = set()
        seen_effects: List[str] = []

        for idx, rule in enumerate(rules):
            rule_path = f"rules[{idx}]"
            if not isinstance(rule, dict):
                errors.append(ValidationIssue(f"Rule at index {idx} must be a dictionary.", rule_path))
                continue

            rule_id = rule.get("id")
            if not rule_id or not isinstance(rule_id, str) or not rule_id.strip():
                errors.append(ValidationIssue(f"Rule at index {idx} missing required string 'id'.", f"{rule_path}.id"))
            else:
                rule_id = rule_id.strip()
                if rule_id in rule_ids:
                    errors.append(ValidationIssue(f"Duplicate rule id '{rule_id}'. Rule IDs must be unique.", f"{rule_path}.id"))
                rule_ids.add(rule_id)

            # Effect validation
            effect = str(rule.get("effect", "")).upper()
            if effect not in {APLEffect.ALLOW.value, APLEffect.REQUIRE_APPROVAL.value, APLEffect.DENY.value}:
                errors.append(
                    ValidationIssue(
                        f"Invalid rule effect '{effect}'. Must be ALLOW, REQUIRE_APPROVAL, or DENY.",
                        f"{rule_path}.effect"
                    )
                )
            seen_effects.append(effect)

            # Conditions validation (accepts 'when' or 'conditions')
            condition_block = rule.get("when") or rule.get("conditions")
            if condition_block is None:
                # Rule without conditions applies unconditionally
                warnings.append(
                    ValidationIssue(
                        f"Rule '{rule_id or idx}' has no conditions and will match unconditionally.",
                        rule_path,
                        severity="WARNING"
                    )
                )
            else:
                condition_count = 0
                condition_count = self._validate_condition_node(
                    condition_block,
                    path=f"{rule_path}.when",
                    current_depth=1,
                    errors=errors,
                    warnings=warnings,
                    count=0
                )
                if condition_count > MAX_CONDITIONS_PER_RULE:
                    errors.append(
                        ValidationIssue(
                            f"Rule exceeds condition limit: {condition_count} conditions found (max {MAX_CONDITIONS_PER_RULE}).",
                            f"{rule_path}.when"
                        )
                    )

        # 5. Semantic checks & linter warnings
        if not any(e == APLEffect.ALLOW.value for e in seen_effects) and default_effect == APLEffect.DENY.value:
            warnings.append(
                ValidationIssue(
                    "Policy has no ALLOW rules and defaults to DENY; it will deny every evaluation.",
                    "rules",
                    severity="WARNING"
                )
            )

        return ValidationResult(
            is_valid=(len(errors) == 0),
            errors=errors,
            warnings=warnings
        )

    def _validate_condition_node(
        self,
        node: Any,
        path: str,
        current_depth: int,
        errors: List[ValidationIssue],
        warnings: List[ValidationIssue],
        count: int
    ) -> int:
        """Recursively validate condition expressions and verify operator/field types."""
        if current_depth > MAX_NESTING_DEPTH:
            errors.append(
                ValidationIssue(
                    f"Condition nesting depth exceeds maximum allowed limit of {MAX_NESTING_DEPTH}.",
                    path
                )
            )
            return count + 1

        if not isinstance(node, dict):
            errors.append(ValidationIssue("Condition node must be an object/dict.", path))
            return count + 1

        # Check for logical combinators: all, any, not
        if "all" in node:
            children = node["all"]
            if not isinstance(children, list) or len(children) == 0:
                errors.append(ValidationIssue("'all' combinator must contain a non-empty list of conditions.", f"{path}.all"))
                return count + 1
            for idx, child in enumerate(children):
                count = self._validate_condition_node(child, f"{path}.all[{idx}]", current_depth + 1, errors, warnings, count)
            return count

        if "any" in node:
            children = node["any"]
            if not isinstance(children, list) or len(children) == 0:
                errors.append(ValidationIssue("'any' combinator must contain a non-empty list of conditions.", f"{path}.any"))
                return count + 1
            for idx, child in enumerate(children):
                count = self._validate_condition_node(child, f"{path}.any[{idx}]", current_depth + 1, errors, warnings, count)
            return count

        if "not" in node:
            child = node["not"]
            count = self._validate_condition_node(child, f"{path}.not", current_depth + 1, errors, warnings, count)
            return count

        # Otherwise, atomic condition: {field: "...", operator: "...", value: ...}
        count += 1
        field_name = node.get("field")
        if not field_name or not isinstance(field_name, str):
            errors.append(ValidationIssue("Atomic condition requires string 'field'.", f"{path}.field"))
            return count

        field_name = field_name.strip()
        if not is_known_field(field_name):
            errors.append(
                ValidationIssue(
                    f"Unregistered field '{field_name}'. Must be in SAFE_FIELD_REGISTRY or start with 'input.'.",
                    f"{path}.field"
                )
            )

        op_str = node.get("operator")
        if not op_str or not isinstance(op_str, str):
            errors.append(ValidationIssue("Atomic condition requires string 'operator'.", f"{path}.operator"))
            return count

        op_str = op_str.strip().lower()
        try:
            operator = APLOperator(op_str)
        except ValueError:
            errors.append(
                ValidationIssue(
                    f"Unknown operator '{op_str}'. Supported: {[o.value for o in APLOperator]}",
                    f"{path}.operator"
                )
            )
            return count

        value = node.get("value")
        self._validate_operator_type_compatibility(field_name, operator, value, path, errors, warnings)
        return count

    def _validate_operator_type_compatibility(
        self,
        field_name: str,
        operator: APLOperator,
        value: Any,
        path: str,
        errors: List[ValidationIssue],
        warnings: List[ValidationIssue]
    ) -> None:
        """Validate operator application to expected field type."""
        field_type = get_field_type(field_name)

        # exists / not_exists operators don't require value
        if operator in (APLOperator.EXISTS, APLOperator.NOT_EXISTS):
            return

        # in / not_in operators require list value
        if operator in (APLOperator.IN, APLOperator.NOT_IN):
            if not isinstance(value, (list, set, tuple)):
                errors.append(
                    ValidationIssue(
                        f"Operator '{operator.value}' requires a list value.",
                        f"{path}.value"
                    )
                )
            elif len(value) > MAX_LIST_ELEMENTS:
                errors.append(
                    ValidationIssue(
                        f"List value for '{operator.value}' exceeds max length of {MAX_LIST_ELEMENTS}.",
                        f"{path}.value"
                    )
                )
            return

        # Range comparisons (gt, gte, lt, lte) require numbers or timestamps
        if operator in (APLOperator.GT, APLOperator.GTE, APLOperator.LT, APLOperator.LTE):
            if field_type == APLType.NUMBER and not isinstance(value, (int, float)):
                errors.append(
                    ValidationIssue(
                        f"Operator '{operator.value}' on numeric field '{field_name}' requires numeric value.",
                        f"{path}.value"
                    )
                )
            elif field_type == APLType.STRING:
                errors.append(
                    ValidationIssue(
                        f"Operator '{operator.value}' cannot be applied to string field '{field_name}'.",
                        f"{path}.operator"
                    )
                )

        # String-specific operators
        if operator in (APLOperator.STARTS_WITH, APLOperator.ENDS_WITH, APLOperator.CONTAINS):
            if not isinstance(value, str):
                errors.append(
                    ValidationIssue(
                        f"String operator '{operator.value}' requires a string value.",
                        f"{path}.value"
                    )
                )
            if field_type not in (APLType.STRING, APLType.ANY):
                warnings.append(
                    ValidationIssue(
                        f"Operator '{operator.value}' applied to non-string field '{field_name}'.",
                        f"{path}.operator",
                        severity="WARNING"
                    )
                )
