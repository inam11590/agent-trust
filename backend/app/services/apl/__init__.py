"""AgentTrust Policy Language (APL/1.0) Service Package."""

from app.services.apl.diff import PolicySemanticDiff, RuleDiff, compute_policy_diff
from app.services.apl.evaluator import APLEvaluationResult, evaluate_apl_policy, resolve_field_value
from app.services.apl.linter import APLLinter, LintIssue
from app.services.apl.parser import APLParseError, compute_policy_content_hash, parse_policy_document
from app.services.apl.schema import (
    APLEffect,
    APLOperator,
    APLType,
    MAX_CONDITIONS_PER_RULE,
    MAX_DOCUMENT_SIZE,
    MAX_LIST_ELEMENTS,
    MAX_NESTING_DEPTH,
    MAX_RULES_PER_POLICY,
    SAFE_FIELD_REGISTRY,
)
from app.services.apl.templates import get_template_by_id, list_templates
from app.services.apl.validator import APLValidator, ValidationIssue, ValidationResult

__all__ = [
    "APLType",
    "APLEffect",
    "APLOperator",
    "SAFE_FIELD_REGISTRY",
    "MAX_DOCUMENT_SIZE",
    "MAX_RULES_PER_POLICY",
    "MAX_CONDITIONS_PER_RULE",
    "MAX_NESTING_DEPTH",
    "MAX_LIST_ELEMENTS",
    "APLParseError",
    "parse_policy_document",
    "compute_policy_content_hash",
    "APLValidator",
    "ValidationResult",
    "ValidationIssue",
    "APLLinter",
    "LintIssue",
    "evaluate_apl_policy",
    "APLEvaluationResult",
    "resolve_field_value",
    "compute_policy_diff",
    "PolicySemanticDiff",
    "RuleDiff",
    "list_templates",
    "get_template_by_id",
]
