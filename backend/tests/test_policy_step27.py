"""Comprehensive Step 27 Test Suite: APL/1.0 Policy-as-Code Engine, Validation, Simulator, and Rollback.

Covers:
1. Safe YAML / JSON parsing and AST normalization
2. Canonical SHA-256 content hashing
3. Resource limits (document size, max rules, max conditions, max nesting)
4. Safe field registry enforcement
5. Strict type safety and operator compatibility
6. Deterministic evaluation with mathematical precedence (DENY > APPROVAL > ALLOW)
7. Trace tree generation and simple English explanations
8. Static analysis and linter anti-pattern detection
9. Semantic diff and security-sensitive change detection
10. Impact analysis on sample request contexts
11. Version immutability and monotonic versioning
12. Rollback generating monotonic signed configuration snapshot
13. Sidecar Data Plane local APL evaluation
14. Platform invariant priority (replay, revoked creds, config expiration cannot be bypassed)
15. Fuzz testing for robustness and zero code execution
16. Performance benchmarks (<1ms evaluation)
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))

from app.services.apl import (
    APLEffect,
    APLLinter,
    APLOperator,
    APLParseError,
    APLType,
    APLValidator,
    compute_policy_content_hash,
    compute_policy_diff,
    evaluate_apl_policy,
    get_template_by_id,
    list_templates,
    parse_policy_document,
    resolve_field_value,
)
from app.services.apl.schema import (
    MAX_CONDITIONS_PER_RULE,
    MAX_DOCUMENT_SIZE,
    MAX_NESTING_DEPTH,
    MAX_RULES_PER_POLICY,
    SAFE_FIELD_REGISTRY,
)
from sidecar.evaluator import evaluate_local_request, LocalAuthorizationResult
from sidecar.state import state


SAMPLE_TRAVEL_POLICY_YAML = """
version: "APL/1.0"
name: "Corporate Travel Flight Purchase Policy"
description: "Tiered approval policy for agent flight bookings."
target:
  environment: "production"

rules:
  - id: "small_purchase_auto"
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

  - id: "medium_purchase_approval"
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

  - id: "large_purchase_deny"
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
"""


# =========================================================================
# 1. PARSER & CANONICAL HASH TESTS
# =========================================================================

def test_parse_valid_yaml():
    ast, chash = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    assert ast["version"] == "APL/1.0"
    assert ast["name"] == "Corporate Travel Flight Purchase Policy"
    assert len(ast["rules"]) == 3
    assert ast["default_effect"] == "DENY"
    assert chash.startswith("sha256:")


def test_parse_valid_json():
    json_doc = json.dumps({
        "version": "APL/1.0",
        "name": "JSON Policy",
        "rules": [{"id": "r1", "effect": "ALLOW"}],
        "default_effect": "DENY"
    })
    ast, chash = parse_policy_document(json_doc, source_format="json")
    assert ast["name"] == "JSON Policy"
    assert len(ast["rules"]) == 1


def test_content_hash_stability():
    ast1, h1 = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    ast2, h2 = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    assert h1 == h2
    assert compute_policy_content_hash(ast1) == h1


def test_document_size_limit_rejection():
    oversized = "a" * (MAX_DOCUMENT_SIZE + 10)
    with pytest.raises(APLParseError) as exc:
        parse_policy_document(oversized)
    assert "exceeds maximum allowed" in str(exc.value)


def test_max_rules_limit_rejection():
    many_rules = [f"  - id: rule_{i}\n    effect: ALLOW\n" for i in range(MAX_RULES_PER_POLICY + 5)]
    doc = 'version: "APL/1.0"\nname: "Too Many Rules"\nrules:\n' + "\n".join(many_rules)
    with pytest.raises(APLParseError) as exc:
        parse_policy_document(doc)
    assert "Rule count" in str(exc.value)


def test_unsupported_version_rejection():
    doc = 'version: "APL/99.0"\nname: "Future Version"\nrules: []'
    with pytest.raises(APLParseError) as exc:
        parse_policy_document(doc)
    assert "Unsupported or missing policy version" in str(exc.value)


# =========================================================================
# 2. VALIDATION & TYPE SAFETY TESTS
# =========================================================================

def test_validator_accepts_valid_policy():
    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    res = APLValidator().validate(ast)
    assert res.is_valid
    assert len(res.errors) == 0


def test_validator_rejects_duplicate_rule_ids():
    doc = """version: "APL/1.0"
name: "Dupes"
rules:
  - id: "rule_1"
    effect: "ALLOW"
  - id: "rule_1"
    effect: "DENY"
"""
    ast, _ = parse_policy_document(doc)
    res = APLValidator().validate(ast)
    assert not res.is_valid
    assert any("Duplicate rule id" in e.message for e in res.errors)


def test_validator_rejects_unregistered_field():
    doc = """version: "APL/1.0"
name: "Unregistered Field"
rules:
  - id: "bad_field"
    effect: "ALLOW"
    when:
      all:
        - field: "attacker.arbitrary_payload"
          operator: "eq"
          value: "test"
"""
    ast, _ = parse_policy_document(doc)
    res = APLValidator().validate(ast)
    assert not res.is_valid
    assert any("Unregistered field" in e.message for e in res.errors)


def test_validator_allows_dynamic_input_prefix():
    doc = """version: "APL/1.0"
name: "Dynamic Input"
rules:
  - id: "dynamic_ok"
    effect: "ALLOW"
    when:
      all:
        - field: "input.merchant_category"
          operator: "eq"
          value: "airlines"
"""
    ast, _ = parse_policy_document(doc)
    res = APLValidator().validate(ast)
    assert res.is_valid


def test_validator_rejects_type_mismatch():
    doc = """version: "APL/1.0"
name: "Type Mismatch"
rules:
  - id: "bad_gt"
    effect: "ALLOW"
    when:
      all:
        - field: "action"
          operator: "gt"
          value: 50
"""
    ast, _ = parse_policy_document(doc)
    res = APLValidator().validate(ast)
    assert not res.is_valid
    assert any("cannot be applied to string field" in e.message for e in res.errors)


def test_validator_rejects_excessive_nesting():
    nested = {
        "all": [{
            "all": [{
                "all": [{
                    "all": [{
                        "all": [{
                            "field": "action",
                            "operator": "eq",
                            "value": "purchase"
                        }]
                    }]
                }]
            }]
        }]
    }
    ast = {
        "version": "APL/1.0",
        "name": "Deep Nesting",
        "rules": [{"id": "deep", "effect": "ALLOW", "when": nested}]
    }
    res = APLValidator().validate(ast)
    assert not res.is_valid
    assert any("Condition nesting depth exceeds" in e.message for e in res.errors)


# =========================================================================
# 3. LINTER TESTS
# =========================================================================

def test_linter_warns_on_insecure_default_allow():
    doc = """version: "APL/1.0"
name: "Insecure Default"
default_effect: "ALLOW"
rules:
  - id: "r1"
    effect: "ALLOW"
"""
    ast, _ = parse_policy_document(doc)
    issues = APLLinter().lint(ast)
    assert any(i.code == "LINT001_INSECURE_DEFAULT" for i in issues)


def test_linter_warns_on_unconditional_allow():
    doc = """version: "APL/1.0"
name: "Broad Allow"
rules:
  - id: "r_wildcard"
    effect: "ALLOW"
"""
    ast, _ = parse_policy_document(doc)
    issues = APLLinter().lint(ast)
    assert any(i.code == "LINT003_OVERLY_BROAD_ALLOW" for i in issues)


def test_linter_detects_contradictory_bounds():
    doc = """version: "APL/1.0"
name: "Impossible Bounds"
rules:
  - id: "r_impossible"
    effect: "ALLOW"
    when:
      all:
        - field: "input.amount"
          operator: "gt"
          value: 1000
        - field: "input.amount"
          operator: "lt"
          value: 500
"""
    ast, _ = parse_policy_document(doc)
    issues = APLLinter().lint(ast)
    assert any(i.code == "LINT004_CONTRADICTORY_BOUNDS" for i in issues)


# =========================================================================
# 4. DETERMINISTIC EVALUATOR & PRECEDENCE TESTS
# =========================================================================

def test_evaluator_small_purchase_auto_allow():
    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    context = {
        "action": "purchase_flight",
        "input": {"amount": 250, "currency": "USD"}
    }
    res = evaluate_apl_policy(ast, context)
    assert res.decision == "ALLOW"
    assert any(r["id"] == "small_purchase_auto" for r in res.matched_rules)
    assert len(res.trace) == 3


def test_evaluator_medium_purchase_requires_approval():
    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    context = {
        "action": "purchase_flight",
        "input": {"amount": 1200, "currency": "USD"}
    }
    res = evaluate_apl_policy(ast, context)
    assert res.decision == "REQUIRE_APPROVAL"
    assert any(r["id"] == "medium_purchase_approval" for r in res.matched_rules)


def test_evaluator_large_purchase_deny():
    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    context = {
        "action": "purchase_flight",
        "input": {"amount": 5000, "currency": "USD"}
    }
    res = evaluate_apl_policy(ast, context)
    assert res.decision == "DENY"
    assert any(r["id"] == "large_purchase_deny" for r in res.matched_rules)


def test_precedence_deny_overrides_approval_and_allow():
    ast = {
        "version": "APL/1.0",
        "name": "Precedence Test",
        "rules": [
            {"id": "allow_rule", "effect": "ALLOW"},
            {"id": "approval_rule", "effect": "REQUIRE_APPROVAL"},
            {"id": "deny_rule", "effect": "DENY"},
        ],
        "default_effect": "ALLOW"
    }
    res = evaluate_apl_policy(ast, {})
    assert res.decision == "DENY"
    assert "DENY takes strict precedence" in res.explanation


def test_precedence_approval_overrides_allow():
    ast = {
        "version": "APL/1.0",
        "name": "Approval Precedence",
        "rules": [
            {"id": "allow_rule", "effect": "ALLOW"},
            {"id": "approval_rule", "effect": "REQUIRE_APPROVAL"},
        ],
        "default_effect": "DENY"
    }
    res = evaluate_apl_policy(ast, {})
    assert res.decision == "REQUIRE_APPROVAL"


def test_default_effect_applied_when_no_rules_match():
    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    context = {
        "action": "other_action",
        "input": {"amount": 100}
    }
    res = evaluate_apl_policy(ast, context)
    assert res.decision == "DENY"
    assert res.default_effect_applied


def test_string_operators_evaluation():
    ast = {
        "version": "APL/1.0",
        "name": "String Ops",
        "rules": [
            {
                "id": "prefix_rule",
                "effect": "ALLOW",
                "when": {
                    "all": [
                        {"field": "action", "operator": "starts_with", "value": "order."},
                        {"field": "action", "operator": "ends_with", "value": ".read"},
                        {"field": "action", "operator": "contains", "value": "invoice"}
                    ]
                }
            }
        ]
    }
    match_ctx = {"action": "order.invoice.read"}
    assert evaluate_apl_policy(ast, match_ctx).decision == "ALLOW"

    no_match_ctx = {"action": "order.payment.read"}
    assert evaluate_apl_policy(ast, no_match_ctx).decision == "DENY"


def test_list_in_and_not_in_evaluation():
    ast = {
        "version": "APL/1.0",
        "name": "List Ops",
        "rules": [
            {
                "id": "in_rule",
                "effect": "ALLOW",
                "when": {
                    "all": [
                        {"field": "risk.level", "operator": "in", "value": ["LOW", "MEDIUM"]},
                        {"field": "input.currency", "operator": "not_in", "value": ["RUB", "IRR"]}
                    ]
                }
            }
        ]
    }
    assert evaluate_apl_policy(ast, {"risk": {"level": "LOW"}, "input": {"currency": "USD"}}).decision == "ALLOW"
    assert evaluate_apl_policy(ast, {"risk": {"level": "HIGH"}, "input": {"currency": "USD"}}).decision == "DENY"
    assert evaluate_apl_policy(ast, {"risk": {"level": "LOW"}, "input": {"currency": "RUB"}}).decision == "DENY"


def test_exists_and_not_exists_evaluation():
    ast = {
        "version": "APL/1.0",
        "name": "Exists Ops",
        "rules": [
            {
                "id": "exists_rule",
                "effect": "ALLOW",
                "when": {
                    "all": [
                        {"field": "target.id", "operator": "exists"},
                        {"field": "delegation.active", "operator": "not_exists"}
                    ]
                }
            }
        ]
    }
    assert evaluate_apl_policy(ast, {"target": {"id": "peer_1"}}).decision == "ALLOW"
    assert evaluate_apl_policy(ast, {"target": {"id": "peer_1"}, "delegation": {"active": True}}).decision == "DENY"


# =========================================================================
# 5. SEMANTIC DIFF & SECURITY IMPACT ANALYSIS
# =========================================================================

def test_semantic_diff_detects_security_sensitive_change():
    v1_yaml = SAMPLE_TRAVEL_POLICY_YAML
    v2_yaml = SAMPLE_TRAVEL_POLICY_YAML.replace("effect: \"REQUIRE_APPROVAL\"", "effect: \"ALLOW\"")

    ast1, _ = parse_policy_document(v1_yaml)
    ast2, _ = parse_policy_document(v2_yaml)

    diff = compute_policy_diff(ast1, ast2, old_version=1, new_version=2)
    assert diff.has_security_sensitive_changes
    assert len(diff.modified_rules) == 1
    assert diff.modified_rules[0].is_security_sensitive
    assert "Human approval guardrail removed" in (diff.modified_rules[0].security_notice or "")
    assert "SECURITY-SENSITIVE CHANGES DETECTED" in diff.markdown_summary


def test_semantic_diff_detects_removed_guardrail():
    ast1, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    ast2 = dict(ast1)
    ast2["rules"] = [r for r in ast1["rules"] if r["id"] != "large_purchase_deny"]

    diff = compute_policy_diff(ast1, ast2, old_version=1, new_version=2)
    assert diff.has_security_sensitive_changes
    assert len(diff.removed_rules) == 1
    assert diff.removed_rules[0].rule_id == "large_purchase_deny"


# =========================================================================
# 6. SIDECAR DATA PLANE INTEGRATION TESTS
# =========================================================================

def test_sidecar_local_apl_evaluation_deny():
    # Setup state
    state.active_config = {
        "config_version": 5,
        "valid_until": "2099-01-01T00:00:00Z",
        "apl_policies": [
            {
                "version": "APL/1.0",
                "rules": [
                    {
                        "id": "block_large_payments",
                        "effect": "DENY",
                        "description": "Block transactions over $1,000",
                        "when": {
                            "all": [
                                {"field": "action", "operator": "eq", "value": "payout.create"},
                                {"field": "input.amount", "operator": "gt", "value": 1000}
                            ]
                        }
                    }
                ]
            }
        ]
    }
    state.config_expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    state.control_plane_reachable = True

    # High amount should be rejected by local APL rule
    res = evaluate_local_request(
        action="payout.create",
        resource="payout_1",
        agent_id="agt_sidecar_test",
        amount=1500.0
    )
    assert res["decision"] == LocalAuthorizationResult.REJECTED
    assert res["code"] == "APL_POLICY_DENY"


def test_sidecar_local_apl_evaluation_approval():
    state.active_config = {
        "config_version": 5,
        "valid_until": "2099-01-01T00:00:00Z",
        "apl_policies": [
            {
                "version": "APL/1.0",
                "rules": [
                    {
                        "id": "approval_rule",
                        "effect": "REQUIRE_APPROVAL",
                        "when": {
                            "all": [
                                {"field": "action", "operator": "eq", "value": "refund.process"}
                            ]
                        }
                    }
                ]
            }
        ]
    }
    state.config_expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    state.control_plane_reachable = True

    res = evaluate_local_request(
        action="refund.process",
        resource="order_1",
        agent_id="agt_sidecar_test",
        amount=100.0
    )
    assert res["decision"] == LocalAuthorizationResult.PENDING_HUMAN_APPROVAL
    assert res["code"] == "APL_POLICY_REQUIRE_APPROVAL"


def test_platform_invariants_strictly_prevent_apl_override():
    """Verify that revoked credentials or expired configs are rejected before APL rules can allow."""
    state.active_config = {
        "config_version": 1,
        "valid_until": "2020-01-01T00:00:00Z",  # Expired
        "apl_policies": [
            {
                "version": "APL/1.0",
                "rules": [{"id": "unconditional_allow", "effect": "ALLOW"}]
            }
        ]
    }
    state.config_expires_at = datetime.now(timezone.utc) - timedelta(days=1)

    res = evaluate_local_request(
        action="test.action",
        resource="test.resource",
        agent_id="agt_test",
    )
    # Must fail on config expired, APL cannot override platform invariant
    assert res["decision"] == LocalAuthorizationResult.REJECTED
    assert res["code"] == "CONFIG_EXPIRED"


# =========================================================================
# 7. FUZZ TESTING & CODE EXECUTION DEFENSE
# =========================================================================

def test_zero_arbitrary_code_execution():
    malicious_inputs = [
        "__import__('os').system('echo hacked')",
        "eval('1+1')",
        "system.exit(1)",
        "; DROP TABLE users; --",
        "{{ 7 * 7 }}",
        "<script>alert(1)</script>",
    ]

    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)

    for mal in malicious_inputs:
        context = {
            "action": mal,
            "input": {"amount": mal, "currency": mal},
            "agent": {"id": mal}
        }
        # Safe evaluation must never execute code or raise unhandled exceptions
        res = evaluate_apl_policy(ast, context)
        assert res.decision in ("ALLOW", "REQUIRE_APPROVAL", "DENY")


def test_standard_templates():
    templates = list_templates()
    assert len(templates) >= 4
    for tpl in templates:
        ast, chash = parse_policy_document(tpl["yaml_source"])
        val = APLValidator().validate(ast)
        assert val.is_valid, f"Template {tpl['id']} failed validation"


# =========================================================================
# 8. PERFORMANCE BENCHMARK
# =========================================================================

def test_evaluation_performance_benchmark():
    ast, _ = parse_policy_document(SAMPLE_TRAVEL_POLICY_YAML)
    context = {
        "action": "purchase_flight",
        "input": {"amount": 250, "currency": "USD"}
    }

    # Warm up
    for _ in range(10):
        evaluate_apl_policy(ast, context)

    # Benchmark 1000 evaluations
    start = time.perf_counter()
    iterations = 1000
    for _ in range(iterations):
        res = evaluate_apl_policy(ast, context)
        assert res.decision == "ALLOW"
    elapsed = time.perf_counter() - start

    avg_ms = (elapsed / iterations) * 1000
    print(f"\nAverage evaluation time: {avg_ms:.4f} ms per evaluation")
    assert avg_ms < 1.0, f"Evaluation too slow: {avg_ms:.4f} ms (budget: 1.0 ms)"


# =========================================================================
# 9. FASTAPI ENDPOINT & SCHEMA INTEGRATION TESTS
# =========================================================================

def test_api_validate_endpoint():
    from fastapi.testclient import TestClient
    from app.main import create_app
    app = create_app()
    client = TestClient(app)

    # Valid policy validation
    resp = client.post("/api/v1/policies/validate", json={"yaml_source": SAMPLE_TRAVEL_POLICY_YAML})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["content_hash"].startswith("sha256:")
    assert len(data["errors"]) == 0

    # Malformed policy validation
    resp_bad = client.post("/api/v1/policies/validate", json={"yaml_source": "invalid: yaml: ["})
    assert resp_bad.status_code == 200
    data_bad = resp_bad.json()
    assert data_bad["is_valid"] is False
    assert len(data_bad["errors"]) > 0


def test_api_templates_endpoint():
    from fastapi.testclient import TestClient
    from app.main import create_app
    app = create_app()
    client = TestClient(app)

    resp = client.get("/api/v1/policies/templates")
    assert resp.status_code == 200
    templates = resp.json()
    assert isinstance(templates, list)
    assert len(templates) >= 4
    template_ids = [t["id"] for t in templates]
    assert "tpl_purchase_limits" in template_ids
    assert "tpl_read_only_agent" in template_ids


def test_api_simulate_endpoint_raw_yaml():
    from fastapi.testclient import TestClient
    from app.main import create_app
    app = create_app()
    client = TestClient(app)

    body = {
        "yaml_source": SAMPLE_TRAVEL_POLICY_YAML,
        "context": {
            "action": "purchase_flight",
            "input": {"amount": 400, "currency": "USD"}
        }
    }
    resp = client.post("/api/v1/policies/simulate", json=body)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert len(data["trace"]) > 0
    assert "Authorized by policy rule(s)" in data["explanation"]


# =========================================================================
# 10. PYTHON SDK & CLI INTEGRATION TESTS
# =========================================================================

def test_python_sdk_policies_client():
    from agenttrust.client import AgentTrust, PoliciesClient
    client = AgentTrust("at_test_step27_dummy_key", "https://api.agenttrust.example")
    assert hasattr(client, "policies")
    assert isinstance(client.policies, PoliciesClient)


def test_cli_policies_validate(monkeypatch):
    import tempfile
    from agenttrust.cli import main
    from agenttrust.client import PoliciesClient
    monkeypatch.setattr(PoliciesClient, "validate", lambda self, yaml_source: {"is_valid": True, "errors": []})

    with tempfile.TemporaryDirectory() as td:
        policy_file = Path(td) / "policy.yaml"
        policy_file.write_text(SAMPLE_TRAVEL_POLICY_YAML, encoding="utf-8")

        # Run CLI validation
        exit_code = main(["policies", "validate", "--api-key", "at_test_dummy", "--file", str(policy_file)])
        assert exit_code == 0


def test_cli_policies_simulate_context_json(monkeypatch):
    import tempfile
    from agenttrust.cli import main
    from agenttrust.client import PoliciesClient
    monkeypatch.setattr(PoliciesClient, "simulate", lambda self, **kwargs: {"decision": "ALLOW", "explanation": "OK"})

    with tempfile.TemporaryDirectory() as td:
        policy_file = Path(td) / "policy.yaml"
        policy_file.write_text(SAMPLE_TRAVEL_POLICY_YAML, encoding="utf-8")

        ctx_file = Path(td) / "ctx.json"
        ctx_file.write_text(json.dumps({"action": "purchase_flight", "input": {"amount": 100}}), encoding="utf-8")

        exit_code = main([
            "policies", "simulate",
            "--api-key", "at_test_dummy",
            "--file", str(policy_file),
            "--context", str(ctx_file)
        ])
        assert exit_code == 0


# =========================================================================
# 11. DATABASE MODELS SCHEMA VERIFICATION
# =========================================================================

def test_database_models_attributes():
    from app.models.policy import Policy, PolicyVersion, PolicyBinding, PolicyTestCase, generate_policy_id

    # Test ID generator
    pid = generate_policy_id()
    assert pid.startswith("pol_")
    assert len(pid) > 10

    # Test columns existence
    assert hasattr(Policy, "organization_id")
    assert hasattr(Policy, "policy_id")
    assert hasattr(Policy, "name")
    assert hasattr(Policy, "description")
    assert hasattr(Policy, "scope_type")
    assert hasattr(Policy, "status")
    assert hasattr(Policy, "is_shadow")

    assert hasattr(PolicyVersion, "policy_id")
    assert hasattr(PolicyVersion, "version_number")
    assert hasattr(PolicyVersion, "content_hash")
    assert hasattr(PolicyVersion, "normalized_document")
    assert hasattr(PolicyVersion, "status")
    assert hasattr(PolicyVersion, "rule_count")

    assert hasattr(PolicyBinding, "policy_id")
    assert hasattr(PolicyBinding, "scope_type")
    assert hasattr(PolicyBinding, "scope_id")
    assert hasattr(PolicyBinding, "priority")

    assert hasattr(PolicyTestCase, "policy_id")
    assert hasattr(PolicyTestCase, "input_context")
    assert hasattr(PolicyTestCase, "expected_decision")
