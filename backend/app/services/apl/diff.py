"""APL/1.0 Semantic Diff and Security Impact Analysis Engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RuleDiff:
    rule_id: str
    change_type: str  # "ADDED", "REMOVED", "MODIFIED"
    old_effect: Optional[str] = None
    new_effect: Optional[str] = None
    old_rule: Optional[Dict[str, Any]] = None
    new_rule: Optional[Dict[str, Any]] = None
    is_security_sensitive: bool = False
    security_notice: Optional[str] = None


@dataclass
class PolicySemanticDiff:
    old_version: int
    new_version: int
    added_rules: List[RuleDiff] = field(default_factory=list)
    removed_rules: List[RuleDiff] = field(default_factory=list)
    modified_rules: List[RuleDiff] = field(default_factory=list)
    default_effect_changed: bool = False
    old_default_effect: Optional[str] = None
    new_default_effect: Optional[str] = None
    has_security_sensitive_changes: bool = False
    markdown_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "old_version": self.old_version,
            "new_version": self.new_version,
            "added_rules": [
                {
                    "rule_id": r.rule_id,
                    "change_type": r.change_type,
                    "new_effect": r.new_effect,
                    "is_security_sensitive": r.is_security_sensitive,
                    "security_notice": r.security_notice
                } for r in self.added_rules
            ],
            "removed_rules": [
                {
                    "rule_id": r.rule_id,
                    "change_type": r.change_type,
                    "old_effect": r.old_effect,
                    "is_security_sensitive": r.is_security_sensitive,
                    "security_notice": r.security_notice
                } for r in self.removed_rules
            ],
            "modified_rules": [
                {
                    "rule_id": r.rule_id,
                    "change_type": r.change_type,
                    "old_effect": r.old_effect,
                    "new_effect": r.new_effect,
                    "is_security_sensitive": r.is_security_sensitive,
                    "security_notice": r.security_notice
                } for r in self.modified_rules
            ],
            "default_effect_changed": self.default_effect_changed,
            "old_default_effect": self.old_default_effect,
            "new_default_effect": self.new_default_effect,
            "has_security_sensitive_changes": self.has_security_sensitive_changes,
            "markdown_summary": self.markdown_summary
        }


def compute_policy_diff(
    old_ast: Dict[str, Any],
    new_ast: Dict[str, Any],
    old_version: int = 1,
    new_version: int = 2
) -> PolicySemanticDiff:
    """Compute rich semantic diff highlighting security impact between two policy versions."""
    diff = PolicySemanticDiff(old_version=old_version, new_version=new_version)

    old_rules_map = {r.get("id"): r for r in old_ast.get("rules", []) if r.get("id")}
    new_rules_map = {r.get("id"): r for r in new_ast.get("rules", []) if r.get("id")}

    old_default = str(old_ast.get("default_effect", "DENY")).upper()
    new_default = str(new_ast.get("default_effect", "DENY")).upper()

    if old_default != new_default:
        diff.default_effect_changed = True
        diff.old_default_effect = old_default
        diff.new_default_effect = new_default
        if new_default == "ALLOW":
            diff.has_security_sensitive_changes = True

    # 1. Added rules
    for r_id, new_rule in new_rules_map.items():
        if r_id not in old_rules_map:
            new_eff = str(new_rule.get("effect", "")).upper()
            is_sec = False
            sec_msg = None
            if new_eff == "ALLOW":
                is_sec = True
                sec_msg = "New ALLOW rule broadens agent permissions."
                diff.has_security_sensitive_changes = True
            diff.added_rules.append(
                RuleDiff(
                    rule_id=r_id,
                    change_type="ADDED",
                    new_effect=new_eff,
                    new_rule=new_rule,
                    is_security_sensitive=is_sec,
                    security_notice=sec_msg
                )
            )

    # 2. Removed rules
    for r_id, old_rule in old_rules_map.items():
        if r_id not in new_rules_map:
            old_eff = str(old_rule.get("effect", "")).upper()
            is_sec = False
            sec_msg = None
            if old_eff in ("DENY", "REQUIRE_APPROVAL"):
                is_sec = True
                sec_msg = f"Removed existing guardrail rule ({old_eff})."
                diff.has_security_sensitive_changes = True
            diff.removed_rules.append(
                RuleDiff(
                    rule_id=r_id,
                    change_type="REMOVED",
                    old_effect=old_eff,
                    old_rule=old_rule,
                    is_security_sensitive=is_sec,
                    security_notice=sec_msg
                )
            )

    # 3. Modified rules
    for r_id, new_rule in new_rules_map.items():
        if r_id in old_rules_map:
            old_rule = old_rules_map[r_id]
            if json.dumps(old_rule, sort_keys=True) != json.dumps(new_rule, sort_keys=True):
                old_eff = str(old_rule.get("effect", "")).upper()
                new_eff = str(new_rule.get("effect", "")).upper()

                is_sec = False
                sec_msg = None

                # Check effect elevation: DENY -> REQUIRE_APPROVAL/ALLOW or REQUIRE_APPROVAL -> ALLOW
                if old_eff == "DENY" and new_eff != "DENY":
                    is_sec = True
                    sec_msg = f"Effect weakened from DENY to {new_eff}."
                    diff.has_security_sensitive_changes = True
                elif old_eff == "REQUIRE_APPROVAL" and new_eff == "ALLOW":
                    is_sec = True
                    sec_msg = "Human approval guardrail removed (now ALLOW)."
                    diff.has_security_sensitive_changes = True

                diff.modified_rules.append(
                    RuleDiff(
                        rule_id=r_id,
                        change_type="MODIFIED",
                        old_effect=old_eff,
                        new_effect=new_eff,
                        old_rule=old_rule,
                        new_rule=new_rule,
                        is_security_sensitive=is_sec,
                        security_notice=sec_msg
                    )
                )

    # Build markdown summary
    lines = [f"### Policy Diff: Version {old_version} -> Version {new_version}"]
    if diff.has_security_sensitive_changes:
        lines.append("\n> [!WARNING] **SECURITY-SENSITIVE CHANGES DETECTED**")
        lines.append("> This update broadens authority, relaxes approvals, or removes protective deny rules.")

    if diff.default_effect_changed:
        lines.append(f"\n- **Default Effect:** `{diff.old_default_effect}` -> `{diff.new_default_effect}`")

    if diff.added_rules:
        lines.append("\n**Added Rules:**")
        for r in diff.added_rules:
            badge = " ⚠️ *(Security Sensitive)*" if r.is_security_sensitive else ""
            lines.append(f"- `+{r.rule_id}` (Effect: `{r.new_effect}`){badge}")

    if diff.removed_rules:
        lines.append("\n**Removed Rules:**")
        for r in diff.removed_rules:
            badge = " ⚠️ *(Security Sensitive)*" if r.is_security_sensitive else ""
            lines.append(f"- `-{r.rule_id}` (Was: `{r.old_effect}`){badge}")

    if diff.modified_rules:
        lines.append("\n**Modified Rules:**")
        for r in diff.modified_rules:
            badge = f" ⚠️ *({r.security_notice})*" if r.is_security_sensitive else ""
            lines.append(f"- `~{r.rule_id}`: `{r.old_effect}` -> `{r.new_effect}`{badge}")

    diff.markdown_summary = "\n".join(lines)
    return diff
