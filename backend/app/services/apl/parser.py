"""Safe YAML and JSON Parser for APL/1.0 Documents."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Tuple
import yaml

from app.services.apl.schema import (
    MAX_DOCUMENT_SIZE,
    MAX_RULES_PER_POLICY,
    SUPPORTED_APL_VERSIONS,
)


class APLParseError(Exception):
    """Raised when an APL document is malformed or exceeds safety limits."""
    def __init__(self, message: str, path: str = "document"):
        super().__init__(f"{path}: {message}")
        self.message = message
        self.path = path


def compute_policy_content_hash(normalized_ast: Dict[str, Any]) -> str:
    """Compute stable, canonical SHA-256 content hash of normalized AST."""
    canon_bytes = json.dumps(normalized_ast, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canon_bytes).hexdigest()}"


def parse_policy_document(source_text: str, source_format: str = "yaml") -> Tuple[Dict[str, Any], str]:
    """
    Safely parse raw policy document into canonical normalized AST and content hash.
    
    Guarantees:
    - Enforces max document size (64 KB)
    - Strictly rejects unsafe YAML tags / code execution
    - Validates top-level structure and rule limits
    """
    if not source_text or not isinstance(source_text, str):
        raise APLParseError("Policy document must be non-empty string.", path="document")

    # 1. Size limit check
    raw_bytes = source_text.encode("utf-8")
    if len(raw_bytes) > MAX_DOCUMENT_SIZE:
        raise APLParseError(
            f"Policy document size ({len(raw_bytes)} bytes) exceeds maximum allowed {MAX_DOCUMENT_SIZE} bytes.",
            path="document"
        )

    # 2. Parse using SafeLoader or JSON
    parsed: Any = None
    try:
        if source_format.lower() == "json":
            parsed = json.loads(source_text)
        else:
            # YAML SafeLoader is strictly sandboxed (no arbitrary Python objects)
            parsed = yaml.safe_load(source_text)
    except Exception as exc:
        raise APLParseError(f"Syntax parsing failure: {str(exc)}", path="syntax") from exc

    if not isinstance(parsed, dict):
        raise APLParseError("Policy root element must be a mapping/object.", path="root")

    # 3. Version validation
    version = parsed.get("version")
    if not version or str(version).strip() not in SUPPORTED_APL_VERSIONS:
        raise APLParseError(
            f"Unsupported or missing policy version '{version}'. Supported: {sorted(SUPPORTED_APL_VERSIONS)}",
            path="version"
        )

    # 4. Mandatory fields
    name = parsed.get("name")
    if not name or not isinstance(name, str):
        raise APLParseError("Policy must specify a non-empty string 'name'.", path="name")

    rules = parsed.get("rules")
    if rules is None or not isinstance(rules, list):
        raise APLParseError("'rules' must be a list of rule definitions.", path="rules")

    if len(rules) > MAX_RULES_PER_POLICY:
        raise APLParseError(
            f"Rule count ({len(rules)}) exceeds maximum limit of {MAX_RULES_PER_POLICY} rules per policy.",
            path="rules"
        )

    # 5. Build Canonical AST
    normalized_ast: Dict[str, Any] = {
        "version": str(version).strip(),
        "name": str(name).strip(),
        "description": str(parsed.get("description") or "").strip(),
        "target": parsed.get("target") or {},
        "rules": rules,
        "default_effect": str(parsed.get("default_effect") or "DENY").upper(),
    }

    content_hash = compute_policy_content_hash(normalized_ast)
    return normalized_ast, content_hash
