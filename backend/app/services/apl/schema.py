"""Safe Field Registry, Type Definitions, and Operator Compatibility for APL/1.0."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set


class APLType(str, Enum):
    STRING = "STRING"
    NUMBER = "NUMBER"
    BOOLEAN = "BOOLEAN"
    ENUM = "ENUM"
    TIMESTAMP = "TIMESTAMP"
    LIST = "LIST"
    ANY = "ANY"


class APLEffect(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    NO_MATCH = "NO_MATCH"


class APLOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    CONTAINS = "contains"


# Maximum complexity limits for DoS defense
MAX_DOCUMENT_SIZE = 65536  # 64 KB
MAX_RULES_PER_POLICY = 50
MAX_CONDITIONS_PER_RULE = 20
MAX_NESTING_DEPTH = 4
MAX_LIST_ELEMENTS = 100

SUPPORTED_APL_VERSIONS = {"APL/1.0"}

# Safe field registry: strict mapping of allowed context paths to data types
SAFE_FIELD_REGISTRY: Dict[str, APLType] = {
    # Requesting Agent Identity
    "agent.id": APLType.STRING,
    "agent.type": APLType.STRING,
    "agent.organization_id": APLType.STRING,
    "agent.status": APLType.STRING,

    # Capability and Action
    "action": APLType.STRING,
    "capability": APLType.STRING,
    "resource": APLType.STRING,

    # Standard Transaction Inputs
    "input.amount": APLType.NUMBER,
    "input.currency": APLType.STRING,
    "input.destination": APLType.STRING,
    "input.recipient": APLType.STRING,

    # Target Peer / Service Identity
    "target.id": APLType.STRING,
    "target.type": APLType.STRING,
    "target.organization_id": APLType.STRING,

    # Verifiable Credentials (ATC/1.0)
    "credential.type": APLType.STRING,
    "credential.issuer": APLType.STRING,
    "credential.valid": APLType.BOOLEAN,

    # Cross-Organization Trust
    "trust.status": APLType.ENUM,
    "trust.relationship_id": APLType.STRING,

    # Delegation Chain
    "delegation.depth": APLType.NUMBER,
    "delegation.active": APLType.BOOLEAN,

    # Risk Assessment
    "risk.level": APLType.ENUM,
    "risk.score": APLType.NUMBER,

    # Infrastructure & Environment Context
    "environment": APLType.ENUM,
    "gateway.id": APLType.STRING,
    "gateway.deployment_type": APLType.STRING,

    # Temporal Context (Explicitly UTC bounded)
    "time.hour": APLType.NUMBER,
    "time.day_of_week": APLType.NUMBER,
    "timestamp": APLType.TIMESTAMP,
}

# Operator compatibility rules
OPERATOR_TYPE_COMPATIBILITY: Dict[APLOperator, Set[APLType]] = {
    APLOperator.EQ: {APLType.STRING, APLType.NUMBER, APLType.BOOLEAN, APLType.ENUM, APLType.TIMESTAMP, APLType.ANY},
    APLOperator.NEQ: {APLType.STRING, APLType.NUMBER, APLType.BOOLEAN, APLType.ENUM, APLType.TIMESTAMP, APLType.ANY},
    APLOperator.GT: {APLType.NUMBER, APLType.TIMESTAMP},
    APLOperator.GTE: {APLType.NUMBER, APLType.TIMESTAMP},
    APLOperator.LT: {APLType.NUMBER, APLType.TIMESTAMP},
    APLOperator.LTE: {APLType.NUMBER, APLType.TIMESTAMP},
    APLOperator.IN: {APLType.STRING, APLType.NUMBER, APLType.ENUM, APLType.ANY},
    APLOperator.NOT_IN: {APLType.STRING, APLType.NUMBER, APLType.ENUM, APLType.ANY},
    APLOperator.EXISTS: {APLType.STRING, APLType.NUMBER, APLType.BOOLEAN, APLType.ENUM, APLType.TIMESTAMP, APLType.LIST, APLType.ANY},
    APLOperator.NOT_EXISTS: {APLType.STRING, APLType.NUMBER, APLType.BOOLEAN, APLType.ENUM, APLType.TIMESTAMP, APLType.LIST, APLType.ANY},
    APLOperator.STARTS_WITH: {APLType.STRING},
    APLOperator.ENDS_WITH: {APLType.STRING},
    APLOperator.CONTAINS: {APLType.STRING},
}


def is_known_field(field_path: str) -> bool:
    """Check if field is explicitly registered or matches dynamic input prefix."""
    if field_path in SAFE_FIELD_REGISTRY:
        return True
    if field_path.startswith("input."):
        # Dynamic capability input fields are allowed if prefixed with 'input.'
        return True
    return False


def get_field_type(field_path: str) -> APLType:
    """Retrieve declared or dynamic type for field."""
    if field_path in SAFE_FIELD_REGISTRY:
        return SAFE_FIELD_REGISTRY[field_path]
    if field_path.startswith("input."):
        return APLType.ANY
    return APLType.ANY
