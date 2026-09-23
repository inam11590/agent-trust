"""Discovery Candidate Matching, Fingerprinting & Deduplication Service (Step 29).

Enforces:
- Deterministic stable fingerprinting
- Cryptographic / explicit ID = VERIFIED_MATCH
- Name similarity = POSSIBLE_MATCH (Never auto-merged!)
- Distinguishes INFERRED vs VERIFIED relationships
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.agent import Agent
from app.services.discovery.connectors.base import DiscoveredResource


def compute_discovery_fingerprint(resource: DiscoveredResource) -> str:
    """Compute deterministic SHA256 fingerprint for duplicate candidate correlation.
    
    NOTE: A fingerprint is solely for inventory correlation; it is NEVER an identity proof.
    """
    canonical_tokens = [
        resource.candidate_type.upper().strip(),
        (resource.location_reference or "").lower().strip(),
        (resource.external_reference or "").lower().strip(),
        (resource.image_name or "").lower().strip(),
        (resource.environment or "unknown").lower().strip(),
    ]
    raw_str = "|".join(canonical_tokens)
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


def match_candidate_with_inventory(
    db: Session,
    organization_id: UUID,
    resource: DiscoveredResource,
    findings: Dict[str, Any],
) -> Tuple[Optional[Agent], Optional[str], List[str]]:
    """Match a discovered resource against the authoritative Step 28 Agent inventory.
    
    Returns:
        (matched_agent, match_type, match_reasons)
        where match_type in (VERIFIED_MATCH, STRONG_MATCH, POSSIBLE_MATCH, None)
    """
    # 1. Check for Explicit AgentTrust Agent ID (VERIFIED_MATCH)
    explicit_id = None
    if "agenttrust.io/agent-id" in resource.labels:
        explicit_id = resource.labels["agenttrust.io/agent-id"]
    elif "raw_metadata" in resource.raw_metadata and "observed_agent_id" in resource.raw_metadata:
        explicit_id = resource.raw_metadata["observed_agent_id"]

    if explicit_id:
        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == organization_id,
                Agent.agent_identifier == explicit_id,
            )
        )
        if agent:
            return (
                agent,
                "VERIFIED_MATCH",
                [f"Matched verified AgentTrust Agent ID '{agent.agent_identifier}' from metadata."],
            )

    # 2. Check for External Resource Reference match (STRONG_MATCH)
    if resource.external_reference:
        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == organization_id,
                Agent.external_reference == resource.external_reference,
            )
        )
        if agent:
            return (
                agent,
                "STRONG_MATCH",
                [f"Matched registered agent external reference '{resource.external_reference}'."],
            )

    # 3. Check for Name Similarity (POSSIBLE_MATCH ONLY - NEVER AUTO-MERGED!)
    clean_name = resource.display_name.lower().replace("-", "").replace("_", "").strip()
    agents = db.scalars(
        select(Agent).where(Agent.organization_id == organization_id)
    ).all()

    for ag in agents:
        ag_clean = ag.name.lower().replace("-", "").replace("_", "").strip()
        if clean_name == ag_clean or clean_name in ag_clean or ag_clean in clean_name:
            return (
                ag,
                "POSSIBLE_MATCH",
                [
                    f"Possible name similarity with registered agent '{ag.name}' ({ag.agent_identifier}).",
                    "Requires human review. Never automatically merged.",
                ],
            )

    return None, None, []


def build_candidate_relationships(
    resource: DiscoveredResource,
    matched_agent: Optional[Agent],
    match_type: Optional[str],
    findings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Assemble structured relationships distinguishing VERIFIED vs INFERRED ties."""
    relationships = list(resource.relationships)

    # If matched agent exists
    if matched_agent and match_type:
        confidence = "VERIFIED" if match_type == "VERIFIED_MATCH" else "INFERRED"
        relationships.append({
            "type": "MATCHES_AGENT",
            "target": matched_agent.agent_identifier,
            "target_name": matched_agent.name,
            "target_id": str(matched_agent.id),
            "confidence": confidence,
            "match_type": match_type,
        })

    # AI Model Providers inferred
    for prov in findings.get("providers_detected", []):
        relationships.append({
            "type": "USES_MODEL_PROVIDER",
            "target": prov,
            "confidence": "INFERRED",
        })

    # Frameworks inferred
    for fw in findings.get("frameworks_detected", []):
        relationships.append({
            "type": "USES_FRAMEWORK",
            "target": fw,
            "confidence": "INFERRED",
        })

    return relationships
