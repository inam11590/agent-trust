"""AgentTrust Agent Discovery Engine (Step 29).

Central orchestrator for:
- DiscoverySource lifecycle and execution
- Connector orchestration with SecretProvider
- Evidence collection and deterministic confidence scoring
- Candidate deduplication and fingerprint correlation
- Known-agent matching (Verified vs Strong vs Possible)
- Unmanaged & Shadow AI detection and governance signals
- Review actions: Match, Ignore (with expiry), False-Positive, Stale detection
- Safe onboarding into Step 28 lifecycle (DRAFT -> REGISTERED -> REVIEW_REQUIRED)
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import io
import json
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.secrets import get_secret_provider
from app.models.agent import Agent, AgentStatus
from app.models.discovery import (
    ConfidenceLevel,
    DiscoveryCandidate,
    DiscoveryCandidateStatus,
    DiscoveryCandidateType,
    DiscoveryEvidence,
    DiscoveryRun,
    DiscoveryRunStatus,
    DiscoverySource,
    DiscoverySourceStatus,
    EvidenceCategory,
    EvidenceStrength,
    generate_candidate_id,
    generate_discovery_run_id,
    generate_discovery_source_id,
    generate_evidence_id,
)
from app.models.organization import SecurityEvent
from app.services.discovery.classifier import classify_workload_evidence
from app.services.discovery.connectors import get_connector
from app.services.discovery.connectors.base import DiscoveredResource
from app.services.discovery.matcher import (
    build_candidate_relationships,
    compute_discovery_fingerprint,
    match_candidate_with_inventory,
)


def create_discovery_source(
    db: Session,
    organization_id: UUID,
    name: str,
    source_type: str,
    configuration: Dict[str, Any],
    credential_reference: Optional[str] = None,
    created_by: Optional[UUID] = None,
) -> DiscoverySource:
    """Create a new discovery source connector."""
    source = DiscoverySource(
        organization_id=organization_id,
        name=name,
        source_type=source_type,
        status=DiscoverySourceStatus.CONFIGURED.value,
        configuration=configuration or {},
        credential_reference=credential_reference,
        created_by=created_by,
    )
    db.add(source)
    db.commit()
    db.refresh(source)

    # Security event
    db.add(
        SecurityEvent(
            organization_id=organization_id,
            event_type="discovery_source_created",
            severity="info",
            description=f"Discovery source '{source.name}' ({source.source_type}) was created.",
            details={
                "source_id": source.source_id,
                "source_type": source.source_type,
                "created_by": str(created_by) if created_by else "system",
            },
        )
    )
    db.commit()
    return source


def execute_discovery_run(
    db: Session,
    source_id: UUID | str,
    trigger_type: str = "MANUAL",
) -> DiscoveryRun:
    """Execute a discovery scan against an infrastructure connector."""
    now_utc = datetime.now(timezone.utc)

    # Resolve source
    if isinstance(source_id, str):
        source = db.scalar(
            select(DiscoverySource).where(
                or_(DiscoverySource.source_id == source_id, DiscoverySource.id == source_id)
            )
        )
    else:
        source = db.scalar(select(DiscoverySource).where(DiscoverySource.id == source_id))

    if not source:
        raise ValueError(f"DiscoverySource '{source_id}' not found.")

    org_id = source.organization_id

    # Create run record
    run = DiscoveryRun(
        source_id=source.id,
        organization_id=org_id,
        status=DiscoveryRunStatus.RUNNING.value,
        trigger_type=trigger_type,
        started_at=now_utc,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    # Retrieve connector credential safely via SecretProvider
    credential_val = None
    if source.credential_reference:
        try:
            secret_provider = get_secret_provider()
            credential_val = secret_provider.get_secret(source.credential_reference)
        except Exception as exc:
            source.status = DiscoverySourceStatus.ERROR.value
            source.last_error_code = "CREDENTIAL_RETRIEVAL_FAILED"
            source.last_error_message = f"SecretProvider failed to load credential reference: {exc}"
            run.status = DiscoveryRunStatus.FAILED.value
            run.error_summary = source.last_error_message
            run.completed_at = datetime.now(timezone.utc)
            db.commit()

            db.add(
                SecurityEvent(
                    organization_id=org_id,
                    event_type="discovery_credential_failure",
                    severity="warning",
                    description=f"Discovery source '{source.name}' failed credential retrieval.",
                    details={"source_id": source.source_id, "error": str(exc)},
                )
            )
            db.commit()
            return run

    # Execute connector scan
    try:
        connector = get_connector(
            source_type=source.source_type,
            configuration=source.configuration,
            credential_value=credential_val,
        )
        resources: List[DiscoveredResource] = connector.scan()
    except Exception as exc:
        source.status = DiscoverySourceStatus.ERROR.value
        source.last_error_code = "SCAN_EXECUTION_ERROR"
        source.last_error_message = str(exc)
        source.last_scan_at = datetime.now(timezone.utc)

        run.status = DiscoveryRunStatus.FAILED.value
        run.error_summary = str(exc)
        run.completed_at = datetime.now(timezone.utc)
        db.commit()

        db.add(
            SecurityEvent(
                organization_id=org_id,
                event_type="discovery_source_failed",
                severity="warning",
                description=f"Discovery scan failed for source '{source.name}': {exc}",
                details={"source_id": source.source_id, "error": str(exc)},
            )
        )
        db.commit()
        return run

    # Process discovered resources
    candidates_found = 0
    known_matches = 0
    unmanaged_found = 0

    for res in resources:
        # 1. Deterministic classification & scoring
        confidence_score, confidence_level, reasons, findings = classify_workload_evidence(
            raw_dependencies=res.dependencies,
            env_var_names=res.env_var_names,
            labels=res.labels,
            image_name=res.image_name,
            resource_name=res.display_name,
            telemetry_signals=res.telemetry_signals,
            environment=res.environment,
        )

        # 2. Known-Agent matching
        matched_agent, match_type, match_reasons = match_candidate_with_inventory(
            db=db,
            organization_id=org_id,
            resource=res,
            findings=findings,
        )

        # 3. Assemble relationships
        relationships = build_candidate_relationships(
            resource=res,
            matched_agent=matched_agent,
            match_type=match_type,
            findings=findings,
        )

        # 4. Fingerprint for deduplication
        fingerprint = compute_discovery_fingerprint(res)

        # 5. Status determination
        if match_type == "VERIFIED_MATCH":
            candidate_status = DiscoveryCandidateStatus.MATCHED.value
            known_matches += 1
        elif confidence_score >= 40:
            candidate_status = DiscoveryCandidateStatus.UNMANAGED.value
            unmanaged_found += 1
        else:
            candidate_status = DiscoveryCandidateStatus.NEEDS_REVIEW.value

        # Check existing candidate by fingerprint in same tenant
        existing_candidate = db.scalar(
            select(DiscoveryCandidate).where(
                DiscoveryCandidate.organization_id == org_id,
                DiscoveryCandidate.fingerprint == fingerprint,
            )
        )

        if existing_candidate:
            # Update existing candidate
            existing_candidate.last_seen_at = now_utc
            existing_candidate.confidence_score = confidence_score
            existing_candidate.confidence_level = confidence_level
            existing_candidate.confidence_reasons = reasons
            existing_candidate.relationships = relationships

            # Reopen review if candidate was IGNORED but has expired or materially changed
            if existing_candidate.status == DiscoveryCandidateStatus.IGNORED.value:
                if existing_candidate.ignored_until and existing_candidate.ignored_until < now_utc:
                    existing_candidate.status = candidate_status

            if matched_agent and not existing_candidate.matched_agent_id:
                existing_candidate.matched_agent_id = matched_agent.id
                existing_candidate.match_type = match_type
                existing_candidate.match_reasons = match_reasons
                if match_type == "VERIFIED_MATCH":
                    existing_candidate.status = DiscoveryCandidateStatus.MATCHED.value

            target_cand = existing_candidate
        else:
            # Create new candidate
            new_cand = DiscoveryCandidate(
                organization_id=org_id,
                source_id=source.id,
                external_resource_reference=res.external_reference,
                candidate_type=res.candidate_type,
                display_name=res.display_name,
                environment=res.environment,
                location_reference=res.location_reference,
                confidence_score=confidence_score,
                confidence_level=confidence_level,
                confidence_reasons=reasons,
                status=candidate_status,
                matched_agent_id=matched_agent.id if matched_agent else None,
                match_type=match_type,
                match_reasons=match_reasons,
                suggested_owner_name=res.suggested_owner.get("owner_name") if res.suggested_owner else None,
                suggested_owner_type=res.suggested_owner.get("owner_type") if res.suggested_owner else None,
                suggested_owner_confidence=res.suggested_owner.get("confidence") if res.suggested_owner else None,
                suggested_owner_reasons=res.suggested_owner.get("reasons", []) if res.suggested_owner else [],
                fingerprint=fingerprint,
                first_seen_at=now_utc,
                last_seen_at=now_utc,
                evidence_summary=findings,
                relationships=relationships,
            )
            db.add(new_cand)
            db.commit()
            db.refresh(new_cand)
            target_cand = new_cand
            candidates_found += 1

            # Emit security event for new high-confidence unmanaged workload
            if candidate_status == DiscoveryCandidateStatus.UNMANAGED.value and res.environment.lower() in ("prod", "production"):
                db.add(
                    SecurityEvent(
                        organization_id=org_id,
                        event_type="unmanaged_agent_detected",
                        severity="warning",
                        description=f"Unmanaged AI agent detected in {res.environment}: '{res.display_name}'.",
                        details={
                            "candidate_id": target_cand.candidate_id,
                            "display_name": target_cand.display_name,
                            "environment": target_cand.environment,
                            "confidence_score": confidence_score,
                            "location": target_cand.location_reference,
                        },
                    )
                )

        # 6. Record safe evidence items
        for fw in findings.get("frameworks_detected", []):
            db.add(
                DiscoveryEvidence(
                    candidate_id=target_cand.id,
                    organization_id=org_id,
                    source_id=source.id,
                    evidence_type="AI_FRAMEWORK_DEPENDENCY",
                    category=EvidenceCategory.FRAMEWORK.value,
                    strength=EvidenceStrength.STRONG.value,
                    details={"framework": fw},
                )
            )

        for prov in findings.get("providers_detected", []):
            db.add(
                DiscoveryEvidence(
                    candidate_id=target_cand.id,
                    organization_id=org_id,
                    source_id=source.id,
                    evidence_type="MODEL_PROVIDER_SDK",
                    category=EvidenceCategory.PROVIDER.value,
                    strength=EvidenceStrength.STRONG.value,
                    details={"provider": prov},
                )
            )

        for var_name in findings.get("safe_env_vars_detected", []):
            db.add(
                DiscoveryEvidence(
                    candidate_id=target_cand.id,
                    organization_id=org_id,
                    source_id=source.id,
                    evidence_type="ENV_VAR_NAME",
                    category=EvidenceCategory.CONFIG.value,
                    strength=EvidenceStrength.WEAK.value,
                    details={"variable_name": var_name},
                )
            )

    # Finalize run
    completed_time = datetime.now(timezone.utc)
    run.status = DiscoveryRunStatus.COMPLETED.value
    run.completed_at = completed_time
    run.resources_examined = len(resources)
    run.candidates_found = candidates_found
    run.known_matches = known_matches
    run.unmanaged_found = unmanaged_found
    run.run_summary = {
        "duration_seconds": (completed_time - now_utc).total_seconds(),
        "resources_scanned": len(resources),
        "candidates_created": candidates_found,
        "known_matches": known_matches,
        "unmanaged_detected": unmanaged_found,
    }

    # Update source health
    source.status = DiscoverySourceStatus.ACTIVE.value
    source.last_scan_at = now_utc
    source.last_success_at = completed_time
    source.resources_examined_count += len(resources)
    source.candidates_found_count += candidates_found
    source.last_error_code = None
    source.last_error_message = None

    db.commit()
    db.refresh(run)
    db.refresh(source)
    return run


# ---------------------------------------------------------------------------
# Candidate Triage & Review Operations
# ---------------------------------------------------------------------------

def match_candidate_to_agent(
    db: Session,
    candidate_id: UUID | str,
    agent_id: UUID | str,
    user_id: Optional[UUID] = None,
) -> DiscoveryCandidate:
    """Manually link a discovery candidate to an existing registered Agent."""
    cand = _get_candidate(db, candidate_id)
    agent = _get_agent(db, agent_id, cand.organization_id)

    cand.matched_agent_id = agent.id
    cand.match_type = "MANUAL_MATCH"
    cand.match_reasons = [f"Manually confirmed match to agent '{agent.name}' by user {user_id or 'system'}."]
    cand.status = DiscoveryCandidateStatus.MATCHED.value
    cand.updated_at = datetime.now(timezone.utc)

    db.add(
        SecurityEvent(
            organization_id=cand.organization_id,
            event_type="candidate_matched",
            severity="info",
            description=f"Discovery candidate '{cand.display_name}' was matched to agent '{agent.name}'.",
            details={
                "candidate_id": cand.candidate_id,
                "agent_id": str(agent.id),
                "matched_by": str(user_id) if user_id else "system",
            },
        )
    )

    db.commit()
    db.refresh(cand)
    return cand


def onboard_candidate_to_inventory(
    db: Session,
    candidate_id: UUID | str,
    owner_id: UUID,
    owner_type: str = "USER",
    purpose: Optional[str] = None,
    risk_classification: str = "LOW",
    team: Optional[str] = None,
    business_function: Optional[str] = None,
    user_id: Optional[UUID] = None,
) -> Agent:
    """
    Safe onboarding workflow:
    Creates a new Agent in DRAFT/REGISTERED state entering the Step 28 lifecycle.
    DOES NOT automatically activate, grant credentials, or grant permissions.
    """
    cand = _get_candidate(db, candidate_id)

    # Sanitize identifier
    base_ident = f"agt_{cand.display_name.lower().replace(' ', '_').replace('-', '_')}"
    # Ensure uniqueness
    ident = base_ident
    existing = db.scalar(select(Agent).where(Agent.agent_identifier == ident))
    if existing:
        ident = f"{base_ident}_{secrets.token_hex(4)}"

    # Create new Agent record in Step 28 authoritative inventory
    agent = Agent(
        organization_id=cand.organization_id,
        name=cand.display_name,
        agent_identifier=ident,
        owner_id=owner_id,
        owner_type=owner_type,
        status=AgentStatus.REGISTERED,  # Safe registered state, NOT ACTIVE!
        purpose=purpose or f"Onboarded from discovered workload: {cand.external_resource_reference}",
        business_function=business_function or "Discovered Service",
        risk_classification=risk_classification,
        team=team,
        source="DISCOVERY",
        external_reference=cand.external_resource_reference,
        tags=["discovered", cand.environment],
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    # Update candidate state
    cand.matched_agent_id = agent.id
    cand.match_type = "ONBOARDED"
    cand.status = DiscoveryCandidateStatus.REGISTERED.value
    cand.updated_at = datetime.now(timezone.utc)

    db.add(
        SecurityEvent(
            organization_id=cand.organization_id,
            event_type="candidate_onboarding_started",
            severity="info",
            description=f"Discovered candidate '{cand.display_name}' was onboarded as agent '{agent.name}' ({agent.agent_identifier}).",
            details={
                "candidate_id": cand.candidate_id,
                "agent_id": str(agent.id),
                "agent_identifier": agent.agent_identifier,
                "onboarded_by": str(user_id) if user_id else "system",
            },
        )
    )

    db.commit()
    db.refresh(agent)
    return agent


def ignore_candidate(
    db: Session,
    candidate_id: UUID | str,
    reason: str,
    days: int = 30,
    user_id: Optional[UUID] = None,
) -> DiscoveryCandidate:
    """Suppress a candidate from review queue for a designated duration."""
    cand = _get_candidate(db, candidate_id)
    cand.status = DiscoveryCandidateStatus.IGNORED.value
    cand.ignore_reason = reason
    cand.ignored_until = datetime.now(timezone.utc) + timedelta(days=days)
    cand.updated_at = datetime.now(timezone.utc)

    db.add(
        SecurityEvent(
            organization_id=cand.organization_id,
            event_type="candidate_ignored",
            severity="info",
            description=f"Discovery candidate '{cand.display_name}' was ignored for {days} days: {reason}",
            details={
                "candidate_id": cand.candidate_id,
                "days": days,
                "reason": reason,
                "user_id": str(user_id) if user_id else "system",
            },
        )
    )
    db.commit()
    db.refresh(cand)
    return cand


def mark_candidate_false_positive(
    db: Session,
    candidate_id: UUID | str,
    reason: str,
    user_id: Optional[UUID] = None,
) -> DiscoveryCandidate:
    """Record that candidate is not an AI agent workload."""
    cand = _get_candidate(db, candidate_id)
    cand.status = DiscoveryCandidateStatus.FALSE_POSITIVE.value
    cand.false_positive_reason = reason
    cand.updated_at = datetime.now(timezone.utc)

    db.add(
        SecurityEvent(
            organization_id=cand.organization_id,
            event_type="candidate_false_positive",
            severity="info",
            description=f"Discovery candidate '{cand.display_name}' was marked false positive: {reason}",
            details={
                "candidate_id": cand.candidate_id,
                "reason": reason,
                "user_id": str(user_id) if user_id else "system",
            },
        )
    )
    db.commit()
    db.refresh(cand)
    return cand


def mark_stale_candidates(
    db: Session,
    organization_id: UUID,
    stale_days: int = 30,
) -> int:
    """Mark candidates not observed in recent scans as STALE."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
    stale_candidates = db.scalars(
        select(DiscoveryCandidate).where(
            DiscoveryCandidate.organization_id == organization_id,
            DiscoveryCandidate.status.in_([
                DiscoveryCandidateStatus.NEW.value,
                DiscoveryCandidateStatus.NEEDS_REVIEW.value,
                DiscoveryCandidateStatus.UNMANAGED.value,
            ]),
            DiscoveryCandidate.last_seen_at < cutoff,
        )
    ).all()

    for cand in stale_candidates:
        cand.status = DiscoveryCandidateStatus.STALE.value
        cand.updated_at = datetime.now(timezone.utc)

    db.commit()
    return len(stale_candidates)


# ---------------------------------------------------------------------------
# Governance Signals & Executive Dashboard
# ---------------------------------------------------------------------------

def get_discovery_governance_signals(
    db: Session,
    organization_id: UUID,
) -> List[Dict[str, Any]]:
    """Evaluate discovery-specific governance signals for an organization."""
    signals_list: List[Dict[str, Any]] = []

    # 1. Unmanaged Agents
    unmanaged = db.scalars(
        select(DiscoveryCandidate).where(
            DiscoveryCandidate.organization_id == organization_id,
            DiscoveryCandidate.status == DiscoveryCandidateStatus.UNMANAGED.value,
        )
    ).all()

    for u in unmanaged:
        sigs = ["UNMANAGED_AGENT", "SHADOW_AI_REVIEW_REQUIRED"]
        if u.environment.lower() in ("prod", "production"):
            sigs.append("DISCOVERY_PRODUCTION_WORKLOAD")
        if not u.suggested_owner_name:
            sigs.append("DISCOVERY_OWNER_UNKNOWN")

        signals_list.append({
            "candidate_id": u.candidate_id,
            "display_name": u.display_name,
            "environment": u.environment,
            "confidence_score": u.confidence_score,
            "signals": sigs,
        })

    return signals_list


def get_discovery_dashboard_metrics(
    db: Session,
    organization_id: UUID,
) -> Dict[str, Any]:
    """Calculate executive metrics and review queue counts for the Discovery portal."""
    candidates = db.scalars(
        select(DiscoveryCandidate).where(DiscoveryCandidate.organization_id == organization_id)
    ).all()

    sources = db.scalars(
        select(DiscoverySource).where(DiscoverySource.organization_id == organization_id)
    ).all()

    status_counts: Dict[str, int] = {}
    for c in candidates:
        status_counts[c.status] = status_counts.get(c.status, 0) + 1

    high_confidence_unmanaged = sum(
        1 for c in candidates
        if c.status == DiscoveryCandidateStatus.UNMANAGED.value and c.confidence_score >= 70
    )
    production_unmanaged = sum(
        1 for c in candidates
        if c.status == DiscoveryCandidateStatus.UNMANAGED.value and c.environment.lower() in ("prod", "production")
    )
    sources_with_errors = sum(1 for s in sources if s.status == DiscoverySourceStatus.ERROR.value)

    return {
        "total_candidates": len(candidates),
        "total_sources": len(sources),
        "new_candidates": status_counts.get(DiscoveryCandidateStatus.NEW.value, 0),
        "needs_review": status_counts.get(DiscoveryCandidateStatus.NEEDS_REVIEW.value, 0),
        "unmanaged_agents": status_counts.get(DiscoveryCandidateStatus.UNMANAGED.value, 0),
        "high_confidence_unmanaged": high_confidence_unmanaged,
        "production_unmanaged": production_unmanaged,
        "matched_agents": status_counts.get(DiscoveryCandidateStatus.MATCHED.value, 0),
        "registered_agents": status_counts.get(DiscoveryCandidateStatus.REGISTERED.value, 0),
        "ignored_candidates": status_counts.get(DiscoveryCandidateStatus.IGNORED.value, 0),
        "false_positives": status_counts.get(DiscoveryCandidateStatus.FALSE_POSITIVE.value, 0),
        "stale_candidates": status_counts.get(DiscoveryCandidateStatus.STALE.value, 0),
        "sources_with_errors": sources_with_errors,
    }


def export_discovery_candidates(
    db: Session,
    organization_id: UUID,
    format: str = "json",
) -> str:
    """Sanitized export of discovery candidates (CSV or JSON). Excludes secrets, prompts, and tokens."""
    candidates = db.scalars(
        select(DiscoveryCandidate).where(DiscoveryCandidate.organization_id == organization_id)
    ).all()

    records = [
        {
            "candidate_id": c.candidate_id,
            "display_name": c.display_name,
            "candidate_type": c.candidate_type,
            "environment": c.environment,
            "location_reference": c.location_reference,
            "external_resource_reference": c.external_resource_reference,
            "confidence_score": c.confidence_score,
            "confidence_level": c.confidence_level,
            "status": c.status,
            "matched_agent_id": str(c.matched_agent_id) if c.matched_agent_id else None,
            "match_type": c.match_type,
            "suggested_owner": c.suggested_owner_name,
            "first_seen_at": c.first_seen_at.isoformat() if c.first_seen_at else None,
            "last_seen_at": c.last_seen_at.isoformat() if c.last_seen_at else None,
        }
        for c in candidates
    ]

    if format.lower() == "csv":
        out = io.StringIO()
        if records:
            writer = csv.DictWriter(out, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)
        return out.getvalue()

    return json.dumps(records, indent=2)


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _get_candidate(db: Session, candidate_id: UUID | str) -> DiscoveryCandidate:
    if isinstance(candidate_id, str):
        cand = db.scalar(
            select(DiscoveryCandidate).where(
                or_(DiscoveryCandidate.candidate_id == candidate_id, DiscoveryCandidate.id == candidate_id)
            )
        )
    else:
        cand = db.scalar(select(DiscoveryCandidate).where(DiscoveryCandidate.id == candidate_id))

    if not cand:
        raise ValueError(f"DiscoveryCandidate '{candidate_id}' not found.")
    return cand


def _get_agent(db: Session, agent_id: UUID | str, org_id: UUID) -> Agent:
    if isinstance(agent_id, str):
        agent = db.scalar(
            select(Agent).where(
                Agent.organization_id == org_id,
                or_(Agent.agent_identifier == agent_id, Agent.id == agent_id),
            )
        )
    else:
        agent = db.scalar(select(Agent).where(Agent.organization_id == org_id, Agent.id == agent_id))

    if not agent:
        raise ValueError(f"Agent '{agent_id}' not found in organization.")
    return agent
