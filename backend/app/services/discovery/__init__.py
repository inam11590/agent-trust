"""Discovery services package initialization (Step 29)."""

from app.services.discovery.classifier import classify_workload_evidence
from app.services.discovery.engine import (
    create_discovery_source,
    execute_discovery_run,
    export_discovery_candidates,
    get_discovery_dashboard_metrics,
    get_discovery_governance_signals,
    ignore_candidate,
    mark_candidate_false_positive,
    mark_stale_candidates,
    match_candidate_to_agent,
    onboard_candidate_to_inventory,
)
from app.services.discovery.matcher import (
    build_candidate_relationships,
    compute_discovery_fingerprint,
    match_candidate_with_inventory,
)

__all__ = [
    "classify_workload_evidence",
    "create_discovery_source",
    "execute_discovery_run",
    "match_candidate_to_agent",
    "onboard_candidate_to_inventory",
    "ignore_candidate",
    "mark_candidate_false_positive",
    "mark_stale_candidates",
    "get_discovery_governance_signals",
    "get_discovery_dashboard_metrics",
    "export_discovery_candidates",
    "compute_discovery_fingerprint",
    "match_candidate_with_inventory",
    "build_candidate_relationships",
]
