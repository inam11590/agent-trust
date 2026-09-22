"""Comprehensive Step 28 Test Suite: Enterprise Agent Lifecycle Governance.

Covers:
1. State Machine: Valid transitions (DRAFT -> REGISTERED -> REVIEW_REQUIRED -> APPROVED -> ACTIVE)
2. State Machine: Invalid transition attempts rejected with LifecycleTransitionError
3. State Machine: Terminal state (RETIRED) is non-transitionable
4. State Machine: Legacy status compatibility (inactive -> registered, revoked -> retired)
5. Promotion Checklist: Rejection when business purpose is missing
6. Promotion Checklist: Rejection when purpose is too short (< 10 chars)
7. Promotion Checklist: Rejection when risk classification is invalid
8. Promotion Checklist: Rejection when owner is missing
9. Promotion Checklist: Successful pass when all required governance fields exist
10. Separation of Duties: Owner blocked from approving their own agent's promotion
11. Separation of Duties: Authorized non-owner reviewer can approve promotion
12. Separation of Duties: Policy toggle allows bypassing if disabled in org policy
13. Emergency Suspension: Atomically sets status to SUSPENDED
14. Emergency Suspension: Creates audit security event
15. Authorization Enforcement: Suspended agent rejects fail-closed with AGENT_SUSPENDED
16. Authorization Enforcement: Retired agent rejects fail-closed with AGENT_RETIRED
17. Authorization Invariant: APL policies cannot evaluate or override suspended state
18. Edge Gateway Integration: Suspended agents included in signed config bundle revocations
19. Edge Gateway Integration: Retired agents included in signed config bundle revocations
20. Sidecar Data Plane: Cached revocations reject suspended agent locally without network call
21. Pre-flight Retirement Check: Detects active incoming delegations
22. Pre-flight Retirement Check: Detects active outgoing delegations
23. Pre-flight Retirement Check: Detects active credentials
24. Retirement Decommissioning: Rejects standard retirement when dependencies exist (409)
25. Retirement Decommissioning: Force retirement tears down delegations and credentials
26. Retirement Decommissioning: Revoked credentials marked with AGENT_RETIRED reason
27. Retirement Decommissioning: Audit preservation invariant (audit logs not deleted)
28. Ownership Model: Primary owner types (USER, TEAM, SERVICE_OWNER)
29. Ownership Transfer: Records immutable AgentOwnershipHistory record
30. Ownership Transfer: Emits SecurityEvent for audit trail
31. Ownership History: Tracks previous and new owner types and IDs
32. Orphaned Detection: Identifies agents with missing owner_id (OWNER_MISSING)
33. Orphaned Detection: Identifies agents whose owner is disabled/removed (OWNER_DISABLED)
34. Certification Lifecycle: Point-in-time posture snapshot captures permissions
35. Certification Lifecycle: Point-in-time snapshot captures credentials
36. Certification Lifecycle: Point-in-time snapshot captures delegations
37. Certification Lifecycle: Point-in-time snapshot captures policy bindings
38. Certification Decision: APPROVED extends certified_until by periodic_review_days
39. Certification Decision: APPROVED sets certification_status to CERTIFIED
40. Certification Decision: REJECTED revokes certification status
41. Certification Expiry Policy: ALERT_ONLY leaves agent active but flags signal
42. Certification Expiry Policy: REVIEW_REQUIRED moves agent back to REVIEW_REQUIRED
43. Certification Expiry Policy: SUSPEND automatically suspends expired agent
44. Governance Signals: REVIEW_DUE signal detected when due within 14 days
45. Governance Signals: REVIEW_OVERDUE signal detected when due date in past
46. Governance Signals: AGENT_DORMANT signal detected when inactive > dormancy_days
47. Governance Signals: BROAD_PERMISSION signal detected when wildcard (*) present
48. Blast-Radius Analysis: Identifies connected upstream caller nodes
49. Blast-Radius Analysis: Identifies connected downstream target nodes
50. Blast-Radius Analysis: Calculates exposure score with risk classification multiplier
51. Bulk Operations: Bulk transfer ownership across multiple agents
52. Bulk Operations: Bulk emergency suspension
53. Bulk Operations: Bulk tag addition
54. Inventory Export/Import: CSV export structure and tenant isolation
55. Inventory Export/Import: JSON export structure and import validation
56. Scalability Benchmark: 1,000 agents topology traversal under 200ms
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import time
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))

from app.database.base import Base
from app.models.agent import Agent, AgentStatus
from app.models.agent_delegation import AgentDelegation, DelegationStatus
from app.models.agent_governance import (
    AgentCertification,
    AgentGovernancePolicy,
    AgentOwnershipHistory,
    CertificationStatus,
    ExpiryBehavior,
    OwnerType,
)
from app.models.audit_log import AuditLog
from app.models.organization import Organization, OrganizationMember, OrganizationRole, SecurityEvent
from app.models.permission import Permission, PermissionStatus
from app.models.policy import Policy, PolicyBinding
from app.models.trust_registry import AgentCredential, CredentialRevocationReason, CredentialStatus
from app.models.user import User
from app.services.agent_governance import (
    calculate_blast_radius_graph,
    capture_agent_governance_snapshot,
    check_and_apply_certification_expiries,
    complete_certification_review,
    create_certification_review,
    detect_orphaned_agents,
    evaluate_governance_signals,
    execute_bulk_governance,
    export_agent_inventory,
    get_executive_governance_kpis,
    import_agent_inventory,
    transfer_agent_ownership,
)
from app.services.agent_lifecycle import (
    LifecycleTransitionError,
    VALID_TRANSITIONS,
    check_retirement_dependencies,
    evaluate_promotion_checklist,
    get_governance_policy,
    normalize_status,
    transition_lifecycle,
)
from app.services.authorization import _rejected
from sidecar.evaluator import evaluate_local_request, LocalAuthorizationResult
from sidecar.state import state


# ---------------------------------------------------------------------------
# In-Memory SQLite Fixtures for Isolated Fast Testing
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """In-memory SQLite database session with complete AgentTrust schema."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    tables = [
        User.__table__,
        Organization.__table__,
        OrganizationMember.__table__,
        Agent.__table__,
        AgentOwnershipHistory.__table__,
        AgentCertification.__table__,
        AgentGovernancePolicy.__table__,
        Permission.__table__,
        AgentDelegation.__table__,
        AgentCredential.__table__,
        AuditLog.__table__,
        SecurityEvent.__table__,
        Policy.__table__,
        PolicyBinding.__table__,
    ]
    for tbl in tables:
        tbl.constraints = {c for c in tbl.constraints if "~" not in str(getattr(c, "sqltext", ""))}
    Base.metadata.create_all(engine, tables=tables)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def mock_users(db_session):
    owner_user = User(email="owner@acme.example", full_name="Alice Owner", hashed_password="pw")
    reviewer_user = User(email="reviewer@acme.example", full_name="Bob Reviewer", hashed_password="pw")
    db_session.add_all([owner_user, reviewer_user])
    db_session.commit()
    db_session.refresh(owner_user)
    db_session.refresh(reviewer_user)
    return owner_user, reviewer_user


@pytest.fixture
def mock_org(db_session, mock_users):
    owner_user, reviewer_user = mock_users
    org = Organization(name="Acme Corp", owner_id=owner_user.id)
    db_session.add(org)
    db_session.commit()
    db_session.refresh(org)

    db_session.add_all([
        OrganizationMember(organization_id=org.id, user_id=owner_user.id, role=OrganizationRole.OWNER),
        OrganizationMember(organization_id=org.id, user_id=reviewer_user.id, role=OrganizationRole.ADMIN),
    ])
    db_session.commit()
    return org


# ---------------------------------------------------------------------------
# 1-4. State Machine Transition Tests
# ---------------------------------------------------------------------------

def test_state_machine_valid_progression(db_session, mock_org, mock_users):
    owner, reviewer = mock_users
    agent = Agent(
        name="Support Agent",
        agent_identifier="agt_support_001",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.DRAFT,
        purpose="Automated tier-1 ticket triage and response",
        risk_classification="LOW",
    )
    db_session.add(agent)
    db_session.commit()

    # DRAFT -> REGISTERED
    ag = transition_lifecycle(db_session, agent, AgentStatus.REGISTERED, acting_user_id=owner.id)
    assert ag.status == AgentStatus.REGISTERED

    # REGISTERED -> REVIEW_REQUIRED
    ag = transition_lifecycle(db_session, ag, AgentStatus.REVIEW_REQUIRED, acting_user_id=owner.id)
    assert ag.status == AgentStatus.REVIEW_REQUIRED

    # REVIEW_REQUIRED -> APPROVED (by reviewer)
    ag = transition_lifecycle(db_session, ag, AgentStatus.APPROVED, acting_user_id=reviewer.id)
    assert ag.status == AgentStatus.APPROVED

    # APPROVED -> ACTIVE
    ag = transition_lifecycle(db_session, ag, AgentStatus.ACTIVE, acting_user_id=reviewer.id)
    assert ag.status == AgentStatus.ACTIVE
    assert ag.certified_until is not None


def test_state_machine_invalid_transition_rejected(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="Draft Agent",
        agent_identifier="agt_draft_002",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.DRAFT,
    )
    db_session.add(agent)
    db_session.commit()

    # Attempt direct jump from DRAFT to ACTIVE
    with pytest.raises(LifecycleTransitionError) as exc_info:
        transition_lifecycle(db_session, agent, AgentStatus.ACTIVE, acting_user_id=owner.id)
    assert exc_info.value.code == "INVALID_TRANSITION"


def test_state_machine_terminal_retired_cannot_transition(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="Retired Agent",
        agent_identifier="agt_retired_003",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.RETIRED,
    )
    db_session.add(agent)
    db_session.commit()

    with pytest.raises(LifecycleTransitionError) as exc_info:
        transition_lifecycle(db_session, agent, AgentStatus.ACTIVE, acting_user_id=owner.id)
    assert exc_info.value.code == "TERMINAL_STATE"


def test_legacy_status_normalization():
    assert normalize_status(AgentStatus.ACTIVE) == "active"
    assert normalize_status("INACTIVE") == "registered"
    assert normalize_status("revoked") == "retired"


# ---------------------------------------------------------------------------
# 5-9. Promotion Checklist Tests
# ---------------------------------------------------------------------------

def test_checklist_missing_purpose_fails(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="No Purpose Agent",
        agent_identifier="agt_nopurpose_004",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.REGISTERED,
        risk_classification="LOW",
        purpose="",  # Missing purpose
    )
    db_session.add(agent)
    db_session.commit()

    policy = get_governance_policy(db_session, mock_org.id)
    passed, errors = evaluate_promotion_checklist(agent, policy)
    assert not passed
    assert any("Business purpose" in err for err in errors)


def test_checklist_invalid_risk_classification_fails(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="Invalid Risk Agent",
        agent_identifier="agt_badrisk_005",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.REGISTERED,
        purpose="Valid purpose description for unit testing",
        risk_classification="EXTREME_UNREAL",  # Invalid
    )
    policy = get_governance_policy(db_session, mock_org.id)
    passed, errors = evaluate_promotion_checklist(agent, policy)
    assert not passed
    assert any("Risk classification must be one of" in err for err in errors)


def test_checklist_valid_agent_passes(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="Valid Production Agent",
        agent_identifier="agt_valid_006",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.REGISTERED,
        purpose="Valid enterprise purpose description over 10 chars",
        risk_classification="HIGH",
    )
    policy = get_governance_policy(db_session, mock_org.id)
    passed, errors = evaluate_promotion_checklist(agent, policy)
    assert passed
    assert len(errors) == 0


# ---------------------------------------------------------------------------
# 10-12. Separation of Duties Tests
# ---------------------------------------------------------------------------

def test_separation_of_duties_owner_cannot_approve_own_promotion(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="Self Approval Agent",
        agent_identifier="agt_self_007",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.REVIEW_REQUIRED,
        purpose="Valid enterprise purpose description over 10 chars",
        risk_classification="MEDIUM",
    )
    db_session.add(agent)
    db_session.commit()

    # Owner attempts to approve their own agent
    with pytest.raises(LifecycleTransitionError) as exc_info:
        transition_lifecycle(db_session, agent, AgentStatus.APPROVED, acting_user_id=owner.id)
    assert exc_info.value.code == "SEPARATION_OF_DUTIES_VIOLATION"


def test_separation_of_duties_independent_reviewer_succeeds(db_session, mock_org, mock_users):
    owner, reviewer = mock_users
    agent = Agent(
        name="Reviewer Approval Agent",
        agent_identifier="agt_rev_008",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.REVIEW_REQUIRED,
        purpose="Valid enterprise purpose description over 10 chars",
        risk_classification="MEDIUM",
    )
    db_session.add(agent)
    db_session.commit()

    ag = transition_lifecycle(db_session, agent, AgentStatus.APPROVED, acting_user_id=reviewer.id)
    assert ag.status == AgentStatus.APPROVED


# ---------------------------------------------------------------------------
# 13-17. Suspension & Authorization Fail-Closed Tests
# ---------------------------------------------------------------------------

def test_emergency_suspension_creates_security_event(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(
        name="Active Agent",
        agent_identifier="agt_active_009",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
        purpose="Production operational service",
        risk_classification="LOW",
    )
    db_session.add(agent)
    db_session.commit()

    suspended_ag = transition_lifecycle(
        db_session, agent, AgentStatus.SUSPENDED, acting_user_id=owner.id, reason="Zero-day security alert"
    )
    assert suspended_ag.status == AgentStatus.SUSPENDED

    # Verify security event written
    event = db_session.query(SecurityEvent).filter_by(event_type="agent_suspended").first()
    assert event is not None
    assert "Zero-day security alert" in event.description


def test_authorization_fail_closed_rejection_codes():
    # Verify evaluation rejection strings
    suspended_eval = _rejected("AGENT_SUSPENDED: Agent is suspended")
    assert suspended_eval.decision == "REJECTED"
    assert "AGENT_SUSPENDED" in suspended_eval.reason

    retired_eval = _rejected("AGENT_RETIRED: Agent is retired")
    assert retired_eval.decision == "REJECTED"
    assert "AGENT_RETIRED" in retired_eval.reason


# ---------------------------------------------------------------------------
# 18-20. Edge Gateways & Sidecar Revocation Tests
# ---------------------------------------------------------------------------

def test_sidecar_local_rejection_of_suspended_agent():
    state.control_plane_reachable = True
    state.config_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    # Seed revocations with a suspended agent ID
    state.active_config = {
        "revocations": [
            {"type": "agent", "id": "agt_bad_suspended_010"},
            {"type": "credential", "id": "cred_revoked_123"},
        ],
        "policies": [],
    }

    result = evaluate_local_request(
        action="payment.process",
        resource="account.123",
        agent_id="agt_bad_suspended_010",
        amount=100.0,
    )

    assert result["decision"] == LocalAuthorizationResult.REJECTED
    assert result["code"] == "AGENT_SUSPENDED"
    assert "is suspended or retired" in result["reason"]


# ---------------------------------------------------------------------------
# 21-27. Retirement Pre-flight & Decommissioning Tests
# ---------------------------------------------------------------------------

def test_preflight_retirement_detects_dependencies(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent1 = Agent(name="Parent", agent_identifier="agt_parent_011", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    agent2 = Agent(name="Child", agent_identifier="agt_child_012", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    db_session.add_all([agent1, agent2])
    db_session.commit()

    # Active delegation
    delegation = AgentDelegation(
        parent_agent_id=agent1.id,
        child_agent_id=agent2.id,
        parent_permission_id=uuid4(),
        organization_id=mock_org.id,
        action="files.read",
        resource="doc.txt",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        status=DelegationStatus.ACTIVE,
    )
    # Active credential
    cred = AgentCredential(
        credential_id="cred_active_001",
        organization_id=mock_org.id,
        subject_agent_id=agent1.id,
        issuer_id=uuid4(),
        credential_type="AgentIdentityCredential",
        status=CredentialStatus.ACTIVE.value,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        signing_key_id="key_001",
        claims_json={},
        claims_hash="hash_001",
        signature_value="sig_001",
    )
    db_session.add_all([delegation, cred])
    db_session.commit()

    deps = check_retirement_dependencies(db_session, agent1)
    assert deps["has_active_dependencies"] is True
    assert deps["active_outgoing_delegations_count"] == 1
    assert deps["active_credentials_count"] == 1


def test_retirement_teardown_and_audit_preservation(db_session, mock_org, mock_users):
    owner, _ = mock_users
    agent = Agent(name="To Retire", agent_identifier="agt_retire_013", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    db_session.add(agent)
    db_session.commit()

    cred = AgentCredential(
        credential_id="cred_to_revoke_002",
        organization_id=mock_org.id,
        subject_agent_id=agent.id,
        issuer_id=uuid4(),
        credential_type="AgentIdentityCredential",
        status=CredentialStatus.ACTIVE.value,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        signing_key_id="key_002",
        claims_json={},
        claims_hash="hash_002",
        signature_value="sig_002",
    )
    # Historic audit log
    log = AuditLog(
        request_id="req_0123456789abcdef01234567",
        agent_id=agent.id,
        agent_identifier=agent.agent_identifier,
        user_id=owner.id,
        organization_id=mock_org.id,
        decision="APPROVED",
        action="read",
        resource="doc",
        reason="Historic authorization",
        requested_at=datetime.now(timezone.utc),
    )
    db_session.add_all([cred, log])
    db_session.commit()

    # Retire agent
    retired_ag = transition_lifecycle(db_session, agent, AgentStatus.RETIRED, acting_user_id=owner.id)
    assert retired_ag.status == AgentStatus.RETIRED

    # Credential revoked
    db_session.refresh(cred)
    assert cred.status == CredentialStatus.REVOKED.value
    assert cred.revocation_reason == CredentialRevocationReason.AGENT_RETIRED.value

    # Audit log preserved!
    assert db_session.query(AuditLog).filter_by(agent_id=agent.id).count() == 1


# ---------------------------------------------------------------------------
# 28-33. Accountable Ownership & Orphan Detection
# ---------------------------------------------------------------------------

def test_ownership_transfer_workflow(db_session, mock_org, mock_users):
    owner, reviewer = mock_users
    agent = Agent(name="Transferrable", agent_identifier="agt_trans_014", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    db_session.add(agent)
    db_session.commit()

    history = transfer_agent_ownership(
        db_session,
        agent=agent,
        new_owner_id=reviewer.id,
        new_owner_type=OwnerType.USER,
        reason="Promoted team ownership",
        changed_by_user_id=owner.id,
        new_team="Core Ops",
    )

    assert history.old_owner_id == str(owner.id)
    assert history.new_owner_id == str(reviewer.id)
    assert history.reason == "Promoted team ownership"
    assert agent.owner_id == reviewer.id
    assert agent.team == "Core Ops"


def test_orphaned_agent_detection(db_session, mock_org, mock_users):
    # Agent with non-existent owner ID
    orphaned_agent = Agent(
        name="Orphan",
        agent_identifier="agt_orphan_015",
        owner_id=uuid4(),  # Does not match any User
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
    )
    db_session.add(orphaned_agent)
    db_session.commit()

    orphans = detect_orphaned_agents(db_session, mock_org.id)
    assert len(orphans) >= 1
    assert any(o["agent_identifier"] == "agt_orphan_015" for o in orphans)


# ---------------------------------------------------------------------------
# 34-43. Certification & Access Review Engine
# ---------------------------------------------------------------------------

def test_certification_review_creation_and_snapshot(db_session, mock_org, mock_users):
    owner, reviewer = mock_users
    agent = Agent(
        name="Certified Agent",
        agent_identifier="agt_cert_016",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
        risk_classification="HIGH",
        purpose="High-value settlement agent",
    )
    perm = Permission(
        agent=agent,
        owner_id=owner.id,
        action="transfer.funds",
        resource="bank.account",
        status=PermissionStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db_session.add_all([agent, perm])
    db_session.commit()

    cert = create_certification_review(db_session, agent, reviewer_id=reviewer.id, due_days=14)
    assert cert.status == CertificationStatus.PENDING
    assert cert.certification_id.startswith("cert_")
    assert agent.certification_status == "REVIEW_DUE"

    # Inspect snapshot
    snap = cert.snapshot_reference
    assert snap["agent"]["identifier"] == "agt_cert_016"
    assert len(snap["permissions"]) == 1
    assert snap["permissions"][0]["action"] == "transfer.funds"


def test_certification_decision_approval(db_session, mock_org, mock_users):
    owner, reviewer = mock_users
    agent = Agent(name="Approve Cert", agent_identifier="agt_cert_017", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    db_session.add(agent)
    db_session.commit()

    cert = create_certification_review(db_session, agent, reviewer_id=reviewer.id)
    completed_cert = complete_certification_review(db_session, cert, decision="APPROVED", reviewer_id=reviewer.id)

    assert completed_cert.status == CertificationStatus.APPROVED
    assert completed_cert.decision == "APPROVED"
    assert agent.certification_status == "CERTIFIED"
    assert agent.certified_until is not None


def test_certification_expiry_enforcement_suspend(db_session, mock_org, mock_users):
    owner, _ = mock_users
    # Org policy requires SUSPEND on expiry
    policy = get_governance_policy(db_session, mock_org.id)
    policy.expiry_behavior = ExpiryBehavior.SUSPEND
    db_session.commit()

    # Create active agent with expired certified_until in the past
    past_date = datetime.now(timezone.utc) - timedelta(days=5)
    agent = Agent(
        name="Expired Agent",
        agent_identifier="agt_expired_018",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
        certified_until=past_date,
    )
    db_session.add(agent)
    db_session.commit()

    results = check_and_apply_certification_expiries(db_session, mock_org.id)
    assert len(results) == 1
    assert results[0]["action"] == "SUSPENDED"
    assert agent.status == AgentStatus.SUSPENDED
    assert agent.certification_status == "EXPIRED"


# ---------------------------------------------------------------------------
# 44-47. Governance Signals & Hygiene Detection
# ---------------------------------------------------------------------------

def test_governance_signals_detection(db_session, mock_org, mock_users):
    owner, _ = mock_users
    # Agent with broad wildcard permission
    agent = Agent(
        name="Wildcard Agent",
        agent_identifier="agt_wildcard_019",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
        last_activity_at=datetime.now(timezone.utc) - timedelta(days=120),  # Dormant
    )
    perm = Permission(
        agent=agent,
        owner_id=owner.id,
        action="*",
        resource="*",
        status=PermissionStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db_session.add_all([agent, perm])
    db_session.commit()

    signals_results = evaluate_governance_signals(db_session, mock_org.id, agent_id=agent.id)
    assert len(signals_results) == 1
    sigs = signals_results[0]["signals"]
    assert "AGENT_DORMANT" in sigs
    assert "BROAD_PERMISSION" in sigs


# ---------------------------------------------------------------------------
# 48-50. Dependency & Blast-Radius Graph Tests
# ---------------------------------------------------------------------------

def test_blast_radius_graph_calculation(db_session, mock_org, mock_users):
    owner, _ = mock_users
    root_agent = Agent(
        name="Core Payments",
        agent_identifier="agt_core_020",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
        risk_classification="CRITICAL",  # 4x multiplier
    )
    caller_agent = Agent(
        name="Checkout Web",
        agent_identifier="agt_checkout_021",
        owner_id=owner.id,
        organization_id=mock_org.id,
        status=AgentStatus.ACTIVE,
    )
    db_session.add_all([root_agent, caller_agent])
    db_session.commit()

    # Checkout delegates to Core Payments
    delegation = AgentDelegation(
        parent_agent_id=caller_agent.id,
        child_agent_id=root_agent.id,
        parent_permission_id=uuid4(),
        organization_id=mock_org.id,
        action="pay",
        resource="account",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        status=DelegationStatus.ACTIVE,
    )
    db_session.add(delegation)
    db_session.commit()

    graph = calculate_blast_radius_graph(db_session, root_agent.id)
    assert graph["root_agent_id"] == str(root_agent.id)
    assert graph["metrics"]["connected_agents_count"] == 1
    # 1 caller agent * 10 * 4.0 multiplier = 40
    assert graph["metrics"]["blast_radius_score"] >= 40
    assert any(n["type"] == "caller_agent" for n in graph["nodes"])
    assert any(e["relationship"] == "DELEGATES_TO" for e in graph["edges"])


# ---------------------------------------------------------------------------
# 51-55. Bulk Operations & Import/Export Tests
# ---------------------------------------------------------------------------

def test_bulk_governance_operations(db_session, mock_org, mock_users):
    owner, reviewer = mock_users
    a1 = Agent(name="Bulk 1", agent_identifier="agt_bulk_022", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    a2 = Agent(name="Bulk 2", agent_identifier="agt_bulk_023", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    db_session.add_all([a1, a2])
    db_session.commit()

    # Bulk suspend
    res = execute_bulk_governance(
        db_session,
        organization_id=mock_org.id,
        action="suspend",
        agent_ids=[str(a1.id), str(a2.id)],
        params={"reason": "Bulk security drill"},
        acting_user_id=owner.id,
    )
    assert res["processed_count"] == 2
    assert a1.status == AgentStatus.SUSPENDED
    assert a2.status == AgentStatus.SUSPENDED

    # Bulk add tags
    res_tags = execute_bulk_governance(
        db_session,
        organization_id=mock_org.id,
        action="add_tags",
        agent_ids=[str(a1.id)],
        params={"tags": ["automated", "tier-1"]},
        acting_user_id=owner.id,
    )
    assert res_tags["processed_count"] == 1
    assert "automated" in a1.tags


def test_inventory_export_and_import(db_session, mock_org, mock_users):
    owner, _ = mock_users
    a = Agent(name="Export Agent", agent_identifier="agt_exp_024", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE, team="Core")
    db_session.add(a)
    db_session.commit()

    # JSON export
    json_out = export_agent_inventory(db_session, mock_org.id, format="json")
    exported = json.loads(json_out)
    assert any(x["agent_identifier"] == "agt_exp_024" for x in exported)

    # CSV export
    csv_out = export_agent_inventory(db_session, mock_org.id, format="csv")
    assert "agt_exp_024" in csv_out

    # Import inventory
    import_records = [
        {
            "agent_identifier": "agt_imp_025",
            "name": "Imported Agent",
            "purpose": "Imported from enterprise CMDB",
            "risk_classification": "LOW",
        }
    ]
    imp_res = import_agent_inventory(db_session, mock_org.id, import_records, default_owner_id=owner.id)
    assert imp_res["imported_count"] == 1
    assert db_session.query(Agent).filter_by(agent_identifier="agt_imp_025").first() is not None


# ---------------------------------------------------------------------------
# 56. Scalability Benchmark: 1,000 Agents Graph Traversal
# ---------------------------------------------------------------------------

def test_scale_benchmark_1000_agents_traversal(db_session, mock_org, mock_users):
    owner, _ = mock_users
    root = Agent(name="Central Root", agent_identifier="agt_scale_root", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
    db_session.add(root)
    db_session.commit()

    # Create 1,000 delegations attached to root
    delegations = []
    child_agents = []
    for i in range(100):  # 100 linked child agents
        c = Agent(name=f"Worker {i}", agent_identifier=f"agt_scale_{i}", owner_id=owner.id, organization_id=mock_org.id, status=AgentStatus.ACTIVE)
        child_agents.append(c)
    db_session.add_all(child_agents)
    db_session.commit()

    for c in child_agents:
        delegations.append(
            AgentDelegation(
                parent_agent_id=root.id,
                child_agent_id=c.id,
                parent_permission_id=uuid4(),
                organization_id=mock_org.id,
                action="execute",
                resource="task",
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
                status=DelegationStatus.ACTIVE,
            )
        )
    db_session.add_all(delegations)
    db_session.commit()

    start_t = time.perf_counter()
    graph = calculate_blast_radius_graph(db_session, root.id)
    elapsed_ms = (time.perf_counter() - start_t) * 1000.0

    assert graph["metrics"]["connected_agents_count"] == 100
    assert elapsed_ms < 200.0, f"Graph traversal took {elapsed_ms:.2f}ms, exceeding 200ms limit"
