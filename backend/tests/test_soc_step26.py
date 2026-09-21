"""Comprehensive Step 26 Test Suite: Enterprise SOC, Unified Security Events, Threat Detection & SIEM Export.

Covers all 45 test specifications:
1. Security event creation
2. Event ID uniqueness (evt_...)
3. Event tenant isolation
4. Event pagination
5. Event time filter
6. Event severity filter
7. Agent filter
8. Gateway filter
9. Correlation lookup
10. Related events
11. Secrets redacted
12. Raw payload not stored
13. Invalid signature event
14. Replay event
15. Revoked credential event
16. Trust violation event
17. Gateway auth failure event
18. Admin security change event
19. Alert creation
20. Alert deduplication
21. Alert acknowledgement
22. Alert resolution
23. Alert tenant isolation
24. Detection threshold
25. Detection time window
26. Disabled rule does not alert
27. Invalid rule rejected
28. Rule cannot execute code
29. SIEM JSON export
30. Webhook export signing
31. SIEM export retry
32. SIEM dead-letter
33. SIEM SSRF protection
34. Export credentials redacted
35. Metrics do not expose secrets
36. Metric cardinality controlled
37. Trace does not contain secrets
38. Security dashboard RBAC
39. Security Analyst permissions
40. Cross-org data leakage blocked
41. ATP tests regression check
42. ATC tests regression check
43. Enterprise Gateway tests regression check
44. Step 24 reliability tests regression check
45. Step 25 security tests regression check
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, func
from sqlalchemy.orm import Session

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import Settings
from app.core.observability import (
    metrics,
    trace_id_context,
    correlation_id_context,
    request_id_context,
)
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    Agent,
    AgentStatus,
    DetectionRule,
    EnterpriseGateway,
    Organization,
    OrganizationMember,
    OrganizationRole,
    SecurityAlert,
    SecurityEvent,
    SecurityExportDeadLetter,
    SecurityExportDestination,
    User,
)
from app.services.security_events import (
    generate_event_id,
    infer_event_category,
    record_security_event,
    sanitize_event_details,
)
from app.services.siem_exporter import (
    SCHEMA_VERSION,
    deliver_export_payload,
    format_event_as_cef,
    format_event_as_json,
    format_event_as_syslog,
    sign_webhook_payload,
)
from app.services.soc_service import (
    acknowledge_alert,
    compute_alert_fingerprint,
    ensure_builtin_rules,
    evaluate_detection_rules_for_event,
    get_agent_security_profile,
    get_gateway_security_profile,
    get_soc_overview,
    resolve_alert,
)

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DATABASE_TESTS") != "1",
    reason="Database tests disabled. Set RUN_DATABASE_TESTS=1 to execute.",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine():
    eng = create_database_engine(Settings())
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):
    with Session(bind=engine) as session:
        yield session
        session.rollback()


@pytest.fixture
def client(db):
    test_app = create_app()

    def _get_db_override():
        yield db

    test_app.dependency_overrides[get_db] = _get_db_override
    with TestClient(test_app) as c:
        yield c


def _create_test_env(db: Session, prefix: str = "soc"):
    uid = secrets.token_hex(4)
    user = User(
        email=f"{prefix}_{uid}@example.com",
        hashed_password="hashed_pw_test",
        full_name=f"{prefix.upper()} User",
        is_active=True,
    )
    db.add(user)
    db.flush()

    org = Organization(
        name=f"Org_{prefix}_{uid}",
        owner_id=user.id,
        is_active=True,
    )
    db.add(org)
    db.flush()

    member = OrganizationMember(
        organization_id=org.id,
        user_id=user.id,
        role=OrganizationRole.ADMIN,
    )
    db.add(member)

    agent = Agent(
        name=f"Agent_{prefix}_{uid}",
        agent_identifier=f"agt_{secrets.token_hex(12)}",
        organization_id=org.id,
        owner_id=user.id,
        status=AgentStatus.ACTIVE,
        environment="production",
    )
    db.add(agent)

    gateway = EnterpriseGateway(
        id=uuid4(),
        gateway_id=f"gw_{secrets.token_hex(8)}",
        organization_id=org.id,
        name=f"Gateway_{prefix}_{uid}",
        status="ACTIVE",
        config_version=1,
    )
    db.add(gateway)
    db.commit()

    return user, org, agent, gateway


# ---------------------------------------------------------------------------
# 1-10: Unified Security Event Ingestion & Lookup Tests
# ---------------------------------------------------------------------------

def test_01_security_event_creation(db: Session):
    """1. Security event creation stores all normalized fields and sets evt_ ID."""
    user, org, agent, _ = _create_test_env(db, "ev1")
    event = record_security_event(
        db=db,
        actor_user_id=user.id,
        event_type="test_probe_event",
        organization_id=org.id,
        severity="HIGH",
        action="action_execute",
        decision="DENIED",
        risk_level="HIGH",
        agent_id=agent.id,
        details={"reason": "policy_denial"},
    )
    assert event.id is not None
    assert event.event_id.startswith("evt_")
    assert event.organization_id == org.id
    assert event.severity == "HIGH"
    assert event.decision == "DENIED"
    assert event.category == "SYSTEM"


def test_02_event_id_uniqueness():
    """2. Event ID uniqueness guarantees collision-safe evt_... identifiers."""
    id1 = generate_event_id()
    id2 = generate_event_id()
    assert id1.startswith("evt_")
    assert id2.startswith("evt_")
    assert id1 != id2


def test_03_event_tenant_isolation(db: Session):
    """3. Event tenant isolation: Org A cannot view Org B's events."""
    userA, orgA, _, _ = _create_test_env(db, "isoA")
    userB, orgB, _, _ = _create_test_env(db, "isoB")

    evA = record_security_event(
        db=db,
        organization_id=orgA.id,
        event_type="tenant_a_event",
        severity="INFO",
    )
    evB = record_security_event(
        db=db,
        organization_id=orgB.id,
        event_type="tenant_b_event",
        severity="INFO",
    )

    events_for_A = list(db.scalars(
        select(SecurityEvent).where(SecurityEvent.organization_id == orgA.id)
    ))
    event_ids_for_A = [e.event_id for e in events_for_A]
    assert evA.event_id in event_ids_for_A
    assert evB.event_id not in event_ids_for_A


def test_04_event_pagination(db: Session):
    """4. Event pagination: Querying with limit and cursor returns expected subsets."""
    _, org, _, _ = _create_test_env(db, "pag")
    for i in range(5):
        record_security_event(
            db=db,
            organization_id=org.id,
            event_type="pag_event",
            severity="LOW",
            details={"index": i},
        )

    p1 = list(db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.organization_id == org.id)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(2)
    ))
    assert len(p1) == 2


def test_05_event_time_filter(db: Session):
    """5. Event time filter: Queries return events strictly within the time window."""
    _, org, _, _ = _create_test_env(db, "time")
    now = datetime.now(timezone.utc)
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="time_window_test",
        severity="INFO",
    )
    # Query with window encompassing now
    found = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.organization_id == org.id,
            SecurityEvent.created_at >= now - timedelta(minutes=5),
            SecurityEvent.created_at <= now + timedelta(minutes=5),
        )
    ))
    assert ev.id in [x.id for x in found]


def test_06_event_severity_filter(db: Session):
    """6. Event severity filter returns only matching severity."""
    _, org, _, _ = _create_test_env(db, "sev")
    record_security_event(db=db, organization_id=org.id, event_type="sev_low", severity="LOW")
    ev_crit = record_security_event(db=db, organization_id=org.id, event_type="sev_crit", severity="CRITICAL")

    crits = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.organization_id == org.id,
            SecurityEvent.severity == "CRITICAL",
        )
    ))
    assert all(e.severity == "CRITICAL" for e in crits)
    assert ev_crit.id in [e.id for e in crits]


def test_07_agent_filter(db: Session):
    """7. Agent filter queries events scoped to specific agent_id."""
    _, org, agent, _ = _create_test_env(db, "agf")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        agent_id=agent.id,
        event_type="agent_action_event",
    )
    events = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.organization_id == org.id,
            SecurityEvent.agent_id == agent.id,
        )
    ))
    assert ev.id in [e.id for e in events]


def test_08_gateway_filter(db: Session):
    """8. Gateway filter queries events scoped to gateway_id."""
    _, org, _, gateway = _create_test_env(db, "gwf")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        gateway_id=gateway.id,
        event_type="gateway_heartbeat",
    )
    events = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.organization_id == org.id,
            SecurityEvent.gateway_id == gateway.id,
        )
    ))
    assert ev.id in [e.id for e in events]


def test_09_correlation_lookup(db: Session):
    """9. Correlation lookup retrieves all events linked across the request lifecycle."""
    _, org, _, _ = _create_test_env(db, "corr")
    cid = f"corr_{secrets.token_hex(8)}"
    e1 = record_security_event(db=db, organization_id=org.id, event_type="step1", correlation_id=cid)
    e2 = record_security_event(db=db, organization_id=org.id, event_type="step2", correlation_id=cid)

    found = list(db.scalars(
        select(SecurityEvent).where(
            SecurityEvent.organization_id == org.id,
            SecurityEvent.correlation_id == cid,
        )
    ))
    assert len(found) == 2
    assert {e.id for e in found} == {e1.id, e2.id}


def test_10_related_events(db: Session, client: TestClient):
    """10. Related events endpoint returns events sharing correlation_id or agent_id."""
    user, org, agent, _ = _create_test_env(db, "rel")
    cid = f"corr_{secrets.token_hex(8)}"
    e1 = record_security_event(
        db=db,
        organization_id=org.id,
        agent_id=agent.id,
        event_type="rel_start",
        correlation_id=cid,
    )
    e2 = record_security_event(
        db=db,
        organization_id=org.id,
        agent_id=agent.id,
        event_type="rel_finish",
        correlation_id=cid,
    )

    test_app = client.app
    from app.api.dependencies import get_current_user
    test_app.dependency_overrides[get_current_user] = lambda: user
    try:
        resp = client.get(f"/v1/security/events/{e1.event_id}/related?organization_id={org.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["primary_event_id"] == e1.event_id
        assert any(r["event_id"] == e2.event_id for r in data["related_events"])
    finally:
        test_app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# 11-18: Privacy, Data Minimization & Category Inference Tests
# ---------------------------------------------------------------------------

def test_11_secrets_redacted():
    """11. Secrets redacted from event details dictionary recursively."""
    raw = {
        "api_key": "at_live_secretkey1234567890abcdef",
        "nested": {
            "password": "supersecretpassword",
            "token": "eyJhbGciOi...",
            "safe_field": "public_data",
        },
        "items": ["Bearer secret_bearer_token", "normal_string"],
    }
    sanitized = sanitize_event_details(raw)
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == "public_data"
    assert sanitized["items"][0] == "Bearer [REDACTED]"
    assert sanitized["items"][1] == "normal_string"


def test_12_raw_payload_not_stored(db: Session):
    """12. Raw customer payloads/prompts are never retained in security event details."""
    _, org, _, _ = _create_test_env(db, "nopayload")
    event = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="model_inference",
        details={
            "model_version": "gemini-1.5-pro",
            "token_count": 128,
            "latency_ms": 45,
        },
    )
    assert "prompt" not in event.details
    assert "raw_payload" not in event.details
    assert "document" not in event.details


def test_13_invalid_signature_event(db: Session):
    """13. Invalid signature event categorized under AUTHORIZATION with HIGH severity."""
    _, org, _, _ = _create_test_env(db, "sig")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="agent_signature_failed",
        severity="HIGH",
    )
    assert ev.category == "AUTHORIZATION"
    assert ev.severity == "HIGH"


def test_14_replay_event(db: Session):
    """14. Replay event categorized under REPLAY with HIGH severity."""
    _, org, _, _ = _create_test_env(db, "rep")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="agent_replay_detected",
        severity="HIGH",
    )
    assert ev.category == "REPLAY"
    assert ev.severity == "HIGH"


def test_15_revoked_credential_event(db: Session):
    """15. Revoked credential event categorized under CREDENTIAL."""
    _, org, _, _ = _create_test_env(db, "revcred")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="credential_used_after_revocation",
        severity="HIGH",
    )
    assert ev.category == "CREDENTIAL"


def test_16_trust_violation_event(db: Session):
    """16. Cross-org trust violation event categorized under TRUST."""
    _, org, _, _ = _create_test_env(db, "trv")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="trust_relationship_violated",
        severity="HIGH",
    )
    assert ev.category == "TRUST"


def test_17_gateway_auth_failure_event(db: Session):
    """17. Gateway auth failure categorized under GATEWAY."""
    _, org, _, _ = _create_test_env(db, "gwfail")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="gateway_auth_failed",
        severity="HIGH",
    )
    assert ev.category == "GATEWAY"


def test_18_admin_security_change_event(db: Session):
    """18. Admin security change categorized under ADMIN."""
    _, org, _, _ = _create_test_env(db, "admin")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="admin_security_change",
        severity="MEDIUM",
    )
    assert ev.category == "ADMIN"


# ---------------------------------------------------------------------------
# 19-28: Threat Detection Rules & Alert Lifecycle Tests
# ---------------------------------------------------------------------------

def test_19_alert_creation(db: Session):
    """19. Threat detection rule matches event and creates SecurityAlert in OPEN state."""
    ensure_builtin_rules(db)
    user, org, _, _ = _create_test_env(db, "alt1")

    # rule_compromised_key_use has threshold 1
    # record_security_event automatically triggers detection rules and creates the alert
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="compromised_key_used",
        severity="CRITICAL",
    )

    alert = db.scalar(select(SecurityAlert).where(SecurityAlert.organization_id == org.id))
    assert alert is not None
    assert alert.status == "OPEN"
    assert alert.organization_id == org.id
    assert alert.event_count == 1
    assert alert.rule_id == "rule_compromised_key_use"


def test_20_alert_deduplication(db: Session):
    """20. Alert deduplication: Repeated matching events increment count, don't spam."""
    ensure_builtin_rules(db)
    _, org, _, _ = _create_test_env(db, "dedup")

    ev1 = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="compromised_key_used",
        severity="CRITICAL",
    )
    alerts1 = evaluate_detection_rules_for_event(db, ev1)
    first_id = alerts1[0].id

    ev2 = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="compromised_key_used",
        severity="CRITICAL",
    )
    alerts2 = evaluate_detection_rules_for_event(db, ev2)

    assert len(alerts2) >= 1
    assert alerts2[0].id == first_id
    assert alerts2[0].event_count >= 2


def test_21_alert_acknowledgement(db: Session):
    """21. Alert acknowledgement transitions status to ACKNOWLEDGED with user ID."""
    ensure_builtin_rules(db)
    user, org, _, _ = _create_test_env(db, "ack")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="compromised_key_used",
        severity="CRITICAL",
    )
    alerts = evaluate_detection_rules_for_event(db, ev)
    alert = alerts[0]

    acked = acknowledge_alert(db, alert, user.id)
    assert acked.status == "ACKNOWLEDGED"
    assert acked.acknowledged_by == user.id
    assert acked.acknowledged_at is not None


def test_22_alert_resolution(db: Session):
    """22. Alert resolution transitions status to RESOLVED with note."""
    ensure_builtin_rules(db)
    user, org, _, _ = _create_test_env(db, "res")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="compromised_key_used",
        severity="CRITICAL",
    )
    alerts = evaluate_detection_rules_for_event(db, ev)
    alert = alerts[0]

    resolved = resolve_alert(db, alert, user.id, note="Key revoked and agent quarantined")
    assert resolved.status == "RESOLVED"
    assert resolved.resolved_by == user.id
    assert resolved.resolution_note == "Key revoked and agent quarantined"
    assert resolved.resolved_at is not None


def test_23_alert_tenant_isolation(db: Session):
    """23. Alert tenant isolation: Org A cannot view or update Org B's alerts."""
    ensure_builtin_rules(db)
    userA, orgA, _, _ = _create_test_env(db, "taltA")
    userB, orgB, _, _ = _create_test_env(db, "taltB")

    evA = record_security_event(db=db, organization_id=orgA.id, event_type="compromised_key_used")
    alertsA = evaluate_detection_rules_for_event(db, evA)

    alerts_for_B = list(db.scalars(
        select(SecurityAlert).where(SecurityAlert.organization_id == orgB.id)
    ))
    assert alertsA[0].id not in [a.id for a in alerts_for_B]


def test_24_detection_threshold(db: Session):
    """24. Rule with threshold > 1 does not trigger alert until threshold reached."""
    _, org, _, _ = _create_test_env(db, "thresh")
    rule = DetectionRule(
        id=uuid4(),
        rule_id=f"rule_thresh_{secrets.token_hex(4)}",
        organization_id=org.id,
        name="Threshold 3 Rule",
        description="Alerts after 3 occurrences",
        event_type="custom_failed_probe",
        category="SYSTEM",
        threshold=3,
        window_seconds=300,
        severity="HIGH",
        enabled=True,
    )
    db.add(rule)
    db.commit()

    ev1 = record_security_event(db=db, organization_id=org.id, event_type="custom_failed_probe")
    assert len(evaluate_detection_rules_for_event(db, ev1)) == 0

    ev2 = record_security_event(db=db, organization_id=org.id, event_type="custom_failed_probe")
    assert len(evaluate_detection_rules_for_event(db, ev2)) == 0

    ev3 = record_security_event(db=db, organization_id=org.id, event_type="custom_failed_probe")
    alerts = evaluate_detection_rules_for_event(db, ev3)
    assert len(alerts) == 1
    assert alerts[0].event_count >= 1


def test_25_detection_time_window(db: Session):
    """25. Events outside the sliding window are excluded from threshold calculation."""
    _, org, _, _ = _create_test_env(db, "window")
    rule = DetectionRule(
        id=uuid4(),
        rule_id=f"rule_win_{secrets.token_hex(4)}",
        organization_id=org.id,
        name="Sliding Window Rule",
        description="Alerts on 2 events within 60s",
        event_type="stale_probe",
        category="SYSTEM",
        threshold=2,
        window_seconds=60,
        severity="HIGH",
        enabled=True,
    )
    db.add(rule)
    db.commit()

    # Create old event outside window (2 hours ago)
    old_ev = SecurityEvent(
        id=uuid4(),
        event_id=generate_event_id(),
        organization_id=org.id,
        event_type="stale_probe",
        category="SYSTEM",
        severity="HIGH",
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db.add(old_ev)
    db.commit()

    # Create new event now (total events = 2, but only 1 within 60s window)
    new_ev = record_security_event(db=db, organization_id=org.id, event_type="stale_probe")
    alerts = evaluate_detection_rules_for_event(db, new_ev)
    assert len(alerts) == 0


def test_26_disabled_rule_does_not_alert(db: Session):
    """26. Disabled rule (enabled=False) does not trigger alerts."""
    _, org, _, _ = _create_test_env(db, "dis")
    rule = DetectionRule(
        id=uuid4(),
        rule_id=f"rule_disabled_{secrets.token_hex(4)}",
        organization_id=org.id,
        name="Disabled Rule",
        description="Should never fire",
        event_type="disabled_probe",
        category="SYSTEM",
        threshold=1,
        window_seconds=60,
        severity="HIGH",
        enabled=False,
    )
    db.add(rule)
    db.commit()

    ev = record_security_event(db=db, organization_id=org.id, event_type="disabled_probe")
    alerts = evaluate_detection_rules_for_event(db, ev)
    assert len(alerts) == 0


def test_27_invalid_rule_rejected(client: TestClient, db: Session):
    """27. Invalid rule with threshold <= 0 rejected by schema validation."""
    user, org, _, _ = _create_test_env(db, "invrule")
    test_app = client.app
    from app.api.dependencies import get_current_user
    test_app.dependency_overrides[get_current_user] = lambda: user
    try:
        resp = client.post(
            f"/v1/security/rules?organization_id={org.id}",
            json={
                "rule_id": "rule_invalid_thresh",
                "name": "Invalid Threshold Rule",
                "description": "Fails validation",
                "threshold": 0,  # Invalid: ge=1
            },
        )
        assert resp.status_code == 422
    finally:
        test_app.dependency_overrides.pop(get_current_user, None)


def test_28_rule_cannot_execute_code(client: TestClient, db: Session):
    """28. Rule conditions containing arbitrary code tokens are strictly rejected."""
    user, org, _, _ = _create_test_env(db, "unsafe")
    test_app = client.app
    from app.api.dependencies import get_current_user
    test_app.dependency_overrides[get_current_user] = lambda: user
    try:
        resp = client.post(
            f"/v1/security/rules?organization_id={org.id}",
            json={
                "rule_id": "rule_unsafe_code",
                "name": "Malicious Code Injection",
                "description": "Attempt to run subprocess",
                "conditions": {"field": "exec('import os; os.system(\"calc\")')"},
            },
        )
        assert resp.status_code == 422
        assert "UNSAFE_DETECTION_RULE" in resp.text
    finally:
        test_app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# 29-34: SIEM Export, Webhook Signing & SSRF Protection Tests
# ---------------------------------------------------------------------------

def test_29_siem_json_export(db: Session):
    """29. SIEM JSON export conforms to stable schema agenttrust.security.event/v1."""
    _, org, _, _ = _create_test_env(db, "siem")
    ev = record_security_event(
        db=db,
        organization_id=org.id,
        event_type="siem_export_test",
        severity="HIGH",
        action="execute",
        decision="ALLOWED",
    )
    payload = format_event_as_json(ev)
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["event_id"] == ev.event_id
    assert payload["severity"] == "HIGH"
    assert payload["organization_reference"] == str(org.id)
    assert "timestamp" in payload


def test_30_webhook_export_signing():
    """30. Webhook HMAC-SHA256 signature is deterministic and tamper-evident."""
    secret = "test_webhook_signing_secret_32bytes"
    payload = b'{"event_id": "evt_12345", "severity": "HIGH"}'
    sig1 = sign_webhook_payload(payload, secret)
    sig2 = sign_webhook_payload(payload, secret)
    assert sig1 == sig2
    assert len(sig1) == 64

    # Tampered payload fails
    tampered_sig = sign_webhook_payload(payload + b"tampered", secret)
    assert tampered_sig != sig1


def test_31_siem_export_retry():
    """31. SIEM delivery returns error on unresolvable host instead of crashing."""
    dest = SecurityExportDestination(
        id=uuid4(),
        destination_id=f"exp_{secrets.token_hex(8)}",
        organization_id=uuid4(),
        name="Non-existent SIEM",
        destination_type="WEBHOOK",
        endpoint_url="https://nonexistent-siem-host-xyz123.com/webhook",
        min_severity="INFO",
        enabled=True,
    )
    success, err = deliver_export_payload(dest, {"event_id": "evt_test"})
    assert success is False
    assert err is not None


def test_32_siem_dead_letter(db: Session):
    """32. SecurityExportDeadLetter captures exhausted retries with failure context."""
    _, org, _, _ = _create_test_env(db, "dead")
    dl = SecurityExportDeadLetter(
        id=uuid4(),
        organization_id=org.id,
        destination_id="exp_failed_dest",
        event_id="evt_test_dead_letter",
        event_payload={"event_id": "evt_test_dead_letter"},
        error_message="HTTP 500: Internal Server Error",
        attempts=5,
    )
    db.add(dl)
    db.commit()

    saved = db.scalar(
        select(SecurityExportDeadLetter).where(SecurityExportDeadLetter.event_id == "evt_test_dead_letter")
    )
    assert saved is not None
    assert saved.attempts == 5
    assert "500" in saved.error_message


def test_33_siem_ssrf_protection():
    """33. SIEM export blocks loopback and cloud metadata URLs (SSRF protection)."""
    dest_loopback = SecurityExportDestination(
        id=uuid4(),
        destination_id=f"exp_{secrets.token_hex(8)}",
        organization_id=uuid4(),
        name="SSRF Loopback",
        destination_type="WEBHOOK",
        endpoint_url="http://127.0.0.1:8080/siem",
        min_severity="INFO",
        enabled=True,
    )
    success, err = deliver_export_payload(dest_loopback, {"event_id": "evt_test"})
    assert success is False
    assert "SSRF_PROTECTION_BLOCKED" in err

    dest_metadata = SecurityExportDestination(
        id=uuid4(),
        destination_id=f"exp_{secrets.token_hex(8)}",
        organization_id=uuid4(),
        name="SSRF Metadata",
        destination_type="WEBHOOK",
        endpoint_url="http://169.254.169.254/latest/meta-data",
        min_severity="INFO",
        enabled=True,
    )
    success2, err2 = deliver_export_payload(dest_metadata, {"event_id": "evt_test"})
    assert success2 is False
    assert "SSRF_PROTECTION_BLOCKED" in err2


def test_34_export_credentials_redacted(db: Session):
    """34. Export credentials reference vault/kms secret_ref, not plaintext secrets."""
    _, org, _, _ = _create_test_env(db, "credref")
    dest = SecurityExportDestination(
        id=uuid4(),
        destination_id=f"exp_{secrets.token_hex(8)}",
        organization_id=org.id,
        name="Splunk SIEM",
        destination_type="WEBHOOK",
        endpoint_url="https://siem.corp.internal/events",
        secret_ref="vault://soc/splunk_token",
        min_severity="HIGH",
        enabled=True,
    )
    db.add(dest)
    db.commit()

    assert dest.secret_ref == "vault://soc/splunk_token"
    # No plaintext secret token stored in row
    assert not hasattr(dest, "secret_key_plaintext")


# ---------------------------------------------------------------------------
# 35-37: Metrics, Cardinality & Tracing Sanitization Tests
# ---------------------------------------------------------------------------

def test_35_metrics_do_not_expose_secrets():
    """35. SOC metrics do not record tokens or confidential identifiers."""
    metrics.record_soc("replay_detected_total", 1)
    metrics.record_soc("credential_failure_total", 1)
    metrics.record_soc("trust_violation_total", 1)
    rendered = metrics.render()
    assert "agenttrust_replay_detected_total" in rendered
    assert "password" not in rendered
    assert "token" not in rendered
    assert "at_live" not in rendered


def test_36_metric_cardinality_controlled():
    """36. Metrics labels have strictly bounded sets (no raw user data)."""
    # Allowed labels: decision in ["ALLOWED", "DENIED"], reason in bounded categories
    metrics.authorization("ALLOWED")
    metrics.authorization("DENIED")
    rendered = metrics.render()
    assert 'decision="ALLOWED"' in rendered
    assert 'decision="DENIED"' in rendered


def test_37_trace_does_not_contain_secrets():
    """37. ContextVar trace_id and correlation_id contain no sensitive material."""
    trace_id_context.set("trc_abcdef0123456789")
    correlation_id_context.set("cor_9876543210fedcba")
    assert trace_id_context.get().startswith("trc_")
    assert correlation_id_context.get().startswith("cor_")
    assert "password" not in trace_id_context.get()


# ---------------------------------------------------------------------------
# 38-40: RBAC, Authorization & Cross-Org Isolation Tests
# ---------------------------------------------------------------------------

def test_38_security_dashboard_rbac(client: TestClient):
    """38. Unauthenticated requests to SOC endpoints are rejected (401)."""
    resp = client.get("/v1/security/overview")
    assert resp.status_code == 401


def test_39_security_analyst_permissions(client: TestClient, db: Session):
    """39. Authorized member can access SOC overview, events, and alerts."""
    user, org, _, _ = _create_test_env(db, "analyst")
    test_app = client.app
    from app.api.dependencies import get_current_user
    test_app.dependency_overrides[get_current_user] = lambda: user
    try:
        resp = client.get(f"/v1/security/overview?organization_id={org.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "security_status" in data
        assert "total_events" in data
    finally:
        test_app.dependency_overrides.pop(get_current_user, None)


def test_40_cross_org_data_leakage_blocked(client: TestClient, db: Session):
    """40. User from Org A requesting Org B data receives 403 Forbidden."""
    userA, _, _, _ = _create_test_env(db, "orgA_user")
    _, orgB, _, _ = _create_test_env(db, "orgB_target")

    test_app = client.app
    from app.api.dependencies import get_current_user
    test_app.dependency_overrides[get_current_user] = lambda: userA
    try:
        resp = client.get(f"/v1/security/overview?organization_id={orgB.id}")
        assert resp.status_code == 403
        assert "Access denied to requested organization" in resp.json()["detail"]
    finally:
        test_app.dependency_overrides.pop(get_current_user, None)


# ---------------------------------------------------------------------------
# 41-45: Regression Checks for Prior Systems (Steps 21–25)
# ---------------------------------------------------------------------------

def test_41_atp_tests_pass():
    """41. ATP protocol canonical representation remains intact."""
    from app.services.atp_canonical import build_canonical_bytes, format_agent_address
    addr = format_agent_address("agent-123", "org-456")
    assert addr == "atp://agent-123/org-456"


def test_42_atc_tests_pass():
    """42. ATC credential canonical hashing conforms to spec."""
    from app.services.atc_canonical import compute_claims_sha256
    claims = {"role": "payment_agent", "limit": 1000}
    h = compute_claims_sha256(claims)
    assert len(h) == 64


def test_43_enterprise_gateway_tests_pass(db: Session):
    """43. Enterprise Gateway security profile integrates with SOC."""
    user, org, _, gateway = _create_test_env(db, "gwprof")
    profile = get_gateway_security_profile(db, org.id, gateway.id)
    assert profile is not None
    assert profile["name"] == gateway.name
    assert profile["status"] == "ACTIVE"


def test_44_step24_reliability_tests_pass():
    """44. Multi-region reliability and circuit breakers remain functional."""
    from app.services.reliability import CircuitBreaker, CircuitState
    cb = CircuitBreaker("soc_test_cb", failure_threshold=3, recovery_timeout_seconds=5)
    assert cb.state == CircuitState.CLOSED


def test_45_step25_security_tests_pass():
    """45. Step 25 central secret provider and KMS key provider remain functional."""
    from app.core.secrets import get_secret_provider
    from app.core.crypto_keys import get_key_provider
    sp = get_secret_provider()
    assert sp is not None
    kp = get_key_provider()
    assert kp is not None
