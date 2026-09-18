"""Step 13 rule scoring, policy, isolation, and integration tests."""

import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import create_database_engine, get_db
from app.main import create_app
from app.models import (
    Agent, AgentStatus, AuditDecision, AuditLog, Notification, NotificationType,
    OrganizationMember, OrganizationRole, MemberStatus, Permission,
    RiskAction, RiskAssessment, RiskLevel, RiskPolicy,
)

pytestmark = pytest.mark.skipif(os.getenv("RUN_DATABASE_TESTS") != "1", reason="Database tests disabled")


@pytest.fixture(scope="module")
def engine():
    value = create_database_engine(Settings())
    yield value
    value.dispose()


@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
                yield session
        finally:
            transaction.rollback()


@pytest.fixture
def client(db):
    app = create_app()
    app.state.settings = Settings(
        _env_file=None, app_env="test", jwt_secret_key=secrets.token_urlsafe(48),
        postgres_user="", postgres_password="",
    )
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as value:
        yield value


def account(client, name="Inam"):
    body = {"email": f"risk-{uuid4()}@example.com", "password": secrets.token_urlsafe(24), "full_name": name}
    user = client.post("/auth/register", json=body).json()
    login = client.post("/auth/login", json={"email": body["email"], "password": body["password"]}).json()
    return user, {"Authorization": f"Bearer {login['access_token']}"}


def setup(client, db, headers, maximum="1000", org_id=None):
    scoped = {**headers, **({"X-Organization-ID": org_id} if org_id else {})}
    agent = client.post("/agents", headers=scoped, json={"name": "Travel Assistant"}).json()
    stored = db.get(Agent, UUID(agent["id"]))
    stored.status = AgentStatus.ACTIVE
    db.commit()
    now = datetime.now(timezone.utc)
    permission = client.post("/permissions", headers=scoped, json={
        "agent_id": agent["id"], "action": "purchase", "resource": "flight",
        "maximum_amount": maximum, "currency": "USD",
        "valid_from": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=2)).isoformat(),
    }).json()
    return scoped, agent, permission


def authorize(client, headers, agent, amount, **extra):
    body = {"agent_id": agent["agent_identifier"], "action": "purchase", "resource": "flight",
            "amount": str(amount), "currency": "USD"}
    body.update(extra)
    return client.post("/authorize", headers=headers, json=body)


def seed_assessments(db, user_id, agent_id, permission_id, count):
    for index in range(count):
        db.add(RiskAssessment(
            request_id=f"req_{index + 1000:024x}", user_id=UUID(user_id), agent_id=UUID(agent_id),
            permission_id=UUID(permission_id), risk_score=1, risk_level=RiskLevel.LOW,
            decision_recommendation=RiskAction.ALLOW, reasons=["seed"], features={}, model_version="rules-v1",
        ))
    db.commit()


def seed_audits(db, user_id, agent, permission_id, amounts=(), rejected=0):
    now = datetime.now(timezone.utc)
    rows = [(amount, AuditDecision.APPROVED) for amount in amounts]
    rows += [(Decimal("1100"), AuditDecision.REJECTED) for _ in range(rejected)]
    for index, (amount, decision) in enumerate(rows):
        db.add(AuditLog(
            request_id=f"req_{index + 5000:024x}", user_id=UUID(user_id), agent_id=UUID(agent["id"]),
            agent_identifier=agent["agent_identifier"], permission_id=UUID(permission_id),
            action="purchase", resource="flight", amount=amount, currency="USD",
            decision=decision, reason="seed", requested_at=now - timedelta(minutes=1),
        ))
    db.commit()


def test_01_low_risk_request_is_allowed_and_saved(client, db):
    user, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    body = authorize(client, scoped, agent, 100).json()
    assert body["decision"] == "APPROVED" and body["risk"]["level"] == "LOW"
    assert db.scalar(select(RiskAssessment).where(RiskAssessment.request_id == body["request_id"])) is not None


def test_02_medium_risk_uses_default_allow_policy(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    body = authorize(client, scoped, agent, 950).json()
    assert body["risk"]["level"] == "MEDIUM" and body["decision"] == "APPROVED"


def test_03_amount_anomaly_increases_risk(client, db):
    user, headers = account(client); scoped, agent, permission = setup(client, db, headers, "5000")
    seed_audits(db, user["id"], agent, permission["id"], amounts=[Decimal("200"), Decimal("250"), Decimal("300")])
    body = authorize(client, scoped, agent, 1200).json()
    assert body["risk"]["score"] >= 45
    assert "Amount is much higher than recent activity" in body["risk"]["reasons"]


def test_04_high_velocity_forces_pending_and_notifies(client, db):
    user, headers = account(client); scoped, agent, permission = setup(client, db, headers, "5000")
    seed_assessments(db, user["id"], agent["id"], permission["id"], 10)
    seed_audits(db, user["id"], agent, permission["id"], rejected=3)
    body = authorize(client, scoped, agent, 200).json()
    assert body["risk"]["level"] == "HIGH" and body["decision"] == "PENDING"
    notice = db.scalar(select(Notification).where(Notification.related_agent_id == UUID(agent["id"])))
    assert notice.type == NotificationType.HIGH_RISK_APPROVAL_REQUIRED


def test_05_critical_risk_is_rejected_and_audited(client, db):
    user, headers = account(client); scoped, agent, permission = setup(client, db, headers, "10000")
    seed_assessments(db, user["id"], agent["id"], permission["id"], 30)
    seed_audits(db, user["id"], agent, permission["id"], amounts=[Decimal("200"), Decimal("220"), Decimal("250")])
    body = authorize(client, scoped, agent, 4000).json()
    assert body["decision"] == "REJECTED" and body["risk"]["level"] == "CRITICAL"
    audit = db.scalar(select(AuditLog).where(AuditLog.request_id == body["request_id"]))
    assert audit.risk_level == "CRITICAL" and audit.risk_recommendation == "REJECT"


def test_06_repeated_rejections_raise_score(client, db):
    user, headers = account(client); scoped, agent, permission = setup(client, db, headers, "2000")
    seed_audits(db, user["id"], agent, permission["id"], rejected=5)
    body = authorize(client, scoped, agent, 200).json()
    assert body["risk"]["score"] >= 25
    assert "Multiple recent rejected requests" in body["risk"]["reasons"]


def test_07_new_agent_and_permission_signals_are_explainable(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    reasons = authorize(client, scoped, agent, 100).json()["risk"]["reasons"]
    assert "Agent was created recently" in reasons and "Permission was created or changed recently" in reasons


def test_08_permission_rejection_never_creates_or_uses_risk_override(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers, "500")
    body = authorize(client, scoped, agent, 700).json()
    assert body["decision"] == "REJECTED" and body["reason"] == "Amount exceeds allowed limit"
    assert body["risk"] is None
    assert db.scalar(select(RiskAssessment).where(RiskAssessment.request_id == body["request_id"])) is None


def test_09_owner_can_view_assessment_detail(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    request_id = authorize(client, scoped, agent, 100).json()["request_id"]
    item = client.get("/risk/assessments", headers=scoped).json()["items"][0]
    detail = client.get(f"/risk/assessments/{item['id']}", headers=scoped)
    assert detail.status_code == 200 and detail.json()["request_id"] == request_id


def test_10_other_user_cannot_view_assessment(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    authorize(client, scoped, agent, 100)
    assessment_id = client.get("/risk/assessments", headers=scoped).json()["items"][0]["id"]
    _, other = account(client, "Other")
    assert client.get(f"/risk/assessments/{assessment_id}", headers=other).status_code == 404


def test_11_owner_can_edit_policy_and_viewer_cannot(client, db):
    owner, owner_headers = account(client); org = client.post("/organizations", headers=owner_headers, json={"name": "Risk Org"}).json()
    scoped_owner = {**owner_headers, "X-Organization-ID": org["id"]}
    assert client.patch("/risk/policy", headers=scoped_owner, json={"high_action": "REJECT"}).json()["high_action"] == "REJECT"
    admin, admin_headers = account(client, "Admin")
    db.add(OrganizationMember(organization_id=UUID(org["id"]), user_id=UUID(admin["id"]), role=OrganizationRole.ADMIN, status=MemberStatus.ACTIVE, invited_by=UUID(owner["id"])))
    db.commit()
    assert client.patch("/risk/policy", headers={**admin_headers, "X-Organization-ID": org["id"]}, json={"high_action": "REQUIRE_APPROVAL"}).status_code == 200
    viewer, viewer_headers = account(client, "Viewer")
    db.add(OrganizationMember(organization_id=UUID(org["id"]), user_id=UUID(viewer["id"]), role=OrganizationRole.VIEWER, status=MemberStatus.ACTIVE, invited_by=UUID(owner["id"])))
    db.commit()
    assert client.patch("/risk/policy", headers={**viewer_headers, "X-Organization-ID": org["id"]}, json={"enabled": False}).status_code == 403


def test_12_client_cannot_submit_risk_score(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    response = authorize(client, scoped, agent, 100, risk_score=0)
    assert response.status_code == 422


def test_13_overview_counts_levels_and_keeps_tenant_scope(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    authorize(client, scoped, agent, 100); authorize(client, scoped, agent, 150)
    values = client.get("/risk/overview", headers=scoped).json()
    assert values["low"] == 1 and values["medium"] == 1


def test_14_level_filter_and_pagination_are_bounded(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    authorize(client, scoped, agent, 100); authorize(client, scoped, agent, 950)
    page = client.get("/risk/assessments?level=LOW&page=1&page_size=1", headers=scoped).json()
    assert page["page_size"] == 1 and all(item["risk_level"] == "LOW" for item in page["items"])
    assert client.get("/risk/assessments?page_size=101", headers=scoped).status_code == 422


def test_15_default_policy_is_conservative_and_rule_provider_is_versioned(client, db):
    _, headers = account(client)
    policy = client.get("/risk/policy", headers=headers).json()
    assert policy["medium_action"] == "ALLOW"
    assert policy["high_action"] == "REQUIRE_APPROVAL"
    assert policy["critical_action"] == "REJECT"


def test_16_risk_records_do_not_store_credentials(client, db):
    _, headers = account(client); scoped, agent, _ = setup(client, db, headers)
    authorize(client, scoped, agent, 100)
    assessment = db.scalar(select(RiskAssessment).order_by(RiskAssessment.created_at.desc()))
    stored = str(assessment.features).lower() + str(assessment.reasons).lower()
    assert "password" not in stored and "token" not in stored and "key_hash" not in stored


def test_17_organization_assessments_are_isolated(client, db):
    _, headers = account(client)
    org_a = client.post("/organizations", headers=headers, json={"name": "Risk A"}).json()
    org_b = client.post("/organizations", headers=headers, json={"name": "Risk B"}).json()
    scoped_a, agent, _ = setup(client, db, headers, org_id=org_a["id"])
    authorize(client, scoped_a, agent, 100)
    assessment_id = client.get("/risk/assessments", headers=scoped_a).json()["items"][0]["id"]
    scoped_b = {**headers, "X-Organization-ID": org_b["id"]}
    assert client.get(f"/risk/assessments/{assessment_id}", headers=scoped_b).status_code == 404


def test_18_developer_view_hides_score_and_rule_reasons():
    from app.api.developer import _developer_response
    from app.services.authorization import AuthorizationResult

    response = _developer_response(AuthorizationResult(
        request_id="req_1234567890abcdef12345678", decision="PENDING",
        reason="Manual approval required", risk_level="HIGH", risk_score=72,
        risk_reasons=("Private scoring detail",),
    )).model_dump(exclude_none=True)
    assert response["risk"] == {"level": "HIGH"}
    assert "score" not in response["risk"] and "reasons" not in response["risk"]
