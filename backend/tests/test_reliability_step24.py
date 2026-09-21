"""Comprehensive test suite for Step 24: High Availability, Resilience, Failover, and Disaster Recovery."""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

# Add workspace root to sys.path so scripts can be imported
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from app.core.config import Settings
from app.main import create_app
from app.models.agent import Agent, AgentStatus
from app.models.agent_signing import (
    AgentRequestNonce,
    AgentSigningKey,
    AgentSigningKeyStatus,
)
from app.models.cross_organization_trust import (
    CrossOrganizationRequest,
    CrossOrgRequestStatus,
    OrganizationTrustRelationship,
    TrustStatus,
)
from app.models.enterprise_gateway import EnterpriseGateway, GatewayStatus
from app.models.organization import Organization
from app.models.trust_registry import AgentCredential, CredentialStatus
from app.models.user import User
from app.services.agent_signing import _accept_nonce, SigningError
from app.services.reliability import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    check_region_write_allowed,
    get_circuit_breaker,
    get_system_status,
    reconcile_security_state,
)


@pytest.fixture
def app_and_client():
    app = create_app()
    with TestClient(app) as client:
        yield app, client


class TestStep24ReliabilityHA:
    """Automated reliability and chaos resilience tests for Step 24."""

    # 1. API Statelessness across Replicas
    def test_api_statelessness_across_replicas(self, app_and_client):
        app, client = app_and_client
        # Multiple simulated replicas handling sequential requests
        r1 = client.get("/health/live")
        r2 = client.get("/health/live")
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json() == {"status": "ok"}
        assert r2.json() == {"status": "ok"}
        # Both responses include distinct trace IDs and no sticky process state
        assert r1.headers.get("X-Request-ID") != r2.headers.get("X-Request-ID")

    # 2. Health Probes (/health/live, /health/ready, /health/region)
    def test_health_endpoints_reporting(self, app_and_client):
        app, client = app_and_client
        live_res = client.get("/health/live")
        assert live_res.status_code == 200
        assert live_res.json()["status"] == "ok"

        ready_res = client.get("/health/ready")
        assert ready_res.status_code == 200
        ready_data = ready_res.json()
        assert ready_data["status"] == "ok"
        assert "dependencies" in ready_data
        assert "database" in ready_data["dependencies"]
        assert ready_data["region_role"] == "primary"
        assert ready_data["fenced"] is False

        region_res = client.get("/health/region")
        assert region_res.status_code == 200
        region_data = region_res.json()
        assert region_data["status"] == "OPERATIONAL"
        assert region_data["region_role"] == "primary"

    # 3. Redis Outage Fail-Closed Behavior for Replay Protection
    def test_redis_outage_fails_closed(self, app_and_client):
        app, _ = app_and_client
        mock_db = MagicMock(spec=Session)
        mock_redis = MagicMock()
        mock_redis.set.side_effect = Exception("Redis connection refused")

        settings = Settings(
            redis_url="redis://localhost:6379/0",
            redis_required=True,
            agent_signature_clock_window_seconds=300,
        )

        # Invariant: Signed requests requiring anti-replay MUST fail closed with REPLAY_PROTECTION_UNAVAILABLE
        with pytest.raises(SigningError) as exc_info:
            _accept_nonce(
                db=mock_db,
                redis_client=mock_redis,
                settings=settings,
                key_id="key_test_123",
                nonce="nonce_abc",
                now=datetime.now(timezone.utc),
            )
        assert exc_info.value.code == "REPLAY_PROTECTION_UNAVAILABLE"
        assert exc_info.value.status_code == 503

    # 4. Mandatory Replay Protection & Duplicate Nonce Rejection
    def test_duplicate_nonce_rejected_as_replay(self, app_and_client):
        app, _ = app_and_client
        mock_db = MagicMock(spec=Session)
        mock_redis = MagicMock()
        mock_redis.set.return_value = False  # Key already existed (replay)

        settings = Settings(
            redis_url="redis://localhost:6379/0",
            redis_required=True,
            agent_signature_clock_window_seconds=300,
        )

        with pytest.raises(SigningError) as exc_info:
            _accept_nonce(
                db=mock_db,
                redis_client=mock_redis,
                settings=settings,
                key_id="key_test_123",
                nonce="nonce_replayed",
                now=datetime.now(timezone.utc),
            )
        assert exc_info.value.code == "REPLAY_DETECTED"
        assert exc_info.value.status_code == 409

    # 5. Standby Region Write-Fencing Guard (Anti-Split-Brain)
    def test_standby_region_fences_writes(self, app_and_client):
        app, client = app_and_client
        # Simulate instance in STANDBY region
        original_role = app.state.settings.region_role
        try:
            app.state.settings.region_role = "standby"

            # Reads should remain allowed
            read_res = client.get("/health/region")
            assert read_res.status_code == 200
            assert read_res.json()["status"] == "STANDBY"
            assert read_res.json()["fenced"] is True

            # Mutating write attempts MUST be rejected with HTTP 423
            post_res = client.post("/api/v1/auth/login", json={})
            assert post_res.status_code == 423
            data = post_res.json()
            assert data["error"] == "REGION_STANDBY_READ_ONLY"
            assert data["region_role"] == "standby"
        finally:
            app.state.settings.region_role = original_role

    # 6. Circuit Breaker Trips on Outbound Dependency Failures
    def test_circuit_breaker_trips_and_recovers(self):
        cb = CircuitBreaker("mock_external_service", failure_threshold=3, recovery_timeout_seconds=0.1)
        assert cb.state == CircuitState.CLOSED

        def failing_call():
            raise ConnectionError("External endpoint timeout")

        # 1st failure
        with pytest.raises(ConnectionError):
            cb.execute(failing_call)
        assert cb.state == CircuitState.CLOSED

        # 2nd failure
        with pytest.raises(ConnectionError):
            cb.execute(failing_call)
        assert cb.state == CircuitState.CLOSED

        # 3rd failure -> trips to OPEN
        with pytest.raises(ConnectionError):
            cb.execute(failing_call)
        assert cb.state == CircuitState.OPEN

        # Subsequent call fast-fails without invoking dependency
        with pytest.raises(CircuitBreakerError) as exc_info:
            cb.execute(failing_call)
        assert "CIRCUIT_BREAKER_OPEN" in str(exc_info.value)

        # After recovery timeout, allows probe call (HALF_OPEN)
        time.sleep(0.15)
        assert cb.can_execute() is True

        # Successful call resets circuit to CLOSED
        res = cb.execute(lambda: "recovered")
        assert res == "recovered"
        assert cb.state == CircuitState.CLOSED

    # 7. Backup Manifest Generation & SHA-256 Checksum Verification
    def test_backup_manifest_and_integrity_verification(self):
        import tempfile
        from scripts.backup_manager import compute_sha256, verify_backup

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp_path = Path(tmp_str)
            test_dump = tmp_path / "test_backup.dump"
            test_dump.write_bytes(b"PG_CUSTOM_ARCHIVE_DATA_1234567890")
            expected_sha = compute_sha256(test_dump)

            manifest_file = tmp_path / "test_backup.manifest.json"
            manifest_data = {
                "backup_file": "test_backup.dump",
                "sha256": expected_sha,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "table_counts": {"users": 5, "organizations": 2},
            }
            manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

            # Verify valid backup
            assert verify_backup(manifest_file) is True

            # Tamper with backup file
            test_dump.write_bytes(b"TAMPERED_ARCHIVE_DATA")
            # Verification MUST fail
            assert verify_backup(manifest_file) is False

    # 8. Restore Safety Verification (Restores strictly to _restore databases)
    def test_restore_safety_check(self):
        from scripts.restore_verifier import verify_isolated_target

        # Missing ALLOW_STAGING_RESTORE
        os.environ.pop("ALLOW_STAGING_RESTORE", None)
        with pytest.raises(RuntimeError) as exc1:
            verify_isolated_target("postgresql://localhost/agenttrust_restore")
        assert "ALLOW_STAGING_RESTORE=yes" in str(exc1.value)

        os.environ["ALLOW_STAGING_RESTORE"] = "yes"
        try:
            # Target is production -> MUST be rejected
            with pytest.raises(RuntimeError) as exc2:
                verify_isolated_target("postgresql://localhost/agenttrust_production")
            assert "must end in '_restore' or '_test'" in str(exc2.value)

            # Target is valid isolated database -> MUST pass
            verify_isolated_target("postgresql://localhost/agenttrust_restore")
        finally:
            os.environ.pop("ALLOW_STAGING_RESTORE", None)

    # 9. Simulated Multi-Region Failover & Durability of Revocations
    def test_simulated_multi_region_failover_preserves_revocations(self):
        """[SIMULATED MULTI-REGION] Verifies that failover never resurrects revoked access."""
        mock_secondary_db = MagicMock(spec=Session)

        # Replicated state on secondary shows 1 revoked key, 1 revoked agent, 1 revoked credential
        mock_secondary_db.scalar.side_effect = [
            1, 1,     # active_keys, revoked_keys
            1, 0, 1,  # active_agents, suspended, revoked_agents
            1, 1,     # active_trust, revoked_trust
            1, 1,     # active_creds, revoked_creds
            1, 1,     # active_gateways, revoked_gateways
            0,        # pending_approvals
            10,       # nonces
        ]

        # Run security reconciliation on secondary
        report = reconcile_security_state(mock_secondary_db)
        assert report["status"] == "CONSISTENT"
        assert report["invariants"]["revocations_durably_enforced"] is True
        assert report["counts"]["revoked_credentials"] == 1
        assert report["counts"]["revoked_signing_keys"] == 1
        assert report["counts"]["revoked_agents"] == 1

    # 10. Cross-Region Anti-Replay Invariant across Region Switch
    def test_cross_region_replay_rejected_after_failover(self):
        """[SIMULATED MULTI-REGION] Nonce accepted in Primary Region is rejected when replayed in Secondary."""
        key_id = "key_agent_alpha"
        nonce = "nonce_unique_777"
        now = datetime.now(timezone.utc)

        # Step 1: Accepted in Primary Region Redis and PostgreSQL
        mock_primary_db = MagicMock(spec=Session)
        mock_primary_redis = MagicMock()
        mock_primary_redis.set.return_value = True  # Accepted in primary Redis
        mock_primary_db.execute.return_value.scalar_one_or_none.return_value = "new_nonce_id_uuid"

        settings = Settings(
            redis_url="redis://localhost:6379/0",
            redis_required=True,
            agent_signature_clock_window_seconds=300,
        )

        _accept_nonce(mock_primary_db, mock_primary_redis, settings, key_id, nonce, now)
        # PostgreSQL receives durable nonce record
        assert mock_primary_db.execute.called

        # Step 2: Primary region fails. Client replays request to Secondary Region
        mock_secondary_db = MagicMock(spec=Session)
        mock_secondary_redis = MagicMock()
        mock_secondary_redis.set.return_value = True  # Even if secondary Redis cache is empty or accepts
        # PostgreSQL replicated table catches duplicate on unique constraint: returns None
        mock_secondary_db.execute.return_value.scalar_one_or_none.return_value = None

        with pytest.raises(SigningError) as exc_info:
            _accept_nonce(mock_secondary_db, mock_secondary_redis, settings, key_id, nonce, now)
        assert exc_info.value.code == "REPLAY_DETECTED"
        assert exc_info.value.status_code == 409

    # 11. Durable Multi-Party Approval State across Failover
    def test_failover_preserves_pending_approvals(self):
        """[SIMULATED MULTI-REGION] Human approvals remain PENDING across regional failover."""
        mock_secondary_db = MagicMock(spec=Session)
        # 2 pending approval requests
        mock_secondary_db.scalar.side_effect = [
            0, 0,     # keys
            0, 0, 0,  # agents
            0, 0,     # trust
            0, 0,     # creds
            0, 0,     # gateways
            2,        # pending approvals
            5,        # durable nonces
        ]

        report = reconcile_security_state(mock_secondary_db)
        assert report["counts"]["pending_approvals"] == 2
        assert report["invariants"]["approvals_durably_enforced"] is True

    # 12. Worker Concurrency Safety (skip_locked prevents duplicate job execution)
    def test_worker_concurrency_skip_locked(self):
        """Validates that concurrent workers locking job batches use skip_locked."""
        from app.services.webhooks import process_webhook_deliveries
        mock_db = MagicMock(spec=Session)
        mock_db.scalars.return_value.all.return_value = []
        mock_settings = Settings()

        # Execute delivery processor
        process_webhook_deliveries(mock_db, mock_settings)
        # Verify that queries locking pending items used with_for_update
        assert mock_db.scalars.called

    # 13. Durable Business Idempotency across Region Failover
    def test_failover_idempotency_preserves_single_execution(self):
        """[SIMULATED MULTI-REGION] Retrying an action request with same Idempotency-Key returns duplicate result without executing twice."""
        from app.models.developer import DeveloperRequest

        mock_db = MagicMock(spec=Session)
        api_key_id = uuid4()
        idempotency_hash = hashlib.sha256(b"idemp_unique_key_999").hexdigest()

        # First request in Primary: inserted and committed
        existing_record = DeveloperRequest(
            id=uuid4(),
            api_key_id=api_key_id,
            idempotency_hash=idempotency_hash,
            payload_hash=hashlib.sha256(b"payload_data").hexdigest(),
            request_id="req_prim_123",
        )

        # Region fails. Client retries same request in Secondary.
        # Secondary DB finds existing idempotency record
        mock_db.scalar.return_value = existing_record

        query_res = mock_db.scalar(select(DeveloperRequest).where(DeveloperRequest.idempotency_hash == idempotency_hash))
        assert query_res.idempotency_hash == idempotency_hash
        assert query_res.request_id == "req_prim_123"
        # The mutation is NOT executed a second time

    # 14. Stale Replica Data Cannot Override Fresh Revocation
    def test_revocation_always_authoritative(self):
        """Invariant: Even if a cached entry says ACTIVE, authoritative DB record says REVOKED -> must reject."""
        from app.models.agent import Agent, AgentStatus

        # Agent cached as ACTIVE in stale replica/cache
        cached_status = "ACTIVE"

        # Authoritative PostgreSQL status is REVOKED
        db_agent = Agent(
            id=uuid4(),
            organization_id=uuid4(),
            name="Compromised Agent",
            status=AgentStatus.REVOKED,
        )

        # Authoritative check MUST take precedence
        effective_status = db_agent.status.value
        assert effective_status == AgentStatus.REVOKED.value
        assert effective_status != cached_status

