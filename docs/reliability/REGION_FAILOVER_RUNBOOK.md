# Operational Runbook: Regional Failover

This runbook describes the precise, step-by-step procedure for declaring a regional disaster and safely failing over the AgentTrust Control Plane from the Primary Region to the Standby Secondary Region.

---

## 1. Outage Confirmation (Phase 1)

Do not trigger failover for transient network blips or single-instance failures. Confirm that a true regional disaster exists:

1. **Synthetic Health Verification**:
   - Check Primary Region health probe:
     ```bash
     curl -sf -m 5 https://primary.agenttrust.internal/health/ready || echo "PRIMARY DOWN"
     ```
   - If `/health/ready` returns HTTP 503 or times out for 3 consecutive minutes across multiple monitoring points.
2. **Infrastructure Provider Confirmation**:
   - Check cloud provider status dashboard (AWS, GCP, Azure) for regional network partition or data center loss.
3. **Dual Authorization**:
   - Regional failover requires approval from at least two incident commanders / platform leads (SEV1 requirement).

---

## 2. Fencing the Old Primary (Phase 2 - Anti-Split-Brain)

Before promoting the secondary region, you **MUST** ensure the old primary cannot accept further writes to prevent split-brain:

1. **DNS / Edge Routing Fencing**:
   - Shift edge traffic router / Global Server Load Balancer away from the primary region IP addresses.
2. **Application Write Fencing**:
   - If the primary API servers are reachable by management bastion, set:
     ```bash
     export REGION_ROLE=standby
     export REGION_FENCING_ENABLED=true
     ```
   - This causes all mutating endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) to reject requests immediately with:
     ```json
     {"error": "REGION_STANDBY_READ_ONLY", "message": "This region is fenced in read-only standby mode."}
     ```
3. **Database Fencing**:
   - Revoke application write roles or put primary PostgreSQL in read-only mode if reachable:
     ```sql
     ALTER SYSTEM SET default_transaction_read_only = 'on';
     SELECT pg_reload_conf();
     ```

---

## 3. Secondary Promotion & Verification (Phase 3)

1. **Verify Replication Stream & Standby Lag**:
   - Connect to secondary standby database:
     ```sql
     SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn();
     ```
   - Confirm WAL replay is caught up to the last received byte.
2. **Promote Secondary PostgreSQL to Primary**:
   - Execute promotion command:
     ```bash
     pg_ctl promote -D /var/lib/postgresql/data
     ```
   - Verify read-write status:
     ```sql
     SELECT pg_is_in_recovery(); -- Must return FALSE
     ```
3. **Promote Secondary Control Plane**:
   - Update secondary environment variables:
     ```bash
     export REGION_ROLE=primary
     export REGION_FENCING_ENABLED=false
     ```
   - Restart API replicas and background workers in the secondary region.

---

## 4. Traffic Switchover (Phase 4)

1. **Update DNS / Traffic Manager**:
   - Point `api.agenttrust.internal` and `gateway.agenttrust.internal` to Secondary Region Load Balancer IP.
   - Low TTL (30s) ensures traffic propagates within 60 seconds.
2. **Verify Secondary Health Probes**:
   ```bash
   curl -sf https://secondary.agenttrust.internal/health/ready
   curl -sf https://secondary.agenttrust.internal/health/region
   ```
   Expected response from `/health/region`:
   ```json
   {"region_id": "us-west-2", "region_role": "primary", "status": "OPERATIONAL"}
   ```

---

## 5. Security & Post-Failover Verification (Phase 5)

Verify that the promoted region maintains all security guarantees:

1. **Replay Protection Check**:
   - Redis replay store in the secondary region is active and healthy.
   - Test signed request replay: an attempt to reuse a previous nonce within the signature window must return `409 Conflict (REPLAY_DETECTED)` or fail closed `503`.
2. **Revocation Durability Check**:
   - Confirm revoked credentials, agents, and cross-organization trust records remain marked `REVOKED`.
3. **Pending Approvals**:
   - Confirm pending human authorization requests remain `PENDING_APPROVAL` and were not auto-approved during failover.
4. **Enterprise Gateways**:
   - Gateways with configured `secondary_control_plane_url` connect to the promoted control plane, verify its TLS certificate and cryptographic identity, and synchronize configuration bundles.

---

## 6. Rollback / Abort Procedure

If promotion fails or data inconsistency is detected before traffic switchover:
1. Keep the edge router pointed to the primary region or safe maintenance page.
2. Do not promote secondary database.
3. Investigate logs in secondary region before making any changes.
