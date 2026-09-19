# Enterprise Gateway & Sidecar Deployment Guide

## 1. Architectural Overview

AgentTrust Enterprise architecture separates the **Control Plane** from the **Data Plane**:

* **Control Plane (Central)**: Compiles organizational policies, tracks agent identities, manages trust relationships, audits, and signs configuration bundles with monotonic versioning.
* **Data Plane (Edge Sidecar / Gateway)**: Deployed inside customer VPCs, Kubernetes clusters, or on-premise infrastructure. It caches signed configuration bundles and enforces authorization decisions locally with microsecond latency without transmitting business payloads to the Control Plane.

```
+-----------------------------------------------------------------------------------+
|                              AgentTrust Control Plane                             |
|  - Policy Engine      - Monotonic Versioning    - Key Binding & Revocation        |
|  - Trust Registry     - Bundle Compiler         - Ed25519 Bundle Signing          |
+-----------------------------------------------------------------------------------+
                                         │
                 Signed Config Bundles   │   Heartbeat & Telemetry
                 (Strictly Monotonic)    │   (Zero Business Payloads)
                                         ▼
+───────────────────────────────────────────────────────────────────────────────────+
|                         Customer VPC / Kubernetes Cluster                         |
|                                                                                   |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  | Pod / Container                                                             |  |
|  |                                                                             |  |
|  |  +-----------------------+              +--------------------------------+  |  |
|  |  |   Autonomous Agent    |  Local Auth  |    AgentTrust Sidecar          |  |  |
|  |  |  (Python/Node/Go/etc) | -----------> |   (127.0.0.1:8080)             |  |  |
|  |  +-----------------------+              |  - Local Ed25519 Keypair       |  |  |
|  |                                         |  - Sub-millisecond Evaluator   |  |  |
|  |                                         |  - Anti-Rollback Cache Disk    |  |  |
|  |                                         |  - SSRF-Protected ATP Egress   |  |  |
|  |                                         +--------------------------------+  |  |
|  |                                                         │                   |  |
|  +─────────────────────────────────────────────────────────┼───────────────────+  |
|                                                            │ Outbound ATP/1.0     |
|                                                            ▼                      |
|                                             +──────────────────────────────+      |
|                                             | External Agent / Service     |      |
|                                             +──────────────────────────────+      |
+───────────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Enrollment & Key Provisioning Lifecycle

Every sidecar or self-hosted gateway maintains its own independent cryptographic identity:

1. **Gateway Registration**:
   An administrator registers the gateway in the Control Plane dashboard or via CLI:
   ```bash
   agenttrust gateways create \
     --name "production-eu-sidecar-mesh" \
     --type "SIDECAR" \
     --environment "PRODUCTION" \
     --offline-policy "FAIL_CLOSED"
   ```
   The Control Plane generates a high-entropy, single-use enrollment token (valid for 1 hour).

2. **Node-Local Key Generation**:
   When the sidecar starts up, it generates an Ed25519 keypair in local secure storage (`.sidecar_keys/`).
   **CRITICAL ZERO-TRUST INVARIANT**: The private key NEVER leaves the sidecar and is NEVER transmitted over the wire or stored in the Control Plane database.

3. **Enrollment Handshake**:
   The sidecar presents its public key along with the one-time token:
   ```bash
   agenttrust gateway enroll \
     --control-plane "https://api.agenttrust.internal" \
     --gateway-id "gw_prod_99ab21..." \
     --token "at_tok_..."
   ```
   The Control Plane validates the token, binds the gateway's public key to its identifier, revokes the token, and returns the initial signed configuration bundle.

---

## 3. Kubernetes Deployment

### Sidecar Pod Specification

Deploy the sidecar alongside your agent container inside the same Pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: billing-agent-pod
  namespace: agenttrust
  labels:
    app: billing-agent
spec:
  containers:
    # 1. Primary AI Agent Container
    - name: agent
      image: registry.internal/agents/billing-agent:v2.1
      env:
        - name: AGENTTRUST_GATEWAY_URL
          value: "http://127.0.0.1:8080"
      resources:
        limits:
          cpu: "1"
          memory: "1Gi"

    # 2. AgentTrust Zero-Trust Sidecar Container
    - name: agenttrust-sidecar
      image: ghcr.io/inam11590/agenttrust-sidecar:latest
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
      env:
        - name: CONTROL_PLANE_URL
          value: "https://api.agenttrust.internal"
        - name: GATEWAY_ID
          valueFrom:
            secretKeyRef:
              name: agenttrust-sidecar-credentials
              key: GATEWAY_ID
        - name: ENROLLMENT_TOKEN
          valueFrom:
            secretKeyRef:
              name: agenttrust-sidecar-credentials
              key: ENROLLMENT_TOKEN
        - name: OFFLINE_POLICY
          value: "FAIL_CLOSED"
        - name: DIRECT_PRIVATE_ENABLED
          value: "false"
      ports:
        - name: http
          containerPort: 8080
      volumeMounts:
        - name: sidecar-cache
          mountPath: /data/.sidecar_cache
        - name: sidecar-keys
          mountPath: /data/.sidecar_keys
      livenessProbe:
        httpGet:
          path: /health
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 10
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
        initialDelaySeconds: 3
        periodSeconds: 5
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
        limits:
          cpu: "500m"
          memory: "256Mi"

  volumes:
    - name: sidecar-cache
      emptyDir: {}
    - name: sidecar-keys
      emptyDir:
        medium: Memory
```

---

## 4. Helm Deployment

Install the sidecar daemon or deployment via Helm:

```bash
helm repo add agenttrust https://charts.agenttrust.internal
helm repo update

helm install my-sidecar agenttrust/agenttrust-sidecar \
  --namespace agenttrust \
  --set controlPlaneUrl="https://api.agenttrust.internal" \
  --set gatewayId="gw_prod_99ab21..." \
  --set enrollmentToken="at_tok_..." \
  --set offlinePolicy="FAIL_CLOSED"
```

---

## 5. Docker Compose Deployment

For testing or development environments:

```bash
docker compose -f deploy/docker-compose.enterprise.yml up -d
```

Verify sidecar operation:
```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```
