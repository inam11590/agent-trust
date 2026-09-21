# SIEM & Security Webhook Export Architecture

## Overview
AgentTrust provides provider-neutral export capabilities to ship normalized security events to external Security Information and Event Management (SIEM) systems, log aggregators, and webhook receivers.

---

## Integration Status & Honesty Labeling

| Integration Target | Protocol / Format | Implementation Status | Real Testing Status |
| :--- | :--- | :--- | :--- |
| **Security Webhook** | Signed JSON HTTP POST (X-AgentTrust-Signature) | **WORKING** | Tested with HMAC-SHA256 signatures |
| **NDJSON / JSON Stream** | Newline-delimited JSON HTTP POST | **WORKING** | Tested with batch and single records |
| **Syslog (RFC 5424)** | Structured Syslog format | **FOUNDATION ONLY** | Schema formatting verified; socket requires real syslog server |
| **CEF (Common Event Format)** | HP/ArcSight standard extension mapping | **FOUNDATION ONLY** | Field mapping verified; requires CEF collector |
| **Splunk HEC** | HTTP Event Collector JSON format | **FOUNDATION ONLY** | Payload conforms to Splunk event API; requires Splunk endpoint |
| **Microsoft Sentinel** | Log Analytics Ingestion API | **FOUNDATION ONLY** | Standard schema ready for Azure Data Collector API |
| **Elasticsearch / OpenSearch** | Bulk JSON index API | **FOUNDATION ONLY** | ECS-compatible document mapping ready |

---

## Core Invariants

1. **Zero Authorization Blocking**: SIEM delivery runs asynchronously on background worker queues. A slow or unreachable SIEM collector will **never** block agent authorization or degrade API response times.
2. **SSRF Protection**: All HTTP/HTTPS destinations are validated against private IP ranges (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254). Private network exports must be explicitly authorized.
3. **Secret Security**: Authentication tokens and secrets for SIEM endpoints are managed through SecretProvider and never exposed in plaintext logs or database query dumps.
4. **Retry & Dead-Letter Persistence**: If an export destination returns an HTTP error or times out, the system retries with exponential backoff (up to 5 attempts). If all retries fail, the event is recorded in the security_export_dead_letters table so that audit trails are never silently discarded.
