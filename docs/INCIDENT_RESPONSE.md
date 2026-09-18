# Incident response

For every incident: record the time and request IDs, preserve logs, contain the
problem, recover service, inspect audit history, and write a short review without
copying secrets into tickets.

| Incident | Detect | Contain and recover | Verify |
|---|---|---|---|
| API key leaked | unusual requests or owner report | revoke it, create a new key, update the server | inspect audit logs and watch the replacement key |
| Database unavailable | readiness and database alerts | stop risky changes, restore connectivity or fail over | migrations, readiness, key tables, authorization test |
| Webhook secret leaked | signature anomalies | rotate secret at both ends and reject the old secret | signed test delivery and audit events |
| Billing webhook failing | failure metric/provider retries | keep current saved state, fix endpoint or secret in Sandbox | replay one event and confirm one stored event |
| Large error spike | HTTP 5xx metric/Sentry | roll back the application if safe, disable failing integration | error rate and readiness return to normal |
| Suspicious authorization | risk and audit alerts | suspend/revoke agent, permissions, and API keys | review affected request IDs and notify the owner |

Database password rotation: create a second managed-database credential, update
the secret store, roll API and workers, verify readiness, then revoke the old
credential. Never place either password in source or logs.
