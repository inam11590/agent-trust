# Incident management (engineering draft)

Use the existing [incident response runbook](../INCIDENT_RESPONSE.md) for immediate handling. Triage suspected account takeover, MFA recovery misuse, SSO misconfiguration, leaked keys, and unexpected authorization decisions as security incidents. Preserve audit and security event records; do not paste secrets into tickets or chat.

First response: identify affected users/organizations, revoke sessions and API keys where appropriate, suspend affected agents, rotate exposed secrets, and restrict provider connections if necessary. Record UTC timestamps and the person approving each action. Validate the fix with a contained test and monitor for recurrence.

For SSO lockout, the organization owner can sign in with password and MFA to disable the requirement. If owner access is unavailable, require an offline identity-verification and two-person recovery procedure before any privileged database change. This manual procedure is not implemented as an API.

Practice the response plan in staging and retain evidence of exercises, decisions, and follow-up work.
