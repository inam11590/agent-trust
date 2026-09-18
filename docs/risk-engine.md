# AgentTrust Rule-Based Risk Engine

Step 13 adds an explainable risk check after normal permission checks pass.
Permission failures are rejected immediately and cannot be overridden by risk.
The engine does not use machine learning and does not make fraud claims.

## Decision flow

```text
authenticate -> check agent -> check permission -> score risk -> apply policy
             -> approve, wait for manual approval, or reject -> audit/notify/webhook
```

The score is between 0 and 100. `LOW` is 0–29, `MEDIUM` is 30–59,
`HIGH` is 60–79, and `CRITICAL` is 80–100. Thresholds and recent time
windows are environment settings. Default policy actions are:

| Level | Action |
| --- | --- |
| LOW | ALLOW |
| MEDIUM | ALLOW |
| HIGH | REQUIRE_APPROVAL |
| CRITICAL | REJECT |

Owners and admins can change the policy. Developers and viewers can only read
it. Personal workspaces have their own policy. Organization policies are
isolated by organization ID.

## Rules

`RuleBasedRiskProvider` adds documented points for an amount far above up to 20
recent approved amounts, an amount close to its permission limit, high request
frequency in a short window, recent rejections, a new agent, a recently changed
permission, an unusual action or resource after enough history exists, and a
recently created API key. Database queries use recent windows, counts, limits,
and indexes; they do not load full history.

Each permission-valid request saves one `risk_assessments` row. It contains the
score, level, recommendation, owner-safe reasons, bounded feature values, and
`rules-v1`. Passwords, tokens, API key values, key hashes, and personal message
content are not risk features. `RiskProvider` is the interface for a future ML
implementation; only `RuleBasedRiskProvider` exists today.

## API

Signed-in workspace users can call:

```text
GET   /risk/overview
GET   /risk/assessments?level=HIGH&page=1&page_size=20
GET   /risk/assessments/{assessment_id}
GET   /risk/policy
PATCH /risk/policy
```

The page size maximum is 100. The signed-in owner view includes the reasons.
The external developer authorization API returns only a high or critical risk
level, without point values or rule details that could help someone tune a
bypass.

High-risk requests create the existing manual approval record and a
`High-Risk Approval Required` notification that opens that exact record.
Critical requests are rejected by the default policy. Final audit rows copy the
risk score, level, and recommendation.

## Run

```powershell
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
$env:RUN_DATABASE_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
```
