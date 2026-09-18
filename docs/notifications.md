# AgentTrust Notifications

Step 12 uses a PostgreSQL delivery queue. The authorization transaction writes
the pending request, its notification, and channel delivery jobs together. It
does not call Firebase or an email service. Run a separate worker to process
push, email, retries, and permission-expiry checks:

```powershell
cd backend
.\.venv\Scripts\python.exe -m app.workers.notifications
```

Use `--once` for one batch. Failed external deliveries retry three times by
default with exponential backoff. Workers use row locks with `SKIP LOCKED`, so
multiple workers do not claim the same batch.

## API

All routes require the signed-in user's bearer token. Notifications are always
filtered by `user_id`; an organization role never grants access to another
person's notifications.

```text
GET    /notifications?page=1&page_size=20&unread=true
GET    /notifications/unread-count
GET    /notifications/stream
POST   /notifications/{id}/read
POST   /notifications/read-all
POST   /notifications/{id}/archive
GET    /notification-preferences
PATCH  /notification-preferences
POST   /devices
DELETE /devices/{id}
```

The stream uses Server-Sent Events and sends only the current user's unread
count and latest notification ID. The dashboard then reloads private data over
the normal API.

## Push

The backend implements Firebase Cloud Messaging HTTP v1. Set `FCM_PROJECT_ID`
and a short-lived `FCM_ACCESS_TOKEN` only in the worker environment. Push data
contains notification type and internal record IDs. It never contains a JWT,
API key, password, webhook secret, or direct approval instruction.

The mobile app always loads the request from FastAPI after a notification tap.
FastAPI rechecks the signed-in user, request state, agent, permission, amount,
currency, and expiry before approval.

Android declares notification permission. iOS declares remote-notification
background mode. Firebase project files, APNs capability, and the official
Flutter Firebase adapter still require the project's Firebase credentials.

## Email

`EMAIL_PROVIDER=development` is available outside production. It marks a safe
preview delivery as sent without making a network call or printing content or
credentials. Production defaults should use `disabled` until a real provider
adapter and credential are configured. Approval emails contain a read-only
summary and tell the user to sign in; they never contain a direct approval link.

## Deduplication and preferences

Authorization and permission-expiry notifications use unique deduplication
keys. A permission stores warning and expired-notification timestamps, which
prevents repeat warnings. Users can configure in-app, push, approval, email,
security, permission-expiry, and general activity preferences.

Push tokens are needed in recoverable form for Firebase delivery. They are
never returned by the API, printed, or placed in audit events. One token can
belong to only one user, and only that user can revoke its device record.
