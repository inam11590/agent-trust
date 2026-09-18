# AgentTrust Web

This is the Next.js App Router dashboard for AgentTrust. It uses TypeScript,
Tailwind CSS, reusable components, and server-side route handlers that connect
to FastAPI.

## Local setup

```powershell
Copy-Item .env.example .env.local
npm install
npm run dev
```

Open http://127.0.0.1:3000. FastAPI must be running at the URL configured in
`AGENTTRUST_API_URL`.

## Checks

```powershell
npm run lint
npm run typecheck
npm test
npm run build
```

The JWT stays in an HTTP-only, same-site cookie. Client components call the
same-origin `/api/backend` proxy and cannot read the bearer token. Use HTTPS in
production so the cookie receives the secure flag. FastAPI remains responsible
for authentication and owner-level authorization.
