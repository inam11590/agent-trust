# AgentTrust Node.js SDK

```ts
const client = new AgentTrust({ apiKey: process.env.AGENTTRUST_API_KEY });
const result = await client.authorize({ agentId: "agt_xxxxx", action: "purchase", resource: "flight", amount: 420, currency: "USD" });
```

For a registered signing key, use the matching local Ed25519 PKCS#8 PEM private key:

```ts
const travel = client.agent({ agentId: "agt_<24 lowercase hex>", keyId: "key_ag_<24 lowercase hex>",
  privateKeyPath: "/secure/path/agent-private.pem" });
const result = await travel.authorize({ action: "purchase", resource: "flight", amount: 420, currency: "USD" });
```

This is a server-side Node SDK. Never bundle the private key into browser code. See [signing protocol](../../docs/AGENT_SIGNING.md).
