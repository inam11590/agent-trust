import assert from "node:assert/strict";
import test from "node:test";
import { AgentTrust } from "../dist/index.js";

const key = "at_live_" + "a".repeat(64);
test("authorize sends API and idempotency keys", async () => {
  let received;
  const client = new AgentTrust({ apiKey: key, baseUrl: "http://localhost:8000", fetch: async (url, init) => { received = { url, init }; return new Response(JSON.stringify({ request_id: "req_1", status: "APPROVED", reason: "Permission valid" }), { status: 200 }); } });
  const result = await client.authorize({ agentId: "agt_1", action: "purchase", resource: "flight", amount: 420, currency: "USD", idempotencyKey: "checkout-1" });
  assert.equal(result.status, "APPROVED"); assert.equal(received.init.headers["X-API-Key"], key); assert.equal(received.init.headers["Idempotency-Key"], "checkout-1");
});
test("getAuthorizationRequest parses status", async () => {
  const client = new AgentTrust({ apiKey: key, fetch: async () => new Response(JSON.stringify({ request_id: "req_1", status: "PENDING", reason: "User approval required" }), { status: 200 }) });
  assert.equal((await client.getAuthorizationRequest("req_1")).status, "PENDING");
});
test("required input is validated", () => assert.throws(() => new AgentTrust({ apiKey: "" })));
