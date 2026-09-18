import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, createPublicKey, verify } from "node:crypto";
import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, canonicalCrossOrgRequestV2, AgentTrust } from "../dist/index.js";

test("canonicalCrossOrgRequestV2 formats correctly and verifies with Ed25519", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const body = Buffer.from(JSON.stringify({ action: "book_hotel", resource: "room" }), "utf8");
  const sourceOrgId = "11111111-1111-1111-1111-111111111111";
  const targetOrgId = "22222222-2222-2222-2222-222222222222";
  const sourceAgentId = "33333333-3333-3333-3333-333333333333";
  const targetAgentId = "44444444-4444-4444-4444-444444444444";
  const keyId = "key_ag_node_test";
  const timestamp = "2026-09-18T12:00:00Z";
  const nonce = "nonce_1234567890abcdef";

  const canonical = canonicalCrossOrgRequestV2(
    "POST",
    "/api/v1/cross-org/authorize",
    sourceOrgId,
    targetOrgId,
    sourceAgentId,
    targetAgentId,
    keyId,
    timestamp,
    nonce,
    body
  );

  const lines = canonical.toString("ascii").split("\n");
  assert.equal(lines[0], "v2");
  assert.equal(lines[1], "POST");
  assert.equal(lines[2], "/api/v1/cross-org/authorize");
  assert.equal(lines[3], sourceOrgId);
  assert.equal(lines[4], targetOrgId);
  assert.equal(lines[5], sourceAgentId);
  assert.equal(lines[6], targetAgentId);
  assert.equal(lines[7], keyId);
  assert.equal(lines[8], timestamp);
  assert.equal(lines[9], nonce);

  const dir = mkdtempSync(join(tmpdir(), "agenttrust-node-crossorg-"));
  try {
    const keyPath = join(dir, "ed25519.pem");
    writeFileSync(keyPath, privateKey.export({ format: "pem", type: "pkcs8" }));

    const signer = new AgentSigner(sourceAgentId, keyId, keyPath);
    const headers = signer.crossOrgHeaders(
      "POST",
      "/api/v1/cross-org/authorize",
      body,
      sourceOrgId,
      targetOrgId,
      targetAgentId,
      timestamp,
      nonce
    );

    assert.equal(headers["X-Agent-ID"], sourceAgentId);
    assert.equal(headers["X-Agent-Key-ID"], keyId);
    assert.equal(headers["X-Agent-Signature-Version"], "v2");
    assert.equal(headers["X-Source-Org-ID"], sourceOrgId);
    assert.equal(headers["X-Target-Org-ID"], targetOrgId);
    assert.equal(headers["X-Target-Agent-ID"], targetAgentId);

    const sigBuf = Buffer.from(headers["X-Agent-Signature"], "base64");
    assert.ok(verify(null, canonical, publicKey, sigBuf));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AgentTrust client authorizeCrossOrg mock response", async () => {
  const fakeFetch = async (url, init) => {
    return new Response(
      JSON.stringify({
        request_id: "xreq_node_mock_123456",
        status: "APPROVED",
        reason: "Cross-organization request authorized",
        pending_approvals: [],
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    );
  };

  const client = new AgentTrust({
    apiKey: "at_test_abcdef1234567890abcdef123456",
    fetch: fakeFetch,
  });

  const res = await client.authorizeCrossOrg({
    sourceAgentId: "src-agent-1",
    targetOrgId: "tgt-org-1",
    targetAgentId: "tgt-agent-1",
    action: "query",
    resource: "inventory",
  });

  assert.equal(res.status, "APPROVED");
  assert.equal(res.requestId, "xreq_node_mock_123456");
});
