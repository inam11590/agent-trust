import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { AgentSigner } from "../dist/signing.js";

test("Node SDK signAtpEnvelope produces valid ATP/1.0 envelope and ATP-SIG/1 signature", () => {
  const vectorPath = resolve("../../tests/protocol/v1/test_vectors.json");
  const vector = JSON.parse(readFileSync(vectorPath, "utf8"));

  // Write temporary pem
  const tmpKeyPath = resolve("./tmp_test_priv.pem");
  writeFileSync(tmpKeyPath, vector.private_key_pem);

  try {
    const signer = new AgentSigner(vector.source.agent_id, "key_test", tmpKeyPath);
    const envelope = signer.signAtpEnvelope({
      sourceOrgId: vector.source.organization_id,
      targetOrgId: vector.target.organization_id,
      targetAgentId: vector.target.agent_id,
      capability: vector.capability,
      payload: vector.payload,
      messageId: vector.message_id,
      timestamp: vector.timestamp,
      nonce: vector.nonce,
    });

    assert.equal(envelope.protocol, "ATP/1.0");
    assert.equal(envelope.payload_sha256, vector.payload_sha256);
    assert.equal(envelope.signature.value, vector.signature_base64);
  } finally {
    try { unlinkSync(tmpKeyPath); } catch {}
  }
});
