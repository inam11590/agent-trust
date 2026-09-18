import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPrivateKey, createPublicKey, verify } from "node:crypto";
import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, canonicalRequest } from "../dist/signing.js";

const values = Object.fromEntries(readFileSync(new URL("../../../docs/test-vectors/agent-signing-v1.properties", import.meta.url), "utf8")
  .split(/\r?\n/).filter((line) => line && !line.startsWith("#"))
  .map((line) => { const index = line.indexOf("="); return [line.slice(0, index), line.slice(index + 1)]; }));

test("official v1 vector matches Node signer and verifies", () => {
  const body = Buffer.from(values.body_base64, "base64");
  const canonical = canonicalRequest(values.method, values.path, values.agent_id, values.key_id,
    values.timestamp, values.nonce, body);
  assert.equal(canonical.toString("base64"), values.canonical_base64);
  const privateKey = createPrivateKey({ key: Buffer.from(values.private_pkcs8_base64, "base64"), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  assert.ok(verify(null, canonical, publicKey, Buffer.from(values.signature_base64, "base64")));
  const dir = mkdtempSync(join(tmpdir(), "agenttrust-test-key-"));
  try {
    const path = join(dir, "test-only.pem");
    writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }));
    const headers = new AgentSigner(values.agent_id, values.key_id, path).headers(values.method,
      values.path, body, values.timestamp, values.nonce);
    assert.equal(headers["X-Agent-Signature"], values.signature_base64);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
