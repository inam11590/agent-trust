import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalAtcCredential, verifyAtcCredentialOffline } from "../dist/signing.js";

test("Node SDK canonicalAtcCredential matches official test vector", () => {
  const vector = JSON.parse(readFileSync("../../tests/credentials/v1/test_vectors.json", "utf8"));
  const cred = vector.credential;

  const { canonicalBuffer, claimsSha256 } = canonicalAtcCredential({
    credentialVersion: cred.credential_version,
    credentialId: cred.credential_id,
    issuerId: cred.issuer,
    subjectOrgId: cred.subject.organization_id,
    subjectAgentId: cred.subject.agent_id,
    credentialType: cred.credential_type,
    issuedAt: cred.issued_at,
    notBefore: cred.not_before,
    expiresAt: cred.expires_at,
    environment: cred.environment,
    claims: cred.claims,
  });

  assert.equal(claimsSha256, vector.claims_sha256);
  assert.equal(canonicalBuffer.toString("ascii"), vector.canonical_ascii);

  // Offline verification
  const valid = verifyAtcCredentialOffline(cred, vector.issuer_public_key_base64);
  assert.equal(valid, true);
});

test("Node SDK detects tampered claims", () => {
  const vector = JSON.parse(readFileSync("../../tests/credentials/v1/test_vectors.json", "utf8"));
  const cred = JSON.parse(JSON.stringify(vector.credential));
  cred.claims.organization_membership = false;

  const valid = verifyAtcCredentialOffline(cred, vector.issuer_public_key_base64);
  assert.equal(valid, false);
});
