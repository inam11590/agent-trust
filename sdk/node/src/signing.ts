/** AgentTrust v1 Ed25519 signing for server-side Node.js. */
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";

export function canonicalRequest(method: string, path: string, agentId: string, keyId: string,
  timestamp: string, nonce: string, body: Uint8Array): Buffer {
  const hash = createHash("sha256").update(body).digest("hex");
  return Buffer.from(["v1", method.toUpperCase(), path, agentId, keyId, timestamp, nonce, hash, ""].join("\n"), "ascii");
}

export function canonicalCrossOrgRequestV2(
  method: string,
  path: string,
  sourceOrgId: string,
  targetOrgId: string,
  sourceAgentId: string,
  targetAgentId: string,
  keyId: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array
): Buffer {
  const hash = createHash("sha256").update(body).digest("hex");
  return Buffer.from([
    "v2",
    method.toUpperCase(),
    path,
    sourceOrgId,
    targetOrgId,
    sourceAgentId,
    targetAgentId,
    keyId,
    timestamp,
    nonce,
    hash,
    "",
  ].join("\n"), "ascii");
}

export class AgentSigner {
  readonly agentId: string;
  readonly keyId: string;
  private readonly privateKey: KeyObject;

  constructor(agentId: string, keyId: string, privateKeyPath: string) {
    this.agentId = agentId; this.keyId = keyId;
    this.privateKey = createPrivateKey(readFileSync(privateKeyPath));
    if (this.privateKey.asymmetricKeyType !== "ed25519") throw new Error("An Ed25519 private key is required");
  }

  headers(method: string, path: string, body: Uint8Array,
    timestamp = new Date().toISOString().slice(0, 19) + "Z", nonce = `nonce_${randomBytes(16).toString("hex")}`): Record<string, string> {
    const signature = sign(null, canonicalRequest(method, path, this.agentId, this.keyId, timestamp, nonce, body), this.privateKey);
    return { "X-Agent-ID": this.agentId, "X-Agent-Key-ID": this.keyId,
      "X-Agent-Timestamp": timestamp, "X-Agent-Nonce": nonce,
      "X-Agent-Signature": signature.toString("base64"), "X-Agent-Signature-Version": "v1" };
  }

  crossOrgHeaders(
    method: string,
    path: string,
    body: Uint8Array,
    sourceOrgId: string,
    targetOrgId: string,
    targetAgentId: string,
    timestamp = new Date().toISOString().slice(0, 19) + "Z",
    nonce = `nonce_${randomBytes(16).toString("hex")}`
  ): Record<string, string> {
    const canonical = canonicalCrossOrgRequestV2(
      method,
      path,
      sourceOrgId,
      targetOrgId,
      this.agentId,
      targetAgentId,
      this.keyId,
      timestamp,
      nonce,
      body
    );
    const signature = sign(null, canonical, this.privateKey);
    return {
      "X-Agent-ID": this.agentId,
      "X-Agent-Key-ID": this.keyId,
      "X-Agent-Timestamp": timestamp,
      "X-Agent-Nonce": nonce,
      "X-Agent-Signature": signature.toString("base64"),
      "X-Agent-Signature-Version": "v2",
      "X-Source-Org-ID": sourceOrgId,
      "X-Target-Org-ID": targetOrgId,
      "X-Target-Agent-ID": targetAgentId,
    };
  }

  signAtpEnvelope(options: {
    sourceOrgId: string;
    targetOrgId: string;
    targetAgentId: string;
    capability: string;
    payload: unknown;
    messageId?: string;
    timestamp?: string;
    nonce?: string;
    credentials?: any[];
  }): Record<string, unknown> {
    const msgId = options.messageId ?? `msg_${randomBytes(16).toString("hex")}`;
    const ts = options.timestamp ?? new Date().toISOString().slice(0, 19) + "Z";
    const n = options.nonce ?? `nonce_${randomBytes(16).toString("hex")}`;

    // Canonical payload hash (sort keys deterministically)
    const sortedJson = options.payload === null || options.payload === undefined
      ? "{}"
      : typeof options.payload === "string"
      ? options.payload
      : JSON.stringify(options.payload, Object.keys(options.payload as object).sort());
    const payloadSha256 = createHash("sha256").update(Buffer.from(sortedJson, "utf8")).digest("hex");

    const canonical = Buffer.from([
      "ATP-SIG/1",
      msgId,
      "request",
      options.sourceOrgId,
      this.agentId,
      options.targetOrgId,
      options.targetAgentId,
      options.capability,
      ts,
      n,
      payloadSha256,
      "",
    ].join("\n"), "utf8");

    const signature = sign(null, canonical, this.privateKey);

    const envelope: Record<string, any> = {
      protocol: "ATP/1.0",
      message_id: msgId,
      message_type: "request",
      source: {
        organization_id: options.sourceOrgId,
        agent_id: this.agentId,
        address: `atp://${options.sourceOrgId}/${this.agentId}`,
      },
      target: {
        organization_id: options.targetOrgId,
        agent_id: options.targetAgentId,
        address: `atp://${options.targetOrgId}/${options.targetAgentId}`,
      },
      capability: options.capability,
      timestamp: ts,
      nonce: n,
      payload: options.payload,
      payload_sha256: payloadSha256,
      signature: {
        version: "ATP-SIG/1",
        key_id: this.keyId,
        value: signature.toString("base64"),
      },
    };

    if (options.credentials) {
      envelope.credentials = options.credentials;
    }

    return envelope;
  }
}

export function canonicalAtcCredential(options: {
  credentialVersion: string;
  credentialId: string;
  issuerId: string;
  subjectOrgId: string;
  subjectAgentId: string;
  credentialType: string;
  issuedAt: string;
  notBefore?: string | null;
  expiresAt: string;
  environment: string;
  claims: Record<string, any>;
}): { canonicalBuffer: Buffer; claimsSha256: string } {
  // Sort claims keys deterministically
  const sortedKeys = Object.keys(options.claims).sort();
  const sortedClaims: Record<string, any> = {};
  for (const k of sortedKeys) {
    sortedClaims[k] = options.claims[k];
  }
  const claimsJson = JSON.stringify(sortedClaims);
  const claimsSha256 = createHash("sha256").update(Buffer.from(claimsJson, "utf8")).digest("hex");

  const canonicalAscii = [
    "ATC-SIG/1",
    options.credentialVersion.trim(),
    options.credentialId.trim(),
    options.issuerId.trim(),
    options.subjectOrgId.trim(),
    options.subjectAgentId.trim(),
    options.credentialType.trim(),
    options.issuedAt.trim(),
    (options.notBefore || "").trim(),
    options.expiresAt.trim(),
    options.environment.trim(),
    claimsSha256.trim(),
    "",
  ].join("\n");

  return {
    canonicalBuffer: Buffer.from(canonicalAscii, "ascii"),
    claimsSha256,
  };
}

export function verifyAtcCredentialOffline(
  credential: Record<string, any>,
  issuerPublicKeyBase64: string
): boolean {
  const proof = credential.proof || {};
  const sigB64 = proof.signature;
  if (!sigB64) return false;

  const subj = credential.subject || {};
  const { canonicalBuffer } = canonicalAtcCredential({
    credentialVersion: credential.credential_version || "",
    credentialId: credential.credential_id || "",
    issuerId: credential.issuer || "",
    subjectOrgId: subj.organization_id || "",
    subjectAgentId: subj.agent_id || "",
    credentialType: credential.credential_type || "",
    issuedAt: credential.issued_at || "",
    notBefore: credential.not_before,
    expiresAt: credential.expires_at || "",
    environment: credential.environment || "production",
    claims: credential.claims || {},
  });

  try {
    const rawPub = Buffer.from(issuerPublicKeyBase64, "base64");
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const spki = Buffer.concat([spkiPrefix, rawPub]);
    const pubKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    const sigBytes = Buffer.from(sigB64, "base64");
    return verify(null, canonicalBuffer, pubKey, sigBytes);
  } catch {
    return false;
  }
}
