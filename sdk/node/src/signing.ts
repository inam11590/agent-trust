/** AgentTrust v1 Ed25519 signing for server-side Node.js. */
import { createHash, createPrivateKey, randomBytes, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";

export function canonicalRequest(method: string, path: string, agentId: string, keyId: string,
  timestamp: string, nonce: string, body: Uint8Array): Buffer {
  const hash = createHash("sha256").update(body).digest("hex");
  return Buffer.from(["v1", method.toUpperCase(), path, agentId, keyId, timestamp, nonce, hash, ""].join("\n"), "ascii");
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
}
