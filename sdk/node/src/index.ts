import { AgentSigner } from "./signing.js";
export { AgentSigner, canonicalRequest } from "./signing.js";

export interface AuthorizationInput { agentId: string; action: string; resource: string; amount?: number; currency?: string; delegationId?: string; idempotencyKey?: string }
export interface AuthorizationResult { requestId: string; status: "APPROVED" | "REJECTED" | "PENDING" | "EXPIRED"; reason: string }

export class AgentTrustError extends Error {
  constructor(message: string, public readonly status?: number) { super(message); this.name = "AgentTrustError"; }
}

export class AgentTrust {
  readonly environment: "sandbox" | "production";
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly send: typeof fetch;

  constructor(options: { apiKey?: string; baseUrl?: string; timeoutMs?: number; fetch?: typeof fetch } = {}) {
    const key = options.apiKey ?? (typeof process !== "undefined" ? process.env.AGENTTRUST_API_KEY : undefined);
    if (!key || (!key.startsWith("at_live_") && !key.startsWith("at_test_"))) throw new Error("A valid AgentTrust API key is required");
    this.environment = key.startsWith("at_test_") ? "sandbox" : "production";
    this.apiKey = key; this.baseUrl = (options.baseUrl ?? "https://api.agenttrust.example").replace(/\/$/, "");
    this.timeout = options.timeoutMs ?? 10_000; this.send = options.fetch ?? fetch;
  }

  authorize(input: AuthorizationInput): Promise<AuthorizationResult> {
    return this.authorizeWithSigner(input);
  }

  agent(options: { agentId: string; keyId: string; privateKeyPath: string }): SignedAgent {
    return new SignedAgent(this, new AgentSigner(options.agentId, options.keyId, options.privateKeyPath));
  }

  authorizeWithSigner(input: AuthorizationInput, signer?: AgentSigner): Promise<AuthorizationResult> {
    if (!input.agentId || !input.action || !input.resource) throw new Error("agentId, action, and resource are required");
    if ((input.amount === undefined) !== (input.currency === undefined)) throw new Error("amount and currency must be provided together");
    if (input.amount !== undefined && input.amount < 0) throw new Error("amount cannot be negative");
    const payload: Record<string, unknown> = {
      agent_id: input.agentId,
      action: input.action,
      resource: input.resource,
      amount: input.amount,
      currency: input.currency,
    };
    if (input.delegationId) {
      payload.delegation_id = input.delegationId;
    }
    return this.request("/api/v1/authorize", { method: "POST", body: JSON.stringify(payload), headers: input.idempotencyKey ? { "Idempotency-Key": input.idempotencyKey } : undefined }, signer);
  }

  getAuthorizationRequest(requestId: string): Promise<AuthorizationResult> {
    if (!requestId.startsWith("req_")) throw new Error("A valid requestId is required");
    return this.request(`/api/v1/authorization-requests/${encodeURIComponent(requestId)}`);
  }

  async createDelegation(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const res = await this.rawRequest("/api/v1/agent-delegations", { method: "POST", body: JSON.stringify(payload) });
    return res;
  }

  async listDelegations(options: { parentAgentId?: string; childAgentId?: string } = {}): Promise<Record<string, unknown>[]> {
    const params = new URLSearchParams();
    if (options.parentAgentId) params.append("parent_agent_id", options.parentAgentId);
    if (options.childAgentId) params.append("child_agent_id", options.childAgentId);
    const query = params.toString() ? `?${params.toString()}` : "";
    const res = await this.rawRequest(`/api/v1/agent-delegations${query}`);
    return res as Record<string, unknown>[];
  }

  async getDelegation(delegationId: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/api/v1/agent-delegations/${encodeURIComponent(delegationId)}`);
  }

  async getDelegationChain(delegationId: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/api/v1/agent-delegations/${encodeURIComponent(delegationId)}/chain`);
  }

  async revokeDelegation(delegationId: string, reason = "Revoked by user"): Promise<Record<string, unknown>> {
    return this.rawRequest(`/api/v1/agent-delegations/${encodeURIComponent(delegationId)}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  private async rawRequest(path: string, init: RequestInit = {}): Promise<any> {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await this.send(this.baseUrl + path, { ...init, signal: controller.signal, headers: { "X-API-Key": this.apiKey, "Accept": "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers } });
      const body = await response.json() as Record<string, unknown>;
      if (!response.ok) throw new AgentTrustError(`AgentTrust API error (${response.status}): ${String(body.detail ?? "Request failed")}`, response.status);
      return body;
    } catch (error) {
      if (error instanceof AgentTrustError) throw error;
      throw new AgentTrustError("Could not connect to AgentTrust");
    } finally { clearTimeout(timer); }
  }

  private async request(path: string, init: RequestInit = {}, signer?: AgentSigner): Promise<AuthorizationResult> {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      if (signer && typeof init.body !== "string") throw new AgentTrustError("Signed authorization needs a JSON body");
      const signed = signer ? signer.headers(init.method ?? "POST", path, Buffer.from(init.body as string, "utf8")) : {};
      const response = await this.send(this.baseUrl + path, { ...init, signal: controller.signal, headers: { "X-API-Key": this.apiKey, "Accept": "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers, ...signed } });
      const body = await response.json() as Record<string, unknown>;
      if (!response.ok) throw new AgentTrustError(`AgentTrust API error (${response.status}): ${String(body.detail ?? "Request failed")}`, response.status);
      return { requestId: String(body.request_id), status: body.status as AuthorizationResult["status"], reason: String(body.reason) };
    } catch (error) {
      if (error instanceof AgentTrustError) throw error;
      throw new AgentTrustError("Could not connect to AgentTrust");
    } finally { clearTimeout(timer); }
  }
}

export class SignedAgent {
  constructor(private readonly client: AgentTrust, private readonly signer: AgentSigner) {}
  get agentId(): string { return this.signer.agentId; }
  authorize(input: Omit<AuthorizationInput, "agentId">): Promise<AuthorizationResult> {
    return this.client.authorizeWithSigner({ ...input, agentId: this.signer.agentId }, this.signer);
  }
  delegate(options: {
    childAgentId: string;
    parentPermissionId: string;
    action: string;
    resource: string;
    maximumAmount?: number;
    currency?: string;
    requiresApproval?: boolean;
    allowDelegation?: boolean;
    expiresAt?: string;
  }): Promise<Record<string, unknown>> {
    return this.client.createDelegation({
      parent_agent_id: this.signer.agentId,
      child_agent_id: options.childAgentId,
      parent_permission_id: options.parentPermissionId,
      action: options.action,
      resource: options.resource,
      maximum_amount: options.maximumAmount,
      currency: options.currency,
      requires_approval: options.requiresApproval ?? false,
      allow_delegation: options.allowDelegation ?? true,
      expires_at: options.expiresAt,
    });
  }
}
