import { AgentSigner } from "./signing.js";
export { AgentSigner, canonicalRequest, canonicalCrossOrgRequestV2 } from "./signing.js";

export interface AuthorizationInput { agentId: string; action: string; resource: string; amount?: number; currency?: string; delegationId?: string; idempotencyKey?: string }
export interface AuthorizationResult { requestId: string; status: "APPROVED" | "REJECTED" | "PENDING" | "EXPIRED"; reason: string }

export interface CrossOrgAuthorizeInput {
  sourceAgentId: string;
  targetOrgId: string;
  targetAgentId: string;
  action: string;
  resource: string;
  amount?: number;
  currency?: string;
  delegationId?: string;
  context?: Record<string, unknown>;
  idempotencyKey?: string;
  sourceOrgId?: string;
}

export interface CrossOrgAuthorizeResult {
  requestId: string;
  status: "APPROVED" | "REJECTED" | "PENDING";
  reason: string;
  pendingApprovals?: string[];
}

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

  async authorizeCrossOrg(input: CrossOrgAuthorizeInput, signer?: AgentSigner): Promise<CrossOrgAuthorizeResult> {
    if (!input.sourceAgentId || !input.targetOrgId || !input.targetAgentId || !input.action || !input.resource) {
      throw new Error("sourceAgentId, targetOrgId, targetAgentId, action, and resource are required");
    }
    if ((input.amount === undefined) !== (input.currency === undefined)) {
      throw new Error("amount and currency must be provided together");
    }
    const payload: Record<string, unknown> = {
      source_agent_id: input.sourceAgentId,
      target_org_id: input.targetOrgId,
      target_agent_id: input.targetAgentId,
      action: input.action,
      resource: input.resource,
    };
    if (input.amount !== undefined) {
      payload.amount = input.amount;
      payload.currency = input.currency;
    }
    if (input.delegationId) payload.delegation_id = input.delegationId;
    if (input.context) payload.context = input.context;

    const path = "/api/v1/cross-org/authorize";
    const bodyStr = JSON.stringify(payload);
    const headers: Record<string, string> = {};
    if (input.idempotencyKey) headers["Idempotency-Key"] = input.idempotencyKey;

    if (signer) {
      const crossHeaders = signer.crossOrgHeaders(
        "POST",
        path,
        Buffer.from(bodyStr, "utf8"),
        input.sourceOrgId ?? "00000000-0000-0000-0000-000000000000",
        input.targetOrgId,
        input.targetAgentId
      );
      Object.assign(headers, crossHeaders);
    }

    const res = await this.rawRequest(path, {
      method: "POST",
      body: bodyStr,
      headers,
    });
    return {
      requestId: String(res.request_id),
      status: res.status as CrossOrgAuthorizeResult["status"],
      reason: String(res.reason),
      pendingApprovals: res.pending_approvals as string[] | undefined,
    };
  }

  async listTrust(options: { status?: string; direction?: string } = {}): Promise<Record<string, unknown>[]> {
    const params = new URLSearchParams();
    if (options.status) params.append("status", options.status);
    if (options.direction) params.append("direction", options.direction);
    const qs = params.toString() ? `?${params.toString()}` : "";
    return this.rawRequest(`/v1/organization-trust${qs}`);
  }

  async getTrust(trustId: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/organization-trust/${encodeURIComponent(trustId)}`);
  }

  async requestTrust(payload: { targetOrganizationId: string; proposedPolicy: Record<string, unknown>; notes?: string }): Promise<Record<string, unknown>> {
    return this.rawRequest("/v1/organization-trust/request", {
      method: "POST",
      body: JSON.stringify({
        target_organization_id: payload.targetOrganizationId,
        proposed_policy: payload.proposedPolicy,
        notes: payload.notes,
      }),
    });
  }

  async acceptTrust(trustId: string, agreedPolicy?: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/organization-trust/${encodeURIComponent(trustId)}/accept`, {
      method: "POST",
      body: JSON.stringify({ agreed_policy: agreedPolicy }),
    });
  }

  async rejectTrust(trustId: string, reason = "Rejected by target organization"): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/organization-trust/${encodeURIComponent(trustId)}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async revokeTrust(trustId: string, reason = "Revoked by organization"): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/organization-trust/${encodeURIComponent(trustId)}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async searchProfiles(options: { query?: string; tag?: string } = {}): Promise<Record<string, unknown>[]> {
    const params = new URLSearchParams();
    if (options.query) params.append("q", options.query);
    if (options.tag) params.append("tag", options.tag);
    const qs = params.toString() ? `?${params.toString()}` : "";
    return this.rawRequest(`/v1/organization-trust/directory${qs}`);
  }

  async getSecurityOverview(windowHours = 24): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/security/overview?window_hours=${windowHours}`);
  }

  async listSecurityEvents(params: { severity?: string; category?: string; limit?: number } = {}): Promise<Record<string, unknown>> {
    const q = new URLSearchParams({ limit: String(params.limit ?? 50) });
    if (params.severity) q.set("severity", params.severity);
    if (params.category) q.set("category", params.category);
    return this.rawRequest(`/v1/security/events?${q.toString()}`);
  }

  async listSecurityAlerts(params: { status?: string; severity?: string; limit?: number } = {}): Promise<Record<string, unknown>> {
    const q = new URLSearchParams({ limit: String(params.limit ?? 50) });
    if (params.status) q.set("status", params.status);
    if (params.severity) q.set("severity", params.severity);
    return this.rawRequest(`/v1/security/alerts?${q.toString()}`);
  }

  async acknowledgeSecurityAlert(alertId: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/security/alerts/${encodeURIComponent(alertId)}/acknowledge`, { method: "POST" });
  }

  async resolveSecurityAlert(alertId: string, note?: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/v1/security/alerts/${encodeURIComponent(alertId)}/resolve`, {
      method: "POST",
      body: JSON.stringify(note ? { resolution_note: note } : {}),
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

  async dispatchAtpEnvelope(envelope: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.rawRequest("/api/v1/atp/messages", {
      method: "POST",
      body: JSON.stringify(envelope),
    });
  }

  async getAtpMessage(messageId: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/api/v1/atp/messages/${messageId}`, { method: "GET" });
  }

  async getGatewayIdentity(): Promise<Record<string, unknown>> {
    return this.rawRequest("/api/v1/atp/gateway-identity", { method: "GET" });
  }

  // Step 28: Enterprise Agent Lifecycle Governance
  async getGovernanceDashboard(): Promise<Record<string, unknown>> {
    return this.rawRequest("/api/v1/governance/dashboard", { method: "GET" });
  }

  async getGovernanceSignals(agentId?: string): Promise<Record<string, unknown>[]> {
    const qs = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : "";
    return this.rawRequest(`/api/v1/governance/signals${qs}`, { method: "GET" }) as unknown as Promise<Record<string, unknown>[]>;
  }

  async listCertifications(status?: string): Promise<Record<string, unknown>[]> {
    const qs = status ? `?status=${encodeURIComponent(status)}` : "";
    return this.rawRequest(`/api/v1/governance/certifications${qs}`, { method: "GET" }) as unknown as Promise<Record<string, unknown>[]>;
  }

  async requestCertification(options: { agentId: string; dueDays?: number; notes?: string }): Promise<Record<string, unknown>> {
    return this.rawRequest("/api/v1/governance/certifications", {
      method: "POST",
      body: JSON.stringify({ agent_id: options.agentId, due_days: options.dueDays ?? 14, notes: options.notes }),
    });
  }

  async decideCertification(certificationId: string, decision: "APPROVED" | "REJECTED", notes?: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/api/v1/governance/certifications/${encodeURIComponent(certificationId)}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision, notes }),
    });
  }

  async transitionAgentLifecycle(agentIdentifier: string, targetStatus: string, reason?: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/agents/${encodeURIComponent(agentIdentifier)}/lifecycle/transition`, {
      method: "POST",
      body: JSON.stringify({ target_status: targetStatus, reason }),
    });
  }

  async transferAgentOwnership(agentIdentifier: string, newOwnerId: string, options: { newOwnerType?: string; reason?: string; newTeam?: string } = {}): Promise<Record<string, unknown>> {
    return this.rawRequest(`/agents/${encodeURIComponent(agentIdentifier)}/ownership/transfer`, {
      method: "POST",
      body: JSON.stringify({
        new_owner_id: newOwnerId,
        new_owner_type: options.newOwnerType ?? "USER",
        reason: options.reason ?? "Ownership reassignment",
        new_team: options.newTeam,
      }),
    });
  }

  async getAgentRelationships(agentIdentifier: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/agents/${encodeURIComponent(agentIdentifier)}/relationships`, { method: "GET" });
  }

  async suspendAgent(agentIdentifier: string, reason: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/agents/${encodeURIComponent(agentIdentifier)}/suspend`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async reactivateAgent(agentIdentifier: string, reason?: string): Promise<Record<string, unknown>> {
    return this.rawRequest(`/agents/${encodeURIComponent(agentIdentifier)}/reactivate`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  async retireAgent(agentIdentifier: string, reason: string, force = false): Promise<Record<string, unknown>> {
    return this.rawRequest(`/agents/${encodeURIComponent(agentIdentifier)}/retirement/execute`, {
      method: "POST",
      body: JSON.stringify({ reason, force }),
    });
  }
}

export class SignedAgent {
  constructor(private readonly client: AgentTrust, private readonly signer: AgentSigner) {}
  get agentId(): string { return this.signer.agentId; }
  authorize(input: Omit<AuthorizationInput, "agentId">): Promise<AuthorizationResult> {
    return this.client.authorizeWithSigner({ ...input, agentId: this.signer.agentId }, this.signer);
  }
  authorizeExternal(input: Omit<CrossOrgAuthorizeInput, "sourceAgentId">): Promise<CrossOrgAuthorizeResult> {
    return this.client.authorizeCrossOrg({ ...input, sourceAgentId: this.signer.agentId }, this.signer);
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

  sendAtpMessage(options: {
    sourceOrgId: string;
    targetAddress: string;
    capability: string;
    payload: unknown;
    messageId?: string;
  }): Promise<Record<string, unknown>> {
    if (!options.targetAddress.startsWith("atp://")) {
      throw new Error(`Invalid target address: ${options.targetAddress}. Expected atp://<org>/<agent>`);
    }
    const parts = options.targetAddress.slice("atp://".length).split("/");
    if (parts.length !== 2) {
      throw new Error(`Invalid target address: ${options.targetAddress}. Expected atp://<org>/<agent>`);
    }
    const [targetOrgId, targetAgentId] = parts;
    const envelope = this.signer.signAtpEnvelope({
      sourceOrgId: options.sourceOrgId,
      targetOrgId,
      targetAgentId,
      capability: options.capability,
      payload: options.payload,
      messageId: options.messageId,
    });
    return this.client.dispatchAtpEnvelope(envelope);
  }
}
