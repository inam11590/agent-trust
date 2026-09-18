"use client";

import { useState } from "react";
import { ArrowRight, CheckCircle2, GitFork, Link2, ShieldAlert, ShieldCheck, Trash2, XCircle } from "lucide-react";

import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import type { Agent, AgentDelegation, DelegationChainResponse, Permission } from "@/types";

export default function DelegationsPage() {
  const { role = "owner" } = useAuth();
  const canManage = role === "owner" || role === "admin";

  const delegations = useApiQuery<AgentDelegation[]>("/agent-delegations");
  const agents = useApiQuery<Agent[]>("/agents");
  const permissions = useApiQuery<Permission[]>("/permissions");

  const [revoking, setRevoking] = useState("");
  const [message, setMessage] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  // Inspect chain state
  const [selectedChain, setSelectedChain] = useState<DelegationChainResponse | null>(null);
  const [loadingChain, setLoadingChain] = useState(false);

  // New delegation modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [parentAgentId, setParentAgentId] = useState("");
  const [childAgentId, setChildAgentId] = useState("");
  const [parentPermissionId, setParentPermissionId] = useState("");
  const [action, setAction] = useState("");
  const [resource, setResource] = useState("");
  const [maxAmount, setMaxAmount] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [requiresApproval, setRequiresApproval] = useState(false);
  const [disallowFurther, setDisallowFurther] = useState(false);
  const [hoursValid, setHoursValid] = useState("24");
  const [creating, setCreating] = useState(false);

  if (delegations.loading || agents.loading || permissions.loading) {
    return <LoadingState label="Loading agent delegations" />;
  }

  if (delegations.error || agents.error || permissions.error) {
    return (
      <ErrorState
        message={delegations.error ?? agents.error ?? permissions.error ?? "Unable to load delegations."}
        retry={() => {
          delegations.reload();
          agents.reload();
          permissions.reload();
        }}
      />
    );
  }

  const agentMap = new Map((agents.data ?? []).map((a) => [a.id, a.name]));

  async function handleRevoke(id: string) {
    if (!window.confirm("Revoke this delegation? All child delegations descending from this delegation will be cascaded and revoked immediately.")) return;
    setRevoking(id);
    setMessage("");
    setErrorMsg("");
    try {
      await apiRequest(`/agent-delegations/${id}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason: "Revoked via Web Dashboard" }),
      });
      setMessage("Delegation and all transitive descendants revoked successfully.");
      delegations.reload();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Unable to revoke delegation.");
    } finally {
      setRevoking("");
    }
  }

  async function handleInspectChain(delegationId: string) {
    setLoadingChain(true);
    try {
      const chain = await apiRequest<DelegationChainResponse>(`/agent-delegations/${delegationId}/chain`);
      setSelectedChain(chain);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load delegation chain.");
    } finally {
      setLoadingChain(false);
    }
  }

  async function handleCreateDelegation(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setMessage("");
    setErrorMsg("");
    try {
      const expiresAt = new Date(Date.now() + parseInt(hoursValid, 10) * 3600 * 1000).toISOString();
      await apiRequest("/agent-delegations", {
        method: "POST",
        body: JSON.stringify({
          parent_agent_id: parentAgentId,
          child_agent_id: childAgentId,
          parent_permission_id: parentPermissionId,
          action,
          resource,
          maximum_amount: maxAmount ? parseFloat(maxAmount) : null,
          currency: maxAmount ? currency : null,
          requires_approval: requiresApproval,
          allow_delegation: !disallowFurther,
          expires_at: expiresAt,
        }),
      });
      setMessage("Agent delegation created successfully.");
      setShowCreateModal(false);
      delegations.reload();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create delegation.");
    } finally {
      setCreating(false);
    }
  }

  const filteredPermissions = (permissions.data ?? []).filter(
    (p) => (!parentAgentId || p.agent_id === parentAgentId) && p.status === "active"
  );

  return (
    <div className="space-y-7">
      <PageHeader
        title="Agent-to-Agent Trust"
        description="Securely delegate scoped permissions from parent AI agents to child AI agents with strict constraint monotonicity, cycle prevention, and immediate cascade revocation."
        action={
          canManage ? (
            <button
              onClick={() => setShowCreateModal(true)}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700"
            >
              <GitFork size={16} /> Create Delegation
            </button>
          ) : undefined
        }
      />

      {message && (
        <div role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
          {message}
        </div>
      )}

      {errorMsg && (
        <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          {errorMsg}
        </div>
      )}

      {/* Security Architecture Highlights */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg bg-blue-50 text-blue-600"><ShieldCheck size={20} /></span>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Monotonicity Rule</p>
              <p className="text-sm font-medium text-slate-900">Narrower Authority Only</p>
            </div>
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Delegated permissions can never exceed parent permissions in scope, maximum amount, or validity window, and human approval can never be bypassed.
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg bg-indigo-50 text-indigo-600"><Link2 size={20} /></span>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Chain Verification</p>
              <p className="text-sm font-medium text-slate-900">Max Depth 3 & Cycle Prevention</p>
            </div>
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Transitive delegation chains (A &rarr; B &rarr; C) are verified in full on every signed action request with cycle detection.
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg bg-amber-50 text-amber-600"><ShieldAlert size={20} /></span>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Cascade Revocation</p>
              <p className="text-sm font-medium text-slate-900">Instant Hierarchy Cutoff</p>
            </div>
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Revoking a parent delegation or root permission immediately stops all descendant delegations from executing actions.
          </p>
        </div>
      </div>

      {/* Delegations List */}
      {!delegations.data?.length ? (
        <EmptyState
          title="No agent delegations configured"
          description="Create a delegation to allow one AI agent to perform tasks on behalf of another AI agent within your organization."
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 px-6 py-4">
            <h3 className="text-sm font-semibold text-slate-900">Active & Historical Delegations ({delegations.data.length})</h3>
          </div>
          <div className="divide-y divide-slate-200">
            {delegations.data.map((delg) => {
              const parentName = agentMap.get(delg.parent_agent_id) ?? delg.parent_agent_id;
              const childName = agentMap.get(delg.child_agent_id) ?? delg.child_agent_id;
              const isActive = delg.status === "active";

              return (
                <div key={delg.id} className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="inline-flex items-center gap-1.5 rounded-md bg-blue-50 px-2.5 py-1 text-xs font-medium text-blue-700">
                        {parentName}
                      </span>
                      <ArrowRight size={14} className="text-slate-400" />
                      <span className="inline-flex items-center gap-1.5 rounded-md bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700">
                        {childName}
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
                          isActive ? "bg-emerald-100 text-emerald-800" : "bg-slate-100 text-slate-600"
                        }`}
                      >
                        {delg.status}
                      </span>
                      <span className="text-xs text-slate-400">Depth {delg.depth}</span>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-600">
                      <span>
                        Action: <strong className="font-mono text-slate-900">{delg.action}</strong>
                      </span>
                      <span>
                        Resource: <strong className="font-mono text-slate-900">{delg.resource}</strong>
                      </span>
                      {delg.maximum_amount && (
                        <span>
                          Limit: <strong className="text-slate-900">{delg.maximum_amount} {delg.currency}</strong>
                        </span>
                      )}
                      <span>
                        Expires: <strong className="text-slate-900">{new Date(delg.expires_at).toLocaleDateString()}</strong>
                      </span>
                      {delg.requires_approval && (
                        <span className="rounded bg-amber-50 px-1.5 py-0.5 text-amber-700">Approval Required</span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleInspectChain(delg.delegation_id)}
                      disabled={loadingChain}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    >
                      <Link2 size={14} /> Chain
                    </button>
                    {canManage && isActive && (
                      <button
                        onClick={() => handleRevoke(delg.delegation_id)}
                        disabled={revoking === delg.delegation_id}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-100"
                      >
                        <Trash2 size={14} /> {revoking === delg.delegation_id ? "Revoking..." : "Revoke"}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Inspect Chain Modal */}
      {selectedChain && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4">
          <div className="w-full max-w-2xl rounded-2xl bg-white p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div>
                <h3 className="text-lg font-semibold text-slate-900">Delegation Chain Inspection</h3>
                <p className="text-xs text-slate-500">Transitive hierarchy verification for {selectedChain.delegation_id}</p>
              </div>
              <button onClick={() => setSelectedChain(null)} className="rounded-lg p-1 text-slate-400 hover:bg-slate-100">
                <XCircle size={20} />
              </button>
            </div>

            <div className="mt-4 space-y-4">
              <div className="flex items-center gap-2 rounded-lg bg-slate-50 p-3 text-xs">
                <span className="font-semibold text-slate-700">Chain Status:</span>
                {selectedChain.is_valid ? (
                  <span className="flex items-center gap-1 text-emerald-600 font-medium"><CheckCircle2 size={14} /> Chain Fully Valid</span>
                ) : (
                  <span className="flex items-center gap-1 text-red-600 font-medium"><XCircle size={14} /> Invalid: {selectedChain.invalid_reason}</span>
                )}
              </div>

              <div className="relative border-l-2 border-blue-200 pl-4 space-y-4 ml-4">
                {selectedChain.chain.map((node) => (
                  <div key={node.depth} className="relative rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="absolute -left-[25px] top-4 size-4 rounded-full border-2 border-blue-500 bg-white" />
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-blue-600">
                        {node.depth === 0 ? "Root User Permission" : `Delegation Step ${node.depth}`}
                      </span>
                      <span className="text-xs text-slate-500">{node.status}</span>
                    </div>
                    <p className="mt-1 text-sm font-semibold text-slate-900">{node.agent_name}</p>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-600">
                      <div>Action: <span className="font-mono text-slate-800">{node.action}</span></div>
                      <div>Resource: <span className="font-mono text-slate-800">{node.resource}</span></div>
                      {node.maximum_amount && (
                        <div>Max Amount: <span className="font-semibold text-slate-800">{node.maximum_amount} {node.currency}</span></div>
                      )}
                      <div>Requires Approval: <span className="font-semibold text-slate-800">{node.requires_approval ? "Yes" : "No"}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <button
                onClick={() => setSelectedChain(null)}
                className="rounded-lg bg-slate-100 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Delegation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4">
          <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div>
                <h3 className="text-lg font-semibold text-slate-900">Create Agent Delegation</h3>
                <p className="text-xs text-slate-500">Monotonically delegate scoped authority to a child agent.</p>
              </div>
              <button onClick={() => setShowCreateModal(false)} className="rounded-lg p-1 text-slate-400 hover:bg-slate-100">
                <XCircle size={20} />
              </button>
            </div>

            <form onSubmit={handleCreateDelegation} className="mt-4 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700">Parent Agent</label>
                  <select
                    value={parentAgentId}
                    onChange={(e) => setParentAgentId(e.target.value)}
                    required
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs"
                  >
                    <option value="">Select Parent</option>
                    {(agents.data ?? []).map((a) => (
                      <option key={a.id} value={a.id}>{a.name}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700">Child Agent</label>
                  <select
                    value={childAgentId}
                    onChange={(e) => setChildAgentId(e.target.value)}
                    required
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs"
                  >
                    <option value="">Select Child</option>
                    {(agents.data ?? []).filter((a) => a.id !== parentAgentId).map((a) => (
                      <option key={a.id} value={a.id}>{a.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700">Parent Permission (Root)</label>
                <select
                  value={parentPermissionId}
                  onChange={(e) => {
                    const id = e.target.value;
                    setParentPermissionId(id);
                    const perm = permissions.data?.find((p) => p.id === id);
                    if (perm) {
                      setAction(perm.action);
                      setResource(perm.resource);
                      if (perm.maximum_amount) setMaxAmount(perm.maximum_amount);
                      if (perm.currency) setCurrency(perm.currency);
                      if (perm.requires_approval) setRequiresApproval(true);
                    }
                  }}
                  required
                  className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs"
                >
                  <option value="">Select Parent Permission</option>
                  {filteredPermissions.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.action} on {p.resource} {p.maximum_amount ? `(Max: ${p.maximum_amount} ${p.currency})` : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700">Action</label>
                  <input
                    type="text"
                    value={action}
                    onChange={(e) => setAction(e.target.value)}
                    required
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700">Resource</label>
                  <input
                    type="text"
                    value={resource}
                    onChange={(e) => setResource(e.target.value)}
                    required
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700">Maximum Amount</label>
                  <input
                    type="number"
                    step="0.01"
                    value={maxAmount}
                    onChange={(e) => setMaxAmount(e.target.value)}
                    placeholder="Optional"
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700">Validity (Hours)</label>
                  <input
                    type="number"
                    value={hoursValid}
                    onChange={(e) => setHoursValid(e.target.value)}
                    min="1"
                    max="720"
                    required
                    className="mt-1 w-full rounded-lg border border-slate-300 p-2 text-xs"
                  />
                </div>
              </div>

              <div className="space-y-2 pt-2">
                <label className="flex items-center gap-2 text-xs text-slate-700">
                  <input
                    type="checkbox"
                    checked={requiresApproval}
                    onChange={(e) => setRequiresApproval(e.target.checked)}
                    className="rounded border-slate-300 text-blue-600"
                  />
                  <span>Require human approval for delegated actions</span>
                </label>

                <label className="flex items-center gap-2 text-xs text-slate-700">
                  <input
                    type="checkbox"
                    checked={disallowFurther}
                    onChange={(e) => setDisallowFurther(e.target.checked)}
                    className="rounded border-slate-300 text-blue-600"
                  />
                  <span>Disallow further delegation by child agent</span>
                </label>
              </div>

              <div className="mt-6 flex justify-end gap-2 border-t border-slate-100 pt-4">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="rounded-lg bg-slate-100 px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-700"
                >
                  {creating ? "Creating..." : "Create Delegation"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
