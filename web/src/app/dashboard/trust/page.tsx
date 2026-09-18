"use client";

import { useState } from "react";
import Link from "next/link";
import {
  CheckCircle2,
  Clock,
  ExternalLink,
  Globe,
  Network,
  Plus,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";

import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import type {
  OrganizationPublicProfile,
  OrganizationTrustRelationship,
} from "@/types";

export default function PartnerTrustPage() {
  const { organization, role = "owner" } = useAuth();
  const canManage = role === "owner" || role === "admin";

  const [activeTab, setActiveTab] = useState<"active" | "pending" | "directory" | "revoked">("active");

  const trustQuery = useApiQuery<OrganizationTrustRelationship[]>("/organization-trust");
  const directoryQuery = useApiQuery<OrganizationPublicProfile[]>("/organization-trust/directory");

  const [actionLoading, setActionLoading] = useState("");
  const [feedbackMessage, setFeedbackMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  // Request Trust Modal State
  const [showRequestModal, setShowRequestModal] = useState(false);
  const [targetOrgId, setTargetOrgId] = useState("");
  const [maxAmount, setMaxAmount] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [approvalStage, setApprovalStage] = useState<"BOTH" | "SOURCE" | "TARGET">("BOTH");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Search in Directory
  const [searchQuery, setSearchQuery] = useState("");

  if (trustQuery.loading || directoryQuery.loading) {
    return <LoadingState label="Loading partner trust relationships" />;
  }

  if (trustQuery.error || directoryQuery.error) {
    return (
      <ErrorState
        message={trustQuery.error ?? directoryQuery.error ?? "Unable to load partner trust data."}
        retry={() => {
          trustQuery.reload();
          directoryQuery.reload();
        }}
      />
    );
  }

  const relationships = trustQuery.data ?? [];
  const currentOrgId = organization?.id;

  const activeTrust = relationships.filter((r) => r.status === "active");
  const pendingTrust = relationships.filter((r) => r.status === "pending");
  const revokedTrust = relationships.filter((r) => r.status === "revoked" || r.status === "rejected" || r.status === "expired");

  const filteredDirectory = (directoryQuery.data ?? []).filter((p) => {
    if (!searchQuery) return true;
    const term = searchQuery.toLowerCase();
    return (
      p.display_name.toLowerCase().includes(term) ||
      (p.description && p.description.toLowerCase().includes(term)) ||
      p.capabilities.some((c) => c.toLowerCase().includes(term))
    );
  });

  async function handleAccept(trustId: string) {
    setActionLoading(trustId);
    setFeedbackMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/organization-trust/${trustId}/accept`, { method: "POST" });
      setFeedbackMessage("Trust relationship accepted successfully.");
      trustQuery.reload();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to accept trust.");
    } finally {
      setActionLoading("");
    }
  }

  async function handleReject(trustId: string) {
    const reason = window.prompt("Reason for rejecting this trust request:", "Not authorized at this time");
    if (reason === null) return;
    setActionLoading(trustId);
    setFeedbackMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/organization-trust/${trustId}/reject`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      setFeedbackMessage("Trust relationship rejected.");
      trustQuery.reload();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to reject trust.");
    } finally {
      setActionLoading("");
    }
  }

  async function handleRevoke(trustId: string) {
    const reason = window.prompt("Reason for revoking trust relationship (all active delegations will be immediately terminated):", "Security policy update");
    if (reason === null) return;
    setActionLoading(trustId);
    setFeedbackMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/organization-trust/${trustId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason }),
      });
      setFeedbackMessage("Trust relationship revoked immediately.");
      trustQuery.reload();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to revoke trust.");
    } finally {
      setActionLoading("");
    }
  }

  async function handleCreateRequest(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setFeedbackMessage("");
    setErrorMessage("");
    try {
      const policy: Record<string, unknown> = {
        approval_stage: approvalStage,
      };
      if (maxAmount) {
        policy.max_amount_per_request = parseFloat(maxAmount);
        policy.currency = currency;
      }
      await apiRequest("/organization-trust/request", {
        method: "POST",
        body: JSON.stringify({
          target_organization_id: targetOrgId.trim(),
          proposed_policy: policy,
          notes: notes.trim() || undefined,
        }),
      });
      setFeedbackMessage("Trust request sent successfully.");
      setShowRequestModal(false);
      setTargetOrgId("");
      setMaxAmount("");
      setNotes("");
      trustQuery.reload();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to submit trust request.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <PageHeader
          title="Partner Trust & Organizations"
          description="Establish explicit, directional zero-trust partnerships with external organizations. No implicit trust is ever granted."
        />
        <div className="flex items-center gap-3">
          <Link
            href="/dashboard/trust/requests"
            className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-slate-200 transition hover:bg-white/10"
          >
            <Clock size={16} className="text-amber-400" />
            Authorization Queue
          </Link>
          {canManage && (
            <button
              onClick={() => setShowRequestModal(true)}
              className="flex items-center gap-2 rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-[#3454c4]"
            >
              <Plus size={16} />
              Request Trust
            </button>
          )}
        </div>
      </div>

      {feedbackMessage && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-3 text-sm text-emerald-400">
          <CheckCircle2 size={16} />
          <span>{feedbackMessage}</span>
        </div>
      )}

      {errorMessage && (
        <div className="flex items-center gap-2 rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-400">
          <ShieldAlert size={16} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-white/10 text-sm">
        <button
          onClick={() => setActiveTab("active")}
          className={`border-b-2 px-4 py-2.5 font-medium transition ${
            activeTab === "active"
              ? "border-[#4168e8] text-white"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Active Partnerships ({activeTrust.length})
        </button>
        <button
          onClick={() => setActiveTab("pending")}
          className={`border-b-2 px-4 py-2.5 font-medium transition ${
            activeTab === "pending"
              ? "border-[#4168e8] text-white"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Pending Requests ({pendingTrust.length})
        </button>
        <button
          onClick={() => setActiveTab("directory")}
          className={`border-b-2 px-4 py-2.5 font-medium transition ${
            activeTab === "directory"
              ? "border-[#4168e8] text-white"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Partner Directory ({directoryQuery.data?.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("revoked")}
          className={`border-b-2 px-4 py-2.5 font-medium transition ${
            activeTab === "revoked"
              ? "border-[#4168e8] text-white"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Revoked History ({revokedTrust.length})
        </button>
      </div>

      {/* Tab: Active Partnerships */}
      {activeTab === "active" && (
        <div>
          {activeTrust.length === 0 ? (
            <EmptyState
              title="No active partner organizations"
              description="Your agents cannot interact with external agents until explicit bidirectional trust is established and confirmed."
            />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-white/10 bg-slate-900/50">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-white/10 bg-white/[0.02] text-xs font-semibold uppercase text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Partner Organization</th>
                    <th className="px-4 py-3">Direction</th>
                    <th className="px-4 py-3">Spend Limit</th>
                    <th className="px-4 py-3">Approval Stage</th>
                    <th className="px-4 py-3">Established</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  {activeTrust.map((r) => {
                    const isSource = r.source_organization_id === currentOrgId;
                    const partnerOrgId = isSource ? r.target_organization_id : r.source_organization_id;
                    const policy = r.agreed_policy || r.source_policy;
                    return (
                      <tr key={r.id} className="hover:bg-white/[0.02]">
                        <td className="px-4 py-3 font-mono text-xs text-slate-200">
                          {partnerOrgId}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${
                              isSource
                                ? "bg-sky-500/10 text-sky-400"
                                : "bg-purple-500/10 text-purple-400"
                            }`}
                          >
                            {isSource ? "Outbound Partner" : "Inbound Partner"}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {policy?.max_amount_per_request
                            ? `${policy.currency || "USD"} ${policy.max_amount_per_request}`
                            : "No limit specified"}
                        </td>
                        <td className="px-4 py-3">
                          <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-300">
                            {policy?.approval_stage || "BOTH"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          {r.established_at ? new Date(r.established_at).toLocaleDateString() : "Active"}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {canManage && (
                            <button
                              disabled={actionLoading === r.id}
                              onClick={() => handleRevoke(r.id)}
                              className="inline-flex items-center gap-1 rounded p-1.5 text-xs font-medium text-rose-400 transition hover:bg-rose-500/10 hover:text-rose-300"
                              title="Revoke Trust"
                            >
                              <Trash2 size={14} />
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab: Pending Requests */}
      {activeTab === "pending" && (
        <div>
          {pendingTrust.length === 0 ? (
            <EmptyState
              title="No pending trust requests"
              description="You have no incoming or outgoing trust invitations awaiting approval."
            />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-white/10 bg-slate-900/50">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-white/10 bg-white/[0.02] text-xs font-semibold uppercase text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Organization</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Proposed Policy</th>
                    <th className="px-4 py-3">Notes</th>
                    <th className="px-4 py-3">Requested Date</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  {pendingTrust.map((r) => {
                    const isIncoming = r.target_organization_id === currentOrgId;
                    const partnerOrgId = isIncoming ? r.source_organization_id : r.target_organization_id;
                    return (
                      <tr key={r.id} className="hover:bg-white/[0.02]">
                        <td className="px-4 py-3 font-mono text-xs text-slate-200">
                          {partnerOrgId}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${
                              isIncoming
                                ? "bg-amber-500/10 text-amber-400"
                                : "bg-blue-500/10 text-blue-400"
                            }`}
                          >
                            {isIncoming ? "Incoming Request" : "Outgoing Request"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {r.source_policy?.max_amount_per_request
                            ? `Max ${r.source_policy.currency || "USD"} ${r.source_policy.max_amount_per_request}`
                            : "Standard policy"}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          {r.notes || "—"}
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-400">
                          {new Date(r.created_at).toLocaleDateString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {canManage && isIncoming ? (
                            <div className="flex items-center justify-end gap-2">
                              <button
                                disabled={actionLoading === r.id}
                                onClick={() => handleAccept(r.id)}
                                className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 transition hover:bg-emerald-500/20"
                              >
                                <CheckCircle2 size={13} />
                                Accept
                              </button>
                              <button
                                disabled={actionLoading === r.id}
                                onClick={() => handleReject(r.id)}
                                className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-2.5 py-1 text-xs font-medium text-rose-400 transition hover:bg-rose-500/20"
                              >
                                <XCircle size={13} />
                                Reject
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-slate-500">Waiting for partner</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab: Partner Directory */}
      {activeTab === "directory" && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm">
            <Search size={16} className="text-slate-400" />
            <input
              type="text"
              placeholder="Search verified organizations by name, description, or capability..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-transparent text-slate-200 placeholder-slate-500 focus:outline-none"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {filteredDirectory.map((org) => (
              <div
                key={org.id}
                className="flex flex-col justify-between rounded-xl border border-white/10 bg-slate-900/50 p-5 transition hover:border-white/20"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <h3 className="font-semibold text-white">{org.display_name}</h3>
                    {org.is_verified && (
                      <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400">
                        <ShieldCheck size={12} />
                        Verified
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">{org.description || "No public description provided."}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {org.capabilities.map((cap) => (
                      <span
                        key={cap}
                        className="rounded bg-white/5 px-2 py-0.5 text-[11px] font-medium text-slate-300"
                      >
                        {cap}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-5 pt-4 border-t border-white/5 flex items-center justify-between">
                  <span className="font-mono text-[10px] text-slate-500">{org.organization_id.slice(0, 8)}...</span>
                  {canManage && org.organization_id !== currentOrgId && (
                    <button
                      onClick={() => {
                        setTargetOrgId(org.organization_id);
                        setShowRequestModal(true);
                      }}
                      className="rounded bg-white/10 px-3 py-1 text-xs font-medium text-white transition hover:bg-[#4168e8]"
                    >
                      Connect
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab: Revoked History */}
      {activeTab === "revoked" && (
        <div>
          {revokedTrust.length === 0 ? (
            <EmptyState
              title="No revoked trust relationships"
              description="Terminated or expired relationships will appear here for audit trail purposes."
            />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-white/10 bg-slate-900/50">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-white/10 bg-white/[0.02] text-xs font-semibold uppercase text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Partner Organization</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Revocation Reason</th>
                    <th className="px-4 py-3">Revoked At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 text-slate-300">
                  {revokedTrust.map((r) => (
                    <tr key={r.id} className="hover:bg-white/[0.02]">
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">
                        {r.source_organization_id === currentOrgId ? r.target_organization_id : r.source_organization_id}
                      </td>
                      <td className="px-4 py-3">
                        <span className="rounded bg-rose-500/10 px-2 py-0.5 text-xs font-medium text-rose-400 uppercase">
                          {r.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {r.revocation_reason || "None recorded"}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {r.revoked_at ? new Date(r.revoked_at).toLocaleString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Request Trust Modal */}
      {showRequestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-slate-900 p-6 shadow-2xl">
            <h2 className="text-lg font-bold text-white">Request Cross-Organization Trust</h2>
            <p className="mt-1 text-xs text-slate-400">
              Propose an explicit trust relationship with an external organization. The target organization must review and accept before any communication can begin.
            </p>

            <form onSubmit={handleCreateRequest} className="mt-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300">Target Organization UUID</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 123e4567-e89b-12d3-a456-426614174000"
                  value={targetOrgId}
                  onChange={(e) => setTargetOrgId(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-[#4168e8] focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300">Max Amount Per Request</label>
                  <input
                    type="number"
                    step="0.01"
                    min="0"
                    placeholder="e.g. 500.00"
                    value={maxAmount}
                    onChange={(e) => setMaxAmount(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-[#4168e8] focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300">Currency</label>
                  <input
                    type="text"
                    maxLength={3}
                    value={currency}
                    onChange={(e) => setCurrency(e.target.value.toUpperCase())}
                    className="mt-1 w-full rounded-lg border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white focus:border-[#4168e8] focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300">Approval Stage Required</label>
                <select
                  value={approvalStage}
                  onChange={(e) => setApprovalStage(e.target.value as "BOTH" | "SOURCE" | "TARGET")}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white focus:border-[#4168e8] focus:outline-none"
                >
                  <option value="BOTH">BOTH (Both organizations must approve actions)</option>
                  <option value="SOURCE">SOURCE (Only calling organization approves)</option>
                  <option value="TARGET">TARGET (Only receiving organization approves)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300">Invitation Notes</label>
                <textarea
                  rows={2}
                  placeholder="Explain why your agents need access to their service..."
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-white/10 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-[#4168e8] focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
                <button
                  type="button"
                  onClick={() => setShowRequestModal(false)}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-medium text-white transition hover:bg-[#3454c4] disabled:opacity-50"
                >
                  {submitting ? "Submitting..." : "Send Trust Request"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
