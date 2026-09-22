"use client";

import { FormEvent, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Bot,
  Calendar,
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  FileCheck,
  Key,
  Layers,
  Network,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Users,
} from "lucide-react";

import { ActivityTable } from "@/components/activity-table";
import { SigningKeys } from "@/components/signing-keys";
import {
  EmptyState,
  ErrorState,
  Field,
  LoadingState,
  PageHeader,
  StatusBadge,
  buttonClass,
  inputClass,
  secondaryButtonClass,
  textareaClass,
} from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate, formatMoney } from "@/lib/format";
import type { Agent, AgentCertification, AgentOwnershipHistory, PaginatedAuditLogs, Permission } from "@/types";

export default function AgentDetailsPage() {
  const { role = "owner" } = useAuth();
  const id = String(useParams<{ id: string }>().id);
  const agent = useApiQuery<Agent>(`/agents/${encodeURIComponent(id)}`);
  const permissions = useApiQuery<Permission[]>("/permissions");
  const activity = useApiQuery<PaginatedAuditLogs>(`/agents/${encodeURIComponent(id)}/audit-logs?page=1&page_size=10`);
  const ownershipHistory = useApiQuery<AgentOwnershipHistory[]>(`/agents/${encodeURIComponent(id)}/ownership/history`);

  const [activeTab, setActiveTab] = useState<string>("overview");
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  // Transfer ownership form state
  const [transferOwnerId, setTransferOwnerId] = useState("");
  const [transferOwnerType, setTransferOwnerType] = useState("USER");
  const [transferTeam, setTransferTeam] = useState("");
  const [transferReason, setTransferReason] = useState("");

  if ([agent, permissions, activity].some((query) => query.loading)) return <LoadingState label="Loading agent workbench" />;
  const error = [agent, permissions, activity].find((query) => query.error)?.error;
  if (error || !agent.data) {
    return (
      <ErrorState
        message={error ?? "Agent not found."}
        retry={() => {
          agent.reload();
          permissions.reload();
          activity.reload();
        }}
      />
    );
  }

  const ag = agent.data;
  const grants = permissions.data?.filter((p) => p.agent_id === ag.id) ?? [];
  const canManage = role === "owner" || role === "admin";

  async function handleLifecycleTransition(targetStatus: string, reason?: string) {
    setBusy(true);
    setMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/agents/${encodeURIComponent(id)}/lifecycle/transition`, {
        method: "POST",
        body: JSON.stringify({ target_status: targetStatus, reason }),
      });
      setMessage(`Agent state transitioned to ${targetStatus}.`);
      agent.reload();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to transition lifecycle state.");
    } finally {
      setBusy(false);
    }
  }

  async function handleOwnershipTransfer(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/agents/${encodeURIComponent(id)}/ownership/transfer`, {
        method: "POST",
        body: JSON.stringify({
          new_owner_id: transferOwnerId,
          new_owner_type: transferOwnerType,
          new_team: transferTeam || undefined,
          reason: transferReason,
        }),
      });
      setMessage("Ownership transferred successfully.");
      setTransferOwnerId("");
      setTransferReason("");
      agent.reload();
      ownershipHistory.reload();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to transfer ownership.");
    } finally {
      setBusy(false);
    }
  }

  async function handleTriggerReview() {
    setBusy(true);
    setMessage("");
    setErrorMessage("");
    try {
      await apiRequest("/governance/certifications", {
        method: "POST",
        body: JSON.stringify({
          agent_id: ag.id,
          due_days: 14,
          notes: "Certification review initiated from agent workbench.",
        }),
      });
      setMessage("Certification review initiated.");
      agent.reload();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to initiate certification review.");
    } finally {
      setBusy(false);
    }
  }

  async function updateAgentMetadata(payload: object) {
    setBusy(true);
    setMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/agents/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      setMessage("Agent governance attributes updated.");
      setEditing(false);
      agent.reload();
    } catch (err: any) {
      setErrorMessage(err.message || "Unable to update agent.");
    } finally {
      setBusy(false);
    }
  }

  const lifecycleStages = ["draft", "registered", "review_required", "approved", "active"];
  const currentStageIndex = lifecycleStages.indexOf(ag.status.toLowerCase());

  const TABS = [
    { id: "overview", label: "Overview" },
    { id: "identity", label: "Identity & Keys" },
    { id: "owner", label: "Ownership & Team" },
    { id: "purpose", label: "Purpose & Scope" },
    { id: "classification", label: "Risk Classification" },
    { id: "lifecycle", label: "Lifecycle" },
    { id: "permissions", label: `Permissions (${grants.length})` },
    { id: "credentials", label: "Credentials" },
    { id: "policies", label: "Policies (APL)" },
    { id: "trust", label: "Cross-Org Trust" },
    { id: "delegations", label: "Delegations" },
    { id: "gateways", label: "Gateways" },
    { id: "activity", label: "Activity" },
    { id: "security", label: "Security Events" },
    { id: "certifications", label: "Access Reviews" },
    { id: "relationships", label: "Blast Radius" },
    { id: "audit", label: "Audit Trail" },
  ];

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center gap-2 text-sm text-slate-500">
        <Link href="/dashboard/agents" className="hover:text-slate-800">
          Agents
        </Link>
        <ChevronRight size={14} />
        <span className="font-semibold text-slate-900">{ag.name}</span>
      </div>

      {/* Header with Title and Status */}
      <PageHeader
        title={ag.name}
        description={`Identity: ${ag.agent_identifier} · Environment: ${ag.environment || "production"}`}
        action={
          <div className="flex items-center gap-3">
            <Link
              href={`/dashboard/agents/${ag.agent_identifier}/relationships`}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <Network size={14} /> Blast Radius
            </Link>
            <StatusBadge value={ag.status} />
          </div>
        }
      />

      {/* Alerts */}
      {message && (
        <div className="flex items-center gap-2 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800">
          <CheckCircle2 size={16} /> {message}
        </div>
      )}
      {errorMessage && (
        <div className="flex items-center gap-2 rounded-lg bg-rose-50 p-3 text-sm text-rose-800">
          <AlertTriangle size={16} /> {errorMessage}
        </div>
      )}

      {/* Lifecycle Progression Bar & Action Bar */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
            Lifecycle Governance Pipeline
          </h3>
          <div className="flex items-center gap-2">
            {canManage && ag.status.toLowerCase() === "registered" && (
              <button
                disabled={busy}
                onClick={() => handleLifecycleTransition("review_required", "Submitted for promotion review")}
                className="rounded-lg bg-[#3157d5] px-3 py-1.5 text-xs font-semibold text-white hover:bg-[#2847b3] disabled:opacity-50"
              >
                Submit for Review
              </button>
            )}
            {canManage && ag.status.toLowerCase() === "review_required" && (
              <button
                disabled={busy}
                onClick={() => handleLifecycleTransition("approved", "Reviewer approved checklist")}
                className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
              >
                Approve Agent
              </button>
            )}
            {canManage && ag.status.toLowerCase() === "approved" && (
              <button
                disabled={busy}
                onClick={() => handleLifecycleTransition("active", "Promoted to operational active state")}
                className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
              >
                Activate Agent
              </button>
            )}
            {canManage && ag.status.toLowerCase() === "active" && (
              <>
                <button
                  disabled={busy}
                  onClick={() => handleTriggerReview()}
                  className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                >
                  Trigger Access Review
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("suspended", "Emergency suspension from workbench")}
                  className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-700 disabled:opacity-50"
                >
                  Emergency Suspend
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("retired", "Decommissioned from workbench")}
                  className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
                >
                  Retire
                </button>
              </>
            )}
            {canManage && ag.status.toLowerCase() === "suspended" && (
              <>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("active", "Reactivated from suspension")}
                  className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                >
                  Reactivate
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("retired", "Decommissioned from suspension")}
                  className="rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
                >
                  Retire
                </button>
              </>
            )}
          </div>
        </div>

        {/* Visual pipeline steps */}
        <div className="flex items-center justify-between gap-2 overflow-x-auto pt-2">
          {lifecycleStages.map((stage, idx) => {
            const isCompleted = currentStageIndex > idx;
            const isCurrent = currentStageIndex === idx;
            const isSpecial = ag.status.toLowerCase() === "suspended" || ag.status.toLowerCase() === "retired";

            return (
              <div key={stage} className="flex flex-1 items-center gap-2 min-w-[120px]">
                <div
                  className={`flex size-7 items-center justify-center rounded-full text-xs font-bold ${
                    isCurrent
                      ? "bg-[#3157d5] text-white ring-4 ring-blue-100"
                      : isCompleted
                      ? "bg-emerald-100 text-emerald-800"
                      : "bg-slate-100 text-slate-400"
                  }`}
                >
                  {isCompleted ? <CheckCircle2 size={14} /> : idx + 1}
                </div>
                <span
                  className={`text-xs font-medium uppercase truncate ${
                    isCurrent ? "font-bold text-[#3157d5]" : isCompleted ? "text-slate-800" : "text-slate-400"
                  }`}
                >
                  {stage.replace("_", " ")}
                </span>
                {idx < lifecycleStages.length - 1 && <div className="h-0.5 flex-1 bg-slate-200" />}
              </div>
            );
          })}
        </div>
      </div>

      {/* 17 Tab Navigation Strip */}
      <div className="border-b border-slate-200">
        <nav className="flex space-x-4 overflow-x-auto pb-1">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`whitespace-nowrap border-b-2 px-3 py-2 text-xs font-medium transition ${
                activeTab === tab.id
                  ? "border-[#3157d5] text-[#3157d5] font-semibold"
                  : "border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-700"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* TAB CONTENT PANELS */}

      {/* 1. Overview Tab */}
      {activeTab === "overview" && (
        <div className="grid gap-5 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-slate-950">Identity & Metadata</h3>
              {canManage && (
                <button
                  onClick={() => setEditing(!editing)}
                  className="text-xs font-semibold text-[#3157d5] hover:underline"
                >
                  {editing ? "Cancel" : "Edit Details"}
                </button>
              )}
            </div>

            {editing ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const form = new FormData(e.currentTarget);
                  void updateAgentMetadata({
                    name: String(form.get("name")),
                    description: String(form.get("description")) || null,
                    purpose: String(form.get("purpose")) || null,
                    business_function: String(form.get("business_function")) || null,
                  });
                }}
                className="space-y-4 text-xs"
              >
                <Field label="Agent Name">
                  <input name="name" defaultValue={ag.name} className={inputClass} required />
                </Field>
                <Field label="Business Function">
                  <input name="business_function" defaultValue={ag.business_function || ""} className={inputClass} />
                </Field>
                <Field label="Documented Purpose">
                  <textarea name="purpose" defaultValue={ag.purpose || ""} className={textareaClass} rows={3} />
                </Field>
                <Field label="Description">
                  <textarea name="description" defaultValue={ag.description || ""} className={textareaClass} rows={2} />
                </Field>
                <button disabled={busy} className={buttonClass}>
                  {busy ? "Saving..." : "Save Changes"}
                </button>
              </form>
            ) : (
              <dl className="grid gap-4 sm:grid-cols-2 text-xs">
                <div>
                  <dt className="text-slate-400 font-medium">Public Identifier</dt>
                  <dd className="mt-1 flex items-center gap-1.5 font-mono text-slate-800">
                    {ag.agent_identifier}
                    <button
                      onClick={() => navigator.clipboard.writeText(ag.agent_identifier)}
                      title="Copy ID"
                      className="text-slate-400 hover:text-slate-600"
                    >
                      <Copy size={12} />
                    </button>
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400 font-medium">Created Timestamp</dt>
                  <dd className="mt-1 text-slate-800">{formatDate(ag.created_at, true)}</dd>
                </div>
                <div>
                  <dt className="text-slate-400 font-medium">Primary Owner</dt>
                  <dd className="mt-1 text-slate-800 font-mono">
                    {ag.owner_type}: {ag.owner_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-400 font-medium">Assigned Team</dt>
                  <dd className="mt-1 text-slate-800">{ag.team || "Unassigned"}</dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-slate-400 font-medium">Documented Purpose</dt>
                  <dd className="mt-1 text-slate-700 leading-relaxed">
                    {ag.purpose || "No formal purpose documented. Please update during review."}
                  </dd>
                </div>
              </dl>
            )}
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <h3 className="font-semibold text-slate-950">Governance Posture</h3>
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <span className="text-slate-500">Certification Posture</span>
                <span className="font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded">
                  {ag.certification_status || "UNREVIEWED"}
                </span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <span className="text-slate-500">Certified Until</span>
                <span className="text-slate-800">
                  {ag.certified_until ? formatDate(ag.certified_until) : "Not certified"}
                </span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <span className="text-slate-500">Last Activity</span>
                <span className="text-slate-800">
                  {ag.last_activity_at ? formatDate(ag.last_activity_at, true) : "None recorded"}
                </span>
              </div>
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <span className="text-slate-500">Risk Classification</span>
                <span className="font-semibold text-slate-800">{ag.risk_classification || "LOW"}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. Identity & Keys Tab */}
      {activeTab === "identity" && (
        <div className="space-y-5">
          <SigningKeys agentId={ag.id} />
        </div>
      )}

      {/* 3. Ownership & Team Tab */}
      {activeTab === "owner" && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-slate-950 mb-4">Transfer Agent Ownership</h3>
            {canManage ? (
              <form onSubmit={handleOwnershipTransfer} className="space-y-4 text-xs max-w-xl">
                <Field label="New Owner Identifier (User UUID, Service Account, or Principal)">
                  <input
                    value={transferOwnerId}
                    onChange={(e) => setTransferOwnerId(e.target.value)}
                    placeholder="e.g. 00000000-0000-0000-0000-000000000000"
                    className={inputClass}
                    required
                  />
                </Field>
                <div className="grid grid-cols-2 gap-4">
                  <Field label="Owner Type">
                    <select
                      value={transferOwnerType}
                      onChange={(e) => setTransferOwnerType(e.target.value)}
                      className={inputClass}
                    >
                      <option value="USER">USER</option>
                      <option value="TEAM">TEAM</option>
                      <option value="SERVICE_OWNER">SERVICE_OWNER</option>
                    </select>
                  </Field>
                  <Field label="Team Name">
                    <input
                      value={transferTeam}
                      onChange={(e) => setTransferTeam(e.target.value)}
                      placeholder="e.g. Platform Engineering"
                      className={inputClass}
                    />
                  </Field>
                </div>
                <Field label="Business Rationale for Transfer">
                  <textarea
                    value={transferReason}
                    onChange={(e) => setTransferReason(e.target.value)}
                    placeholder="Document justification for audit trail..."
                    className={textareaClass}
                    required
                    rows={2}
                  />
                </Field>
                <button disabled={busy} className={buttonClass}>
                  {busy ? "Transferring..." : "Execute Ownership Transfer"}
                </button>
              </form>
            ) : (
              <p className="text-xs text-slate-500">Only organization admins or owners can transfer agent ownership.</p>
            )}
          </div>

          {/* Ownership History Table */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-slate-950 mb-3">Ownership Audit Trail</h3>
            {!ownershipHistory.data?.length ? (
              <p className="text-xs text-slate-500">No ownership transfers on record.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b bg-slate-50 uppercase text-slate-500">
                    <tr>
                      <th className="p-3">Date</th>
                      <th className="p-3">Previous Owner</th>
                      <th className="p-3">New Owner</th>
                      <th className="p-3">Reason</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {ownershipHistory.data.map((h) => (
                      <tr key={h.id}>
                        <td className="p-3 text-slate-500">{formatDate(h.changed_at, true)}</td>
                        <td className="p-3 font-mono">
                          {h.old_owner_type}: {h.old_owner_id}
                        </td>
                        <td className="p-3 font-mono font-semibold text-slate-900">
                          {h.new_owner_type}: {h.new_owner_id}
                        </td>
                        <td className="p-3 text-slate-600">{h.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. Purpose & Scope Tab */}
      {activeTab === "purpose" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4 text-xs">
          <h3 className="font-semibold text-slate-950 text-sm">Business Scope & Functional Specification</h3>
          <dl className="grid gap-4 sm:grid-cols-2">
            <div>
              <dt className="text-slate-400 font-medium">Business Function</dt>
              <dd className="mt-1 font-semibold text-slate-800">{ag.business_function || "Unspecified"}</dd>
            </div>
            <div>
              <dt className="text-slate-400 font-medium">Data Classification</dt>
              <dd className="mt-1 font-semibold text-slate-800">{ag.data_classification || "INTERNAL"}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-slate-400 font-medium">Data Access Description</dt>
              <dd className="mt-1 text-slate-700 leading-relaxed">
                {ag.data_access_description || "No sensitive data access declared."}
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-slate-400 font-medium">Expected Tool & API Actions</dt>
              <dd className="mt-1 text-slate-700">
                {ag.expected_actions?.length ? (
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {ag.expected_actions.map((act) => (
                      <span key={act} className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700">
                        {act}
                      </span>
                    ))}
                  </div>
                ) : (
                  "No expected actions specified."
                )}
              </dd>
            </div>
          </dl>
        </div>
      )}

      {/* 5. Classification Tab */}
      {activeTab === "classification" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4 text-xs">
          <h3 className="font-semibold text-slate-950 text-sm">Enterprise Risk & Criticality Posture</h3>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-lg border border-slate-200 p-4">
              <span className="text-slate-400 font-medium">Risk Classification</span>
              <div className="text-lg font-bold text-slate-900 mt-1">{ag.risk_classification || "LOW"}</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-4">
              <span className="text-slate-400 font-medium">Business Criticality</span>
              <div className="text-lg font-bold text-slate-900 mt-1">{ag.business_criticality || "LOW"}</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-4">
              <span className="text-slate-400 font-medium">Data Sensitivity</span>
              <div className="text-lg font-bold text-slate-900 mt-1">{ag.data_classification || "INTERNAL"}</div>
            </div>
          </div>
        </div>
      )}

      {/* 6. Lifecycle & State Machine Tab */}
      {activeTab === "lifecycle" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4 text-xs">
          <h3 className="font-semibold text-slate-950 text-sm">Lifecycle State Controls</h3>
          <p className="text-slate-500">
            Agents progress through formalized enterprise states with separation of duties enforcement.
          </p>
          <div className="flex flex-wrap gap-2 pt-2">
            {canManage && (
              <>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("review_required", "Transitioned to review")}
                  className={secondaryButtonClass}
                >
                  Move to Review Required
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("approved", "Manual promotion approval")}
                  className={secondaryButtonClass}
                >
                  Move to Approved
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("active", "Activated")}
                  className={buttonClass}
                >
                  Move to Active
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("suspended", "Manual suspension")}
                  className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-1.5 font-semibold text-amber-800 hover:bg-amber-100"
                >
                  Emergency Suspend
                </button>
                <button
                  disabled={busy}
                  onClick={() => handleLifecycleTransition("retired", "Decommissioned")}
                  className="rounded-lg border border-rose-300 bg-rose-50 px-3 py-1.5 font-semibold text-rose-800 hover:bg-rose-100"
                >
                  Retire Decommission
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {/* 7. Permissions Tab */}
      {activeTab === "permissions" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-slate-950">Granted Capabilities</h3>
            <Link
              href="/dashboard/permissions/new"
              className="text-xs font-semibold text-[#3157d5] hover:underline"
            >
              + Grant New Permission
            </Link>
          </div>
          {grants.length ? (
            <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
              <table className="w-full min-w-[650px] text-left text-xs">
                <thead className="border-b bg-slate-50 uppercase text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Action · Resource</th>
                    <th className="px-4 py-3">Limit</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Expires</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {grants.map((perm) => (
                    <tr key={perm.id}>
                      <td className="px-4 py-3 font-semibold text-slate-900">
                        {perm.action} · {perm.resource}
                      </td>
                      <td className="px-4 py-3 text-slate-600">
                        {formatMoney(perm.maximum_amount, perm.currency)}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge value={perm.status} />
                      </td>
                      <td className="px-4 py-3 text-slate-500">
                        {formatDate(perm.expires_at, true)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No permissions granted" description="Assign permissions to enable agent operations." />
          )}
        </div>
      )}

      {/* 8-12. Placeholders for other tabs */}
      {activeTab === "credentials" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Verifiable Agent Credentials (ATC/1.0)</h3>
          <p className="text-xs text-slate-500">Cryptographically verifiable credentials issued to this agent.</p>
        </div>
      )}

      {activeTab === "policies" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Policy-as-Code Bindings (APL/1.0)</h3>
          <p className="text-xs text-slate-500">Declarative policies bound to this agent identity.</p>
        </div>
      )}

      {activeTab === "trust" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Cross-Organization Trust Connections</h3>
          <p className="text-xs text-slate-500">External agent authorization channels and bilateral trust policies.</p>
        </div>
      )}

      {activeTab === "delegations" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Agent-to-Agent Delegations</h3>
          <p className="text-xs text-slate-500">Incoming and outgoing delegation chains.</p>
        </div>
      )}

      {activeTab === "gateways" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Enterprise Gateway Deployments</h3>
          <p className="text-xs text-slate-500">Edge gateways and sidecars serving this agent identity.</p>
        </div>
      )}

      {/* 13. Activity Tab */}
      {activeTab === "activity" && (
        <div className="space-y-4">
          <h3 className="font-semibold text-slate-950">Recent Authorization Activity</h3>
          {activity.data?.items.length ? (
            <ActivityTable logs={activity.data.items} agents={[ag]} />
          ) : (
            <EmptyState title="No audit activity yet" description="Authorization requests will appear here." />
          )}
        </div>
      )}

      {/* 14. Security Tab */}
      {activeTab === "security" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Security Events & Alerts</h3>
          <p className="text-xs text-slate-500">Security anomalies and emergency suspension logs.</p>
        </div>
      )}

      {/* 15. Certifications Tab */}
      {activeTab === "certifications" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-slate-950">Access Certification Reviews</h3>
              <p className="text-xs text-slate-500">Periodic governance posture sign-offs and reviews.</p>
            </div>
            {canManage && (
              <button
                disabled={busy}
                onClick={handleTriggerReview}
                className="rounded-lg bg-[#3157d5] px-3 py-1.5 text-xs font-semibold text-white hover:bg-[#2847b3] disabled:opacity-50"
              >
                Trigger Access Review
              </button>
            )}
          </div>
          <div className="rounded-lg bg-slate-50 p-4 text-xs space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-500">Status</span>
              <span className="font-bold text-slate-900">{ag.certification_status || "UNREVIEWED"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Certified Valid Until</span>
              <span className="text-slate-900">{ag.certified_until ? formatDate(ag.certified_until) : "None"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Next Review Due Date</span>
              <span className="text-slate-900">{ag.next_review_due_at ? formatDate(ag.next_review_due_at) : "None"}</span>
            </div>
          </div>
        </div>
      )}

      {/* 16. Relationships Tab */}
      {activeTab === "relationships" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm text-center space-y-3">
          <Network size={32} className="mx-auto text-[#3157d5]" />
          <h3 className="font-semibold text-slate-950">Visual Blast Radius & Dependency Topology</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Inspect caller and target agents, verifiable credentials, and policy bindings.
          </p>
          <Link
            href={`/dashboard/agents/${ag.agent_identifier}/relationships`}
            className="inline-flex items-center gap-2 rounded-lg bg-[#3157d5] px-4 py-2 text-xs font-semibold text-white hover:bg-[#2847b3]"
          >
            Launch Interactive Topology Graph &rarr;
          </Link>
        </div>
      )}

      {/* 17. Audit Tab */}
      {activeTab === "audit" && (
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <h3 className="font-semibold text-slate-950 mb-2">Immutable Governance Audit Log</h3>
          <p className="text-xs text-slate-500">All lifecycle transitions, ownership changes, and reviews are permanently preserved.</p>
        </div>
      )}
    </div>
  );
}
