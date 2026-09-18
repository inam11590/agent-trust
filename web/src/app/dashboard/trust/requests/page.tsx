"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  CheckCircle2,
  Clock,
  ExternalLink,
  Filter,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import type { CrossOrganizationRequest } from "@/types";

export default function CrossOrgRequestsPage() {
  const { organization, role = "owner" } = useAuth();
  const canDecide = role === "owner" || role === "admin";

  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const requestsQuery = useApiQuery<CrossOrganizationRequest[]>("/cross-org/requests");

  const [actionLoading, setActionLoading] = useState("");
  const [feedbackMessage, setFeedbackMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");

  if (requestsQuery.loading) {
    return <LoadingState label="Loading cross-organization requests" />;
  }

  if (requestsQuery.error) {
    return (
      <ErrorState
        message={requestsQuery.error ?? "Unable to load cross-organization authorization requests."}
        retry={() => requestsQuery.reload()}
      />
    );
  }

  const requests = requestsQuery.data ?? [];
  const currentOrgId = organization?.id;

  const filteredRequests = requests.filter((r) => {
    if (statusFilter === "ALL") return true;
    return r.status === statusFilter;
  });

  async function handleDecision(requestId: string, decision: "APPROVED" | "REJECTED") {
    let reason: string | null = "";
    if (decision === "REJECTED") {
      reason = window.prompt("Reason for rejection:", "Administrative rejection");
      if (reason === null) return;
    }

    setActionLoading(requestId);
    setFeedbackMessage("");
    setErrorMessage("");
    try {
      await apiRequest(`/cross-org/requests/${requestId}/approve`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          reason: reason || undefined,
        }),
      });
      setFeedbackMessage(`Request ${requestId} successfully marked ${decision}.`);
      requestsQuery.reload();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : `Failed to record ${decision} decision.`);
    } finally {
      setActionLoading("");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Link href="/dashboard/trust" className="hover:text-white flex items-center gap-1">
              <ArrowLeft size={12} /> Back to Partner Trust
            </Link>
          </div>
          <PageHeader
            title="Cross-Organization Authorization Queue"
            description="Review and decide high-value or multi-party authorization requests initiated between independent organizations."
          />
        </div>

        {/* Filter */}
        <div className="flex items-center gap-2 rounded-lg border border-white/10 bg-slate-900/50 p-1 text-xs">
          <button
            onClick={() => setStatusFilter("ALL")}
            className={`rounded px-3 py-1.5 font-medium transition ${
              statusFilter === "ALL" ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            All ({requests.length})
          </button>
          <button
            onClick={() => setStatusFilter("PENDING")}
            className={`rounded px-3 py-1.5 font-medium transition ${
              statusFilter === "PENDING" ? "bg-amber-500/20 text-amber-300" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Pending ({requests.filter((r) => r.status === "PENDING").length})
          </button>
          <button
            onClick={() => setStatusFilter("APPROVED")}
            className={`rounded px-3 py-1.5 font-medium transition ${
              statusFilter === "APPROVED" ? "bg-emerald-500/20 text-emerald-300" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Approved ({requests.filter((r) => r.status === "APPROVED").length})
          </button>
          <button
            onClick={() => setStatusFilter("REJECTED")}
            className={`rounded px-3 py-1.5 font-medium transition ${
              statusFilter === "REJECTED" ? "bg-rose-500/20 text-rose-300" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Rejected ({requests.filter((r) => r.status === "REJECTED").length})
          </button>
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

      {filteredRequests.length === 0 ? (
        <EmptyState
          title="No authorization requests found"
          description="Cross-organization requests submitted by connected external agents will appear here for evaluation."
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-white/10 bg-slate-900/50">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/10 bg-white/[0.02] text-xs font-semibold uppercase text-slate-400">
              <tr>
                <th className="px-4 py-3">Request ID</th>
                <th className="px-4 py-3">Action & Resource</th>
                <th className="px-4 py-3">Amount</th>
                <th className="px-4 py-3">Direction</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Date</th>
                <th className="px-4 py-3 text-right">Decision</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-slate-300">
              {filteredRequests.map((r) => {
                const isOutbound = r.source_organization_id === currentOrgId;
                const pendingMyOrg =
                  r.status === "PENDING" &&
                  (r.approvals || []).some(
                    (a) => a.organization_id === currentOrgId && a.status === "PENDING"
                  );

                return (
                  <tr key={r.id} className="hover:bg-white/[0.02]">
                    <td className="px-4 py-3 font-mono text-xs text-white">
                      {r.request_id}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-medium text-slate-200">{r.action}</div>
                      <div className="text-xs text-slate-400">{r.resource}</div>
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200">
                      {r.amount !== null ? `${r.currency || "USD"} ${r.amount}` : "—"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${
                          isOutbound
                            ? "bg-sky-500/10 text-sky-400"
                            : "bg-purple-500/10 text-purple-400"
                        }`}
                      >
                        {isOutbound ? "Outbound" : "Inbound"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium ${
                          r.status === "APPROVED"
                            ? "bg-emerald-500/10 text-emerald-400"
                            : r.status === "REJECTED"
                            ? "bg-rose-500/10 text-rose-400"
                            : "bg-amber-500/10 text-amber-400"
                        }`}
                      >
                        {r.status === "APPROVED" && <ShieldCheck size={12} />}
                        {r.status === "REJECTED" && <XCircle size={12} />}
                        {r.status === "PENDING" && <Clock size={12} />}
                        {r.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {r.status === "PENDING" && canDecide ? (
                        <div className="flex items-center justify-end gap-2">
                          <button
                            disabled={actionLoading === r.request_id}
                            onClick={() => handleDecision(r.request_id, "APPROVED")}
                            className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-50"
                          >
                            <CheckCircle2 size={13} />
                            Approve
                          </button>
                          <button
                            disabled={actionLoading === r.request_id}
                            onClick={() => handleDecision(r.request_id, "REJECTED")}
                            className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-2.5 py-1 text-xs font-medium text-rose-400 transition hover:bg-rose-500/20 disabled:opacity-50"
                          >
                            <XCircle size={13} />
                            Reject
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs text-slate-500">
                          {r.decision_reason || "Completed"}
                        </span>
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
  );
}
