"use client";

import { useState } from "react";
import Link from "next/link";
import {
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  Eye,
  FileText,
  RefreshCw,
  XCircle,
} from "lucide-react";

import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";
import type { AgentCertification } from "@/types";

export default function CertificationReviewsQueuePage() {
  const { role = "owner" } = useAuth();
  const canManage = role === "owner" || role === "admin";
  const query = useApiQuery<AgentCertification[]>("/governance/certifications");

  const [selectedCert, setSelectedCert] = useState<AgentCertification | null>(null);
  const [decisionNotes, setDecisionNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  if (query.loading) return <LoadingState label="Loading review queue" />;
  if (query.error) return <ErrorState message={query.error} retry={query.reload} />;

  const certs = query.data || [];

  async function handleDecision(certId: string, decision: "APPROVED" | "REJECTED") {
    setBusy(true);
    setMessage("");
    setErrorMsg("");
    try {
      await apiRequest(`/governance/certifications/${certId}/decide`, {
        method: "POST",
        body: JSON.stringify({
          decision,
          notes: decisionNotes || undefined,
        }),
      });
      setMessage(`Review ${certId} was successfully ${decision}.`);
      setSelectedCert(null);
      setDecisionNotes("");
      query.reload();
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to submit decision.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-7">
      <div className="flex items-center gap-2 text-sm text-slate-500">
        <Link href="/dashboard/governance" className="hover:text-slate-800">
          Governance
        </Link>
        <ChevronRight size={14} />
        <span className="font-semibold text-slate-900">Access Review Queue</span>
      </div>

      <PageHeader
        title="Agent Certification & Access Reviews"
        description="Formal sign-off queue for agent capabilities, permissions, and security posture."
        action={
          <button
            onClick={() => query.reload()}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
          >
            <RefreshCw size={14} /> Refresh Queue
          </button>
        }
      />

      {message && (
        <div className="flex items-center gap-2 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800">
          <CheckCircle2 size={16} /> {message}
        </div>
      )}
      {errorMsg && (
        <div className="flex items-center gap-2 rounded-lg bg-rose-50 p-3 text-sm text-rose-800">
          <AlertCircle size={16} /> {errorMsg}
        </div>
      )}

      {!certs.length ? (
        <EmptyState
          title="Review queue is empty"
          description="There are no pending or completed certification reviews for your organization."
        />
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="border-b bg-slate-50 uppercase text-slate-500">
              <tr>
                <th className="p-3">Review ID</th>
                <th className="p-3">Agent ID</th>
                <th className="p-3">Status</th>
                <th className="p-3">Requested Date</th>
                <th className="p-3">Due Date</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {certs.map((cert) => {
                const isPending = cert.status === "PENDING";
                const badgeColor =
                  cert.status === "APPROVED"
                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                    : cert.status === "REJECTED"
                    ? "bg-rose-50 text-rose-700 border-rose-200"
                    : "bg-amber-50 text-amber-700 border-amber-200";

                return (
                  <tr key={cert.id} className="hover:bg-slate-50">
                    <td className="p-3 font-mono font-semibold text-slate-900">{cert.certification_id}</td>
                    <td className="p-3 font-mono text-slate-600">{cert.agent_id}</td>
                    <td className="p-3">
                      <span className={`inline-flex rounded border px-2 py-0.5 text-[10px] font-semibold ${badgeColor}`}>
                        {cert.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-500">{formatDate(cert.requested_at)}</td>
                    <td className="p-3 text-slate-500">{cert.due_at ? formatDate(cert.due_at) : "No due date"}</td>
                    <td className="p-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setSelectedCert(cert)}
                          className="inline-flex items-center gap-1 rounded bg-slate-100 px-2.5 py-1 font-medium text-slate-700 hover:bg-slate-200"
                        >
                          <Eye size={12} /> Inspect Snapshot
                        </button>
                        {isPending && canManage && (
                          <>
                            <button
                              disabled={busy}
                              onClick={() => handleDecision(cert.certification_id, "APPROVED")}
                              className="rounded bg-emerald-600 px-2.5 py-1 font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                            >
                              Approve
                            </button>
                            <button
                              disabled={busy}
                              onClick={() => handleDecision(cert.certification_id, "REJECTED")}
                              className="rounded bg-rose-600 px-2.5 py-1 font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
                            >
                              Reject
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Snapshot Modal */}
      {selectedCert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="max-h-[85vh] w-full max-w-2xl overflow-y-auto rounded-xl bg-white p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b pb-3">
              <h3 className="text-base font-semibold text-slate-900">
                Posture Snapshot: {selectedCert.certification_id}
              </h3>
              <button
                onClick={() => setSelectedCert(null)}
                className="rounded p-1 text-slate-400 hover:text-slate-600"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="rounded-lg bg-slate-50 p-3">
                <span className="font-semibold text-slate-700">Snapshot JSON:</span>
                <pre className="mt-2 max-h-60 overflow-x-auto rounded bg-slate-900 p-3 font-mono text-[11px] text-slate-100">
                  {JSON.stringify(selectedCert.snapshot_reference, null, 2)}
                </pre>
              </div>

              {selectedCert.status === "PENDING" && canManage && (
                <div className="space-y-3 pt-2">
                  <label className="block font-medium text-slate-700">Review Decision Notes:</label>
                  <textarea
                    value={decisionNotes}
                    onChange={(e) => setDecisionNotes(e.target.value)}
                    placeholder="Document justification for approval or rejection..."
                    className="w-full rounded-lg border border-slate-200 p-2 text-xs outline-none focus:border-[#3157d5]"
                    rows={2}
                  />
                  <div className="flex justify-end gap-2">
                    <button
                      disabled={busy}
                      onClick={() => handleDecision(selectedCert.certification_id, "REJECTED")}
                      className="rounded-lg bg-rose-600 px-4 py-2 font-semibold text-white hover:bg-rose-700 disabled:opacity-50"
                    >
                      Reject Access
                    </button>
                    <button
                      disabled={busy}
                      onClick={() => handleDecision(selectedCert.certification_id, "APPROVED")}
                      className="rounded-lg bg-emerald-600 px-4 py-2 font-semibold text-white hover:bg-emerald-700 disabled:opacity-50"
                    >
                      Certify & Approve
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
