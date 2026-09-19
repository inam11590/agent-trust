"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Clock, Eye, Layers, Radio, RefreshCw, Shield, Waypoints } from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import { EmptyState, LoadingState, PageHeader, StatusBadge } from "@/components/ui";
import { ATPMessageRecord } from "@/types";

export default function GatewayMessagesFeedPage() {
  const [messages, setMessages] = useState<ATPMessageRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedMessage, setSelectedMessage] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>("");

  const fetchMessages = async () => {
    setLoading(true);
    try {
      const query = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : "";
      const data = await apiRequest<ATPMessageRecord[]>(`/atp/messages${query}`);
      setMessages(data || []);
    } catch (err) {
      console.error("Failed to load ATP messages", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMessages();
  }, [statusFilter]);

  const openDetails = async (msgId: string) => {
    setDetailLoading(true);
    try {
      const data = await apiRequest<any>(`/atp/messages/${msgId}`);
      setSelectedMessage(data);
    } catch (err) {
      console.error("Failed to fetch message details", err);
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div className="space-y-8 p-6 lg:p-8">
      <div className="flex items-center gap-2 text-sm text-slate-500">
        <Link href="/dashboard/gateway" className="inline-flex items-center gap-1 hover:text-slate-800">
          <ArrowLeft size={14} /> Protocol Gateway
        </Link>
        <span>/</span>
        <span className="font-semibold text-slate-900">Messages Feed</span>
      </div>

      <PageHeader
        title="Protocol Message Feed & Staging"
        description="Authoritative audit stream of ATP/1.0 messages routed, staged for approval, or dispatched through the Gateway."
        action={
          <div className="flex items-center gap-3">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 shadow-xs"
            >
              <option value="">All Statuses</option>
              <option value="DELIVERED">Delivered</option>
              <option value="PENDING_APPROVAL">Pending Approval</option>
              <option value="PENDING">Pending</option>
              <option value="FAILED">Failed</option>
            </select>
            <button
              onClick={fetchMessages}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 shadow-xs hover:bg-slate-50"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
          </div>
        }
      />

      {loading ? (
        <LoadingState label="Loading ATP messages" />
      ) : messages.length === 0 ? (
        <EmptyState
          title="No ATP messages found"
          description="Messages routed between AI agents via the AgentTrust Gateway will appear in this live stream."
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs">
          <table className="w-full text-left text-sm text-slate-600">
            <thead className="border-b border-slate-200 bg-slate-50 text-xs font-semibold uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-3">Message ID</th>
                <th className="px-5 py-3">Capability</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Attestation</th>
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-normal">
              {messages.map((msg) => (
                <tr key={msg.id} className="hover:bg-slate-50/80 transition">
                  <td className="px-5 py-3.5 font-mono text-xs font-medium text-slate-900">
                    {msg.message_id}
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs text-blue-600 font-medium">
                    {msg.capability}
                  </td>
                  <td className="px-5 py-3.5">
                    <StatusBadge value={msg.status} />
                  </td>
                  <td className="px-5 py-3.5 font-mono text-xs text-slate-500">
                    {msg.attestation_id ? `${msg.attestation_id.slice(0, 16)}…` : "—"}
                  </td>
                  <td className="px-5 py-3.5 text-xs text-slate-500">
                    {new Date(msg.created_at).toLocaleString()}
                  </td>
                  <td className="px-5 py-3.5 text-right">
                    <button
                      onClick={() => openDetails(msg.message_id)}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800"
                    >
                      <Eye size={13} /> View Trace
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Message Trace Modal / Drawer */}
      {selectedMessage && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-4 backdrop-blur-xs">
          <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl bg-white p-6 shadow-2xl border border-slate-200">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div>
                <h3 className="font-semibold text-slate-900">ATP Message Audit Record</h3>
                <p className="font-mono text-xs text-slate-500">{selectedMessage.record?.message_id}</p>
              </div>
              <button
                onClick={() => setSelectedMessage(null)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-3 rounded-lg bg-slate-50 p-3 text-xs">
                <div>
                  <span className="font-semibold text-slate-500">Status</span>
                  <div className="mt-0.5">
                    <StatusBadge value={selectedMessage.record?.status} />
                  </div>
                </div>
                <div>
                  <span className="font-semibold text-slate-500">Capability</span>
                  <p className="mt-0.5 font-mono font-medium text-slate-900">{selectedMessage.record?.capability}</p>
                </div>
                <div>
                  <span className="font-semibold text-slate-500">Protocol Version</span>
                  <p className="mt-0.5 font-mono text-slate-700">ATP/{selectedMessage.record?.atp_version}</p>
                </div>
                <div>
                  <span className="font-semibold text-slate-500">Created At</span>
                  <p className="mt-0.5 text-slate-700">{new Date(selectedMessage.record?.created_at).toLocaleString()}</p>
                </div>
              </div>

              {selectedMessage.record?.decision_reason && (
                <div className="rounded-lg bg-amber-50/70 p-3 border border-amber-200/60 text-xs">
                  <span className="font-semibold text-amber-800">Gateway Decision / Hold Reason</span>
                  <p className="mt-1 text-amber-900">{selectedMessage.record.decision_reason}</p>
                </div>
              )}

              {selectedMessage.record?.attestation_id && (
                <div>
                  <span className="text-xs font-semibold text-slate-600">Gateway Attestation Header Token</span>
                  <p className="mt-1 rounded bg-slate-100 p-2 font-mono text-[11px] text-slate-800 break-all border border-slate-200">
                    {selectedMessage.record.attestation_id}
                  </p>
                </div>
              )}

              {/* Delivery Attempts */}
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                  Delivery Attempts ({selectedMessage.deliveries?.length || 0})
                </h4>
                {selectedMessage.deliveries && selectedMessage.deliveries.length > 0 ? (
                  <div className="space-y-2">
                    {selectedMessage.deliveries.map((del: any, idx: number) => (
                      <div key={idx} className="rounded-lg border border-slate-200 p-3 text-xs bg-white">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-800">Attempt #{del.attempt_count}</span>
                          <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-700">
                            HTTP {del.http_status ?? "—"}
                          </span>
                        </div>
                        <p className="mt-1 text-slate-600">
                          Status: <span className="font-semibold">{del.status}</span>
                        </p>
                        {del.error_message && (
                          <p className="mt-1 text-red-600 font-mono text-[11px]">{del.error_message}</p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No delivery attempts recorded.</p>
                )}
              </div>
            </div>

            <div className="mt-6 flex justify-end border-t border-slate-200 pt-3">
              <button
                onClick={() => setSelectedMessage(null)}
                className="rounded-lg bg-slate-100 px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
