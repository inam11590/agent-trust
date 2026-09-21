"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock,
  ExternalLink,
  Filter,
  Info,
  RotateCw,
  Search,
  ShieldAlert,
} from "lucide-react";

import { PageHeader, buttonClass, inputClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

type Alert = {
  id: string;
  alert_id: string;
  organization_id: string;
  rule_id: string;
  fingerprint: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  first_seen_at: string;
  last_seen_at: string;
  event_count: number;
  assigned_to: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_note: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

type AlertResponse = {
  items: Alert[];
  total: number;
};

export default function SecurityAlertsPage() {
  const { organization } = useAuth();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [resolveNote, setResolveNote] = useState("");
  const [actionLoading, setActionLoading] = useState(false);

  async function loadAlerts() {
    setLoading(true);
    setError("");
    try {
      const q = new URLSearchParams();
      if (organization?.id) q.set("organization_id", organization.id);
      if (statusFilter) q.set("status", statusFilter);
      if (severityFilter) q.set("severity", severityFilter);
      const res = await apiRequest<AlertResponse>(`/security/alerts?${q}`);
      setAlerts(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();
  }, [organization, statusFilter, severityFilter]);

  async function handleAcknowledge(alertId: string) {
    setActionLoading(true);
    try {
      const q = organization?.id ? `?organization_id=${organization.id}` : "";
      const updated = await apiRequest<Alert>(`/security/alerts/${alertId}/acknowledge${q}`, {
        method: "POST",
      });
      setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? updated : a)));
      if (selectedAlert?.alert_id === alertId) setSelectedAlert(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to acknowledge alert.");
    } finally {
      setActionLoading(false);
    }
  }

  async function handleResolve(alertId: string) {
    setActionLoading(true);
    try {
      const q = organization?.id ? `?organization_id=${organization.id}` : "";
      const updated = await apiRequest<Alert>(`/security/alerts/${alertId}/resolve${q}`, {
        method: "POST",
        body: JSON.stringify({ resolution_note: resolveNote || "Resolved by analyst." }),
      });
      setAlerts((prev) => prev.map((a) => (a.alert_id === alertId ? updated : a)));
      if (selectedAlert?.alert_id === alertId) setSelectedAlert(updated);
      setResolveNote("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to resolve alert.");
    } finally {
      setActionLoading(false);
    }
  }

  function getSeverityBadge(sev: string) {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return <span className="rounded-full bg-rose-100 px-2 py-0.5 text-xs font-bold text-rose-800">CRITICAL</span>;
      case "HIGH":
        return <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-bold text-amber-800">HIGH</span>;
      case "MEDIUM":
        return <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-bold text-blue-800">MEDIUM</span>;
      default:
        return <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-bold text-slate-700">{sev}</span>;
    }
  }

  function getStatusBadge(st: string) {
    switch (st.toUpperCase()) {
      case "OPEN":
        return <span className="rounded-full bg-red-50 border border-red-200 px-2 py-0.5 text-xs font-semibold text-red-700">OPEN</span>;
      case "ACKNOWLEDGED":
        return <span className="rounded-full bg-amber-50 border border-amber-200 px-2 py-0.5 text-xs font-semibold text-amber-700">ACKNOWLEDGED</span>;
      case "RESOLVED":
        return <span className="rounded-full bg-emerald-50 border border-emerald-200 px-2 py-0.5 text-xs font-semibold text-emerald-700">RESOLVED</span>;
      default:
        return <span className="rounded-full bg-slate-50 border border-slate-200 px-2 py-0.5 text-xs font-semibold text-slate-700">{st}</span>;
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <Link href="/dashboard/security" className="text-xs font-medium text-slate-500 hover:text-slate-800 flex items-center gap-1">
              <ArrowLeft size={12} /> Back to Security Center
            </Link>
          </div>
          <PageHeader
            title="Threat Detection Alerts"
            description="Triage, investigate, and resolve deterministic AI agent threat alerts."
          />
        </div>
        <button
          onClick={() => loadAlerts()}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
        >
          <RotateCw size={15} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <select
          aria-label="Status filter"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="RESOLVED">Resolved</option>
        </select>

        <select
          aria-label="Severity filter"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <span className="self-center text-xs text-slate-500">{total} alerts matching</span>
      </div>

      {/* Alert Table */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm lg:col-span-2">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-500">
              <tr>
                <th className="p-3">Severity</th>
                <th className="p-3">Alert</th>
                <th className="p-3">Events</th>
                <th className="p-3">Status</th>
                <th className="p-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => setSelectedAlert(item)}
                  className={`cursor-pointer border-t border-slate-100 transition hover:bg-slate-50 ${
                    selectedAlert?.alert_id === item.alert_id ? "bg-blue-50/50" : ""
                  }`}
                >
                  <td className="p-3">{getSeverityBadge(item.severity)}</td>
                  <td className="p-3">
                    <p className="font-semibold text-slate-900">{item.title}</p>
                    <p className="text-xs text-slate-500 line-clamp-1">{item.description}</p>
                  </td>
                  <td className="p-3">
                    <span className="rounded bg-slate-100 px-2 py-0.5 text-xs font-mono font-bold text-slate-800">
                      {item.event_count}
                    </span>
                  </td>
                  <td className="p-3">{getStatusBadge(item.status)}</td>
                  <td className="p-3 text-xs text-slate-500">{formatDate(item.last_seen_at)}</td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-6 text-center text-slate-500">
                    No alerts match the selected criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Alert Details Drawer */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <h3 className="font-bold text-slate-900">Alert Triage & Details</h3>
          {selectedAlert ? (
            <div className="space-y-4 text-sm">
              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Alert ID</span>
                <p className="font-mono text-xs font-bold text-slate-700">{selectedAlert.alert_id}</p>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Rule ID</span>
                <p className="font-mono text-xs text-slate-700">{selectedAlert.rule_id}</p>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Status & Severity</span>
                <div className="mt-1 flex items-center gap-2">
                  {getStatusBadge(selectedAlert.status)}
                  {getSeverityBadge(selectedAlert.severity)}
                </div>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Description</span>
                <p className="mt-1 text-slate-700">{selectedAlert.description}</p>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">First Seen / Last Seen</span>
                <p className="text-xs text-slate-600">First: {formatDate(selectedAlert.first_seen_at)}</p>
                <p className="text-xs text-slate-600">Last: {formatDate(selectedAlert.last_seen_at)}</p>
              </div>

              {selectedAlert.resolution_note && (
                <div className="rounded-lg bg-emerald-50 p-3 border border-emerald-200">
                  <span className="text-xs font-bold text-emerald-800">Resolution Note:</span>
                  <p className="text-xs text-emerald-900 mt-1">{selectedAlert.resolution_note}</p>
                </div>
              )}

              {/* Actions */}
              <div className="pt-3 border-t border-slate-100 space-y-3">
                {selectedAlert.status === "OPEN" && (
                  <button
                    onClick={() => handleAcknowledge(selectedAlert.alert_id)}
                    disabled={actionLoading}
                    className="w-full rounded-lg bg-amber-600 py-2 text-xs font-bold text-white shadow-sm hover:bg-amber-700 disabled:opacity-50"
                  >
                    Acknowledge Alert
                  </button>
                )}

                {selectedAlert.status !== "RESOLVED" && (
                  <div className="space-y-2">
                    <input
                      value={resolveNote}
                      onChange={(e) => setResolveNote(e.target.value)}
                      placeholder="Resolution note (e.g. key rotated)..."
                      className="w-full rounded-lg border border-slate-200 p-2 text-xs"
                    />
                    <button
                      onClick={() => handleResolve(selectedAlert.alert_id)}
                      disabled={actionLoading}
                      className="w-full rounded-lg bg-emerald-600 py-2 text-xs font-bold text-white shadow-sm hover:bg-emerald-700 disabled:opacity-50"
                    >
                      Resolve Alert
                    </button>
                  </div>
                )}

                <Link
                  href={`/dashboard/security/events?correlation_id=${selectedAlert.fingerprint}`}
                  className="flex items-center justify-center gap-1.5 text-xs text-blue-600 font-semibold hover:underline pt-2"
                >
                  Explore Correlated Events <ExternalLink size={13} />
                </Link>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500 py-8 text-center">
              Select an alert from the table to inspect details, timeline, and actions.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
