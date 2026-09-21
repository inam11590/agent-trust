"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  ArrowLeft,
  Calendar,
  ExternalLink,
  Eye,
  Filter,
  Layers,
  Radio,
  RotateCw,
  Search,
  Shield,
  Tag,
} from "lucide-react";

import { PageHeader, buttonClass, inputClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

type SecurityEventItem = {
  id: string;
  event_id: string;
  event_type: string;
  category: string;
  severity: string;
  description: string | null;
  actor_type: string | null;
  actor_id: string | null;
  agent_id: string | null;
  gateway_id: string | null;
  decision: string | null;
  risk_level: string | null;
  request_id: string | null;
  trace_id: string | null;
  correlation_id: string | null;
  details: Record<string, unknown>;
  created_at: string;
};

type EventsResponse = {
  items: SecurityEventItem[];
  total: number;
  next_cursor: string | null;
};

type RelatedEventsResponse = {
  primary_event_id: string;
  related_events: SecurityEventItem[];
  total_found: number;
};

export default function SecurityEventsExplorerPage() {
  const { organization } = useAuth();
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [total, setTotal] = useState(0);

  // Filters
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [decision, setDecision] = useState("");
  const [correlationId, setCorrelationId] = useState("");
  const [eventType, setEventType] = useState("");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<SecurityEventItem[]>([]);
  const [loadingRelated, setLoadingRelated] = useState(false);

  async function loadEvents() {
    setLoading(true);
    setError("");
    try {
      const q = new URLSearchParams({ limit: "50" });
      if (organization?.id) q.set("organization_id", organization.id);
      if (category) q.set("category", category);
      if (severity) q.set("severity", severity);
      if (decision) q.set("decision", decision);
      if (correlationId) q.set("correlation_id", correlationId);
      if (eventType) q.set("event_type", eventType);

      const res = await apiRequest<EventsResponse>(`/security/events?${q}`);
      setEvents(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load events.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadEvents();
  }, [organization, category, severity, decision, correlationId, eventType]);

  async function selectEvent(evt: SecurityEventItem) {
    setSelectedEvent(evt);
    setLoadingRelated(true);
    try {
      const q = organization?.id ? `?organization_id=${organization.id}` : "";
      const rel = await apiRequest<RelatedEventsResponse>(
        `/security/events/${evt.event_id || evt.id}/related${q}`
      );
      setRelatedEvents(rel.related_events);
    } catch {
      setRelatedEvents([]);
    } finally {
      setLoadingRelated(false);
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

  function getDecisionBadge(dec: string | null) {
    if (!dec) return <span className="text-slate-400 text-xs">-</span>;
    if (dec.toUpperCase() === "ALLOWED") {
      return <span className="rounded bg-emerald-100 px-1.5 py-0.5 text-xs font-bold text-emerald-800">ALLOWED</span>;
    }
    return <span className="rounded bg-rose-100 px-1.5 py-0.5 text-xs font-bold text-rose-800">DENIED</span>;
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
            title="Security Event Explorer"
            description="Tenant-isolated, append-only security logs with correlation and investigation timelines."
          />
        </div>
        <button
          onClick={() => loadEvents()}
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

      {/* Filter Bar */}
      <div className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-2 lg:grid-cols-5">
        <select
          aria-label="Category filter"
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700"
        >
          <option value="">All Categories</option>
          <option value="AUTHORIZATION">AUTHORIZATION</option>
          <option value="AUTHENTICATION">AUTHENTICATION</option>
          <option value="REPLAY">REPLAY</option>
          <option value="CREDENTIAL">CREDENTIAL</option>
          <option value="TRUST">TRUST</option>
          <option value="GATEWAY">GATEWAY</option>
          <option value="ADMIN">ADMIN</option>
          <option value="SUPPLY_CHAIN">SUPPLY_CHAIN</option>
        </select>

        <select
          aria-label="Severity filter"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="INFO">Info</option>
        </select>

        <select
          aria-label="Decision filter"
          value={decision}
          onChange={(e) => setDecision(e.target.value)}
          className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700"
        >
          <option value="">All Decisions</option>
          <option value="ALLOWED">Allowed</option>
          <option value="DENIED">Denied</option>
        </select>

        <input
          value={correlationId}
          onChange={(e) => setCorrelationId(e.target.value)}
          placeholder="Filter by Correlation ID..."
          className="rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700"
        />

        <input
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          placeholder="Filter by Event Type..."
          className="rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700"
        />
      </div>

      {/* Main Events Table + Details Split */}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm lg:col-span-2">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-500">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Event Type</th>
                <th className="p-3">Category</th>
                <th className="p-3">Decision</th>
                <th className="p-3">Correlation</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr
                  key={e.id}
                  onClick={() => selectEvent(e)}
                  className={`cursor-pointer border-t border-slate-100 transition hover:bg-slate-50 ${
                    selectedEvent?.event_id === e.event_id ? "bg-blue-50/50" : ""
                  }`}
                >
                  <td className="p-3 text-xs text-slate-500 whitespace-nowrap">{formatDate(e.created_at)}</td>
                  <td className="p-3">{getSeverityBadge(e.severity)}</td>
                  <td className="p-3">
                    <p className="font-semibold text-slate-900">{e.event_type.replaceAll("_", " ")}</p>
                    <p className="text-xs text-slate-400 font-mono">{e.event_id}</p>
                  </td>
                  <td className="p-3 text-xs font-semibold text-slate-600">{e.category}</td>
                  <td className="p-3">{getDecisionBadge(e.decision)}</td>
                  <td className="p-3">
                    {e.correlation_id ? (
                      <button
                        onClick={(evt) => {
                          evt.stopPropagation();
                          setCorrelationId(e.correlation_id ?? "");
                        }}
                        className="rounded bg-slate-100 px-1.5 py-0.5 text-xs font-mono text-slate-700 hover:bg-slate-200"
                        title="Click to filter by correlation ID"
                      >
                        {e.correlation_id.slice(0, 14)}...
                      </button>
                    ) : (
                      <span className="text-slate-400 text-xs">-</span>
                    )}
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-6 text-center text-slate-500">
                    No security events found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Event Details & Related Timeline */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <h3 className="font-bold text-slate-900">Event & Investigation Timeline</h3>
          {selectedEvent ? (
            <div className="space-y-4 text-sm">
              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Event ID</span>
                <p className="font-mono text-xs font-bold text-slate-800">{selectedEvent.event_id || selectedEvent.id}</p>
              </div>

              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Type & Category</span>
                <p className="font-medium text-slate-800">{selectedEvent.event_type} ({selectedEvent.category})</p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-xs font-semibold text-slate-400 uppercase">Severity</span>
                  <div className="mt-0.5">{getSeverityBadge(selectedEvent.severity)}</div>
                </div>
                <div>
                  <span className="text-xs font-semibold text-slate-400 uppercase">Decision</span>
                  <div className="mt-0.5">{getDecisionBadge(selectedEvent.decision)}</div>
                </div>
              </div>

              {selectedEvent.agent_id && (
                <div>
                  <span className="text-xs font-semibold text-slate-400 uppercase">Agent Reference</span>
                  <Link
                    href={`/dashboard/security/agents/${selectedEvent.agent_id}`}
                    className="flex items-center gap-1 font-mono text-xs text-blue-600 hover:underline"
                  >
                    {selectedEvent.agent_id} <ExternalLink size={11} />
                  </Link>
                </div>
              )}

              {selectedEvent.gateway_id && (
                <div>
                  <span className="text-xs font-semibold text-slate-400 uppercase">Gateway Reference</span>
                  <Link
                    href={`/dashboard/security/gateways/${selectedEvent.gateway_id}`}
                    className="flex items-center gap-1 font-mono text-xs text-blue-600 hover:underline"
                  >
                    {selectedEvent.gateway_id} <ExternalLink size={11} />
                  </Link>
                </div>
              )}

              {selectedEvent.correlation_id && (
                <div>
                  <span className="text-xs font-semibold text-slate-400 uppercase">Correlation ID</span>
                  <p className="font-mono text-xs text-slate-700 break-all">{selectedEvent.correlation_id}</p>
                </div>
              )}

              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase">Safe Metadata (Redacted)</span>
                <pre className="mt-1 max-h-36 overflow-auto rounded bg-slate-50 p-2 text-xs font-mono text-slate-700 border border-slate-200">
                  {JSON.stringify(selectedEvent.details, null, 2)}
                </pre>
              </div>

              {/* Related Events Timeline */}
              <div className="pt-3 border-t border-slate-100">
                <span className="text-xs font-bold text-slate-700 uppercase">
                  Correlated Event Chain ({relatedEvents.length})
                </span>
                {loadingRelated ? (
                  <p className="text-xs text-slate-400 mt-2">Loading related events...</p>
                ) : relatedEvents.length > 0 ? (
                  <div className="mt-2 space-y-2 max-h-48 overflow-y-auto">
                    {relatedEvents.map((rel) => (
                      <div
                        key={rel.id}
                        onClick={() => setSelectedEvent(rel)}
                        className="cursor-pointer rounded border border-slate-100 bg-slate-50 p-2 text-xs hover:border-blue-200 transition"
                      >
                        <div className="flex justify-between font-medium text-slate-800">
                          <span>{rel.event_type}</span>
                          <span>{getDecisionBadge(rel.decision)}</span>
                        </div>
                        <p className="text-[10px] text-slate-500">{formatDate(rel.created_at)}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-400 mt-2">No other events linked in this time window.</p>
                )}
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500 py-8 text-center">
              Click an event from the table to inspect metadata and correlated lifecycle events.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
