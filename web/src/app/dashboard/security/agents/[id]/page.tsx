"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { ArrowLeft, Bot, CheckCircle2, RotateCw, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";

import { PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

type AgentProfile = {
  agent_id: string;
  name: string;
  status: string;
  total_recent_events: number;
  allowed_count: number;
  denied_count: number;
  deny_rate: number;
  recent_alerts: {
    alert_id: string;
    title: string;
    severity: string;
    status: string;
    first_seen_at: string;
  }[];
  recent_events: {
    event_id: string;
    event_type: string;
    severity: string;
    decision: string | null;
    created_at: string;
  }[];
};

export default function AgentSecurityProfilePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { organization } = useAuth();
  const [profile, setProfile] = useState<AgentProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadProfile() {
    setLoading(true);
    setError("");
    try {
      const q = organization?.id ? `?organization_id=${organization.id}` : "";
      const data = await apiRequest<AgentProfile>(`/security/agents/${id}/profile${q}`);
      setProfile(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load agent profile.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProfile();
  }, [id, organization]);

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
            title={profile ? `Agent Security Profile: ${profile.name}` : "Agent Security Profile"}
            description={`Behavioral signals, risk assessment, and decision history for Agent ID: ${id}`}
          />
        </div>
        <button
          onClick={() => loadProfile()}
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

      {profile && (
        <>
          {/* Posture Overview */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Agent Status</p>
              <p className="mt-2 text-2xl font-bold text-slate-900 uppercase">{profile.status}</p>
              <p className="mt-1 text-xs text-slate-500">Autonomous lifecycle state</p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Total Recent Events</p>
              <p className="mt-2 text-2xl font-bold text-slate-900">{profile.total_recent_events}</p>
              <p className="mt-1 text-xs text-slate-500">Sample window: last 100 events</p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Allowed / Denied</p>
              <p className="mt-2 text-2xl font-bold text-slate-900">
                <span className="text-emerald-600">{profile.allowed_count}</span> / <span className="text-rose-600">{profile.denied_count}</span>
              </p>
              <p className="mt-1 text-xs text-slate-500">Authorization decisions</p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Deny Rate</p>
              <p className="mt-2 text-2xl font-bold text-slate-900">
                {(profile.deny_rate * 100).toFixed(1)}%
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {profile.deny_rate > 0.3 ? "Elevated denial anomaly" : "Normal operating range"}
              </p>
            </div>
          </div>

          {/* Recent Alerts and Events */}
          <div className="grid gap-6 lg:grid-cols-2">
            {/* Recent Alerts */}
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
              <h3 className="font-bold text-slate-900">Triggered Security Alerts</h3>
              {profile.recent_alerts.length > 0 ? (
                <div className="space-y-2">
                  {profile.recent_alerts.map((a) => (
                    <div key={a.alert_id} className="rounded-lg border border-slate-100 bg-slate-50 p-3 text-sm">
                      <div className="flex justify-between items-center font-semibold text-slate-800">
                        <span>{a.title}</span>
                        <span className="rounded bg-rose-100 text-rose-800 text-xs px-2 py-0.5">{a.severity}</span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{formatDate(a.first_seen_at)}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-6 text-center">No active alerts for this agent.</p>
              )}
            </div>

            {/* Recent Security Events */}
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
              <h3 className="font-bold text-slate-900">Recent Security Activity</h3>
              {profile.recent_events.length > 0 ? (
                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {profile.recent_events.map((e) => (
                    <div key={e.event_id} className="rounded-lg border border-slate-100 bg-slate-50 p-2.5 text-xs">
                      <div className="flex justify-between font-medium text-slate-800">
                        <span>{e.event_type}</span>
                        <span className={e.decision === "ALLOWED" ? "text-emerald-700" : "text-rose-700 font-bold"}>
                          {e.decision || "-"}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 mt-0.5">{formatDate(e.created_at)}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 py-6 text-center">No security events found for this agent.</p>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
