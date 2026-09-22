"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertCircle,
  AlertTriangle,
  Bot,
  Calendar,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  FileText,
  Filter,
  Layers,
  Network,
  RefreshCw,
  Shield,
  ShieldAlert,
  Users,
} from "lucide-react";

import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";

interface GovernanceKPIs {
  total_agents: number;
  active_agents: number;
  draft_agents: number;
  review_required_agents: number;
  suspended_agents: number;
  retired_agents: number;
  pending_reviews_count: number;
  risk_breakdown: Record<string, number>;
  signal_breakdown: Record<string, number>;
  orphaned_count: number;
  dormant_count: number;
  overdue_count: number;
}

export default function GovernanceDashboardPage() {
  const query = useApiQuery<GovernanceKPIs>("/governance/dashboard");
  const signalsQuery = useApiQuery<Array<{ agent_id: string; agent_identifier: string; name: string; status: string; risk_classification: string; signals: string[] }>>("/governance/signals");

  if (query.loading) return <LoadingState label="Loading Governance KPIs" />;
  if (query.error) return <ErrorState message={query.error} retry={query.reload} />;

  const kpi = query.data || {
    total_agents: 0,
    active_agents: 0,
    draft_agents: 0,
    review_required_agents: 0,
    suspended_agents: 0,
    retired_agents: 0,
    pending_reviews_count: 0,
    risk_breakdown: {},
    signal_breakdown: {},
    orphaned_count: 0,
    dormant_count: 0,
    overdue_count: 0,
  };

  const signalsList = signalsQuery.data || [];

  return (
    <div className="space-y-7">
      <div className="flex items-center gap-2 text-sm text-slate-500">
        <Link href="/dashboard/agents" className="hover:text-slate-800">
          Agents
        </Link>
        <ChevronRight size={14} />
        <span className="font-semibold text-slate-900">Governance Center</span>
      </div>

      <PageHeader
        title="Enterprise Agent Lifecycle Governance"
        description="Centralized posture, access review queues, and security signals for autonomous AI agents."
        action={
          <div className="flex items-center gap-3">
            <Link
              href="/dashboard/governance/reviews"
              className="inline-flex items-center gap-2 rounded-lg bg-[#3157d5] px-3.5 py-2 text-sm font-semibold text-white shadow-sm hover:bg-[#2847b3]"
            >
              <ClipboardCheck size={16} /> Access Review Queue ({kpi.pending_reviews_count})
            </Link>
            <button
              onClick={() => {
                query.reload();
                signalsQuery.reload();
              }}
              className="rounded-lg border border-slate-300 bg-white p-2 text-slate-600 hover:bg-slate-50"
              title="Refresh Dashboard"
            >
              <RefreshCw size={16} />
            </button>
          </div>
        }
      />

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-6">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Total Governed</span>
          <div className="mt-1 text-2xl font-bold text-slate-900">{kpi.total_agents}</div>
          <span className="text-[11px] text-slate-400">across organization</span>
        </div>

        <div className="rounded-xl border border-emerald-100 bg-emerald-50/50 p-4 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-emerald-700">Active Agents</span>
          <div className="mt-1 text-2xl font-bold text-emerald-900">{kpi.active_agents}</div>
          <span className="text-[11px] text-emerald-600">operational</span>
        </div>

        <div className="rounded-xl border border-amber-100 bg-amber-50/50 p-4 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-amber-700">Review Pending</span>
          <div className="mt-1 text-2xl font-bold text-amber-900">{kpi.review_required_agents}</div>
          <span className="text-[11px] text-amber-600">needs sign-off</span>
        </div>

        <div className="rounded-xl border border-rose-100 bg-rose-50/50 p-4 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-rose-700">Suspended</span>
          <div className="mt-1 text-2xl font-bold text-rose-900">{kpi.suspended_agents}</div>
          <span className="text-[11px] text-rose-600">fail-closed edge</span>
        </div>

        <div className="rounded-xl border border-amber-100 bg-amber-50/50 p-4 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-amber-700">Orphaned Agents</span>
          <div className="mt-1 text-2xl font-bold text-amber-900">{kpi.orphaned_count}</div>
          <span className="text-[11px] text-amber-600">owner unassigned/disabled</span>
        </div>

        <div className="rounded-xl border border-purple-100 bg-purple-50/50 p-4 shadow-sm">
          <span className="text-xs font-semibold uppercase tracking-wider text-purple-700">Dormant Agents</span>
          <div className="mt-1 text-2xl font-bold text-purple-900">{kpi.dormant_count}</div>
          <span className="text-[11px] text-purple-600">&gt; 90 days inactive</span>
        </div>
      </div>

      {/* Risk Distribution and Signal Breakdown */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Risk Breakdown Card */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <h3 className="font-semibold text-slate-900 flex items-center gap-2">
            <Shield size={18} className="text-[#3157d5]" /> Risk Classification Breakdown
          </h3>
          <div className="space-y-3">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => {
              const count = kpi.risk_breakdown[level] || 0;
              const pct = kpi.total_agents ? Math.round((count / kpi.total_agents) * 100) : 0;
              const barColor =
                level === "CRITICAL"
                  ? "bg-rose-500"
                  : level === "HIGH"
                  ? "bg-amber-500"
                  : level === "MEDIUM"
                  ? "bg-blue-500"
                  : "bg-emerald-500";

              return (
                <div key={level} className="space-y-1 text-xs">
                  <div className="flex justify-between font-medium">
                    <span className="text-slate-700">{level} Risk</span>
                    <span className="text-slate-500">
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-100 overflow-hidden">
                    <div className={`h-full ${barColor}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Governance Hygiene Signals Card */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <h3 className="font-semibold text-slate-900 flex items-center gap-2">
            <AlertTriangle size={18} className="text-amber-500" /> Active Governance Signals
          </h3>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-lg border border-slate-200 p-3">
              <span className="text-slate-500">Reviews Overdue</span>
              <div className="text-xl font-bold text-rose-600 mt-1">{kpi.overdue_count}</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <span className="text-slate-500">Broad Permissions (*)</span>
              <div className="text-xl font-bold text-amber-600 mt-1">
                {kpi.signal_breakdown["BROAD_PERMISSION"] || 0}
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <span className="text-slate-500">Dormant Identities</span>
              <div className="text-xl font-bold text-slate-700 mt-1">{kpi.dormant_count}</div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <span className="text-slate-500">Orphaned Identities</span>
              <div className="text-xl font-bold text-amber-600 mt-1">{kpi.orphaned_count}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Agents Requiring Governance Attention */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <h3 className="font-semibold text-slate-900">Agents Requiring Attention</h3>
        {!signalsList.length ? (
          <p className="text-xs text-slate-500">All agent identities comply with organization governance policies.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b bg-slate-50 uppercase text-slate-500">
                <tr>
                  <th className="p-3">Agent</th>
                  <th className="p-3">State</th>
                  <th className="p-3">Risk</th>
                  <th className="p-3">Detected Signals</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {signalsList.slice(0, 10).map((item) => (
                  <tr key={item.agent_id}>
                    <td className="p-3 font-semibold text-slate-900">
                      <div>{item.name}</div>
                      <div className="font-mono text-[10px] text-slate-400">{item.agent_identifier}</div>
                    </td>
                    <td className="p-3 uppercase text-slate-600 font-medium">{item.status}</td>
                    <td className="p-3">
                      <span className="rounded bg-slate-100 px-2 py-0.5 font-semibold text-slate-700">
                        {item.risk_classification || "LOW"}
                      </span>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {item.signals.map((sig) => (
                          <span
                            key={sig}
                            className="rounded bg-amber-50 border border-amber-200 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800"
                          >
                            {sig.replace("_", " ")}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3 text-right">
                      <Link
                        href={`/dashboard/agents/${item.agent_identifier}`}
                        className="font-semibold text-[#3157d5] hover:underline"
                      >
                        Inspect &rarr;
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
