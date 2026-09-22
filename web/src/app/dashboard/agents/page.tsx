"use client";

import { useState } from "react";
import {
  AlertTriangle,
  Bot,
  Calendar,
  CheckCircle2,
  ChevronRight,
  Copy,
  Download,
  Filter,
  Layers,
  Network,
  Search,
  Shield,
  ShieldAlert,
  UserCheck,
  Users,
} from "lucide-react";
import Link from "next/link";

import { EmptyState, ErrorState, LoadingState, PageHeader, PrimaryLink, StatusBadge } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { formatDate } from "@/lib/format";
import type { Agent } from "@/types";
import { useAuth } from "@/contexts/auth-context";

export default function AgentsPage() {
  const { role = "owner" } = useAuth();
  const canManage = role === "owner" || role === "admin";
  const query = useApiQuery<Agent[]>("/agents");

  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [bulkAction, setBulkAction] = useState("");
  const [bulkSuccessMsg, setBulkSuccessMsg] = useState("");

  if (query.loading) return <LoadingState label="Loading agents inventory" />;
  if (query.error) return <ErrorState message={query.error} retry={query.reload} />;

  const agents = query.data || [];

  // Filter calculations
  const filteredAgents = agents.filter((ag) => {
    if (statusFilter !== "all" && ag.status.toLowerCase() !== statusFilter.toLowerCase()) {
      return false;
    }
    if (riskFilter !== "all" && (ag.risk_classification || "LOW").toUpperCase() !== riskFilter.toUpperCase()) {
      return false;
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchName = ag.name.toLowerCase().includes(term);
      const matchId = ag.agent_identifier.toLowerCase().includes(term);
      const matchTeam = (ag.team || "").toLowerCase().includes(term);
      if (!matchName && !matchId && !matchTeam) return false;
    }
    return true;
  });

  // KPI Metrics
  const totalCount = agents.length;
  const activeCount = agents.filter((a) => a.status === "active").length;
  const reviewDueCount = agents.filter((a) => a.status === "review_required" || a.certification_status === "REVIEW_DUE").length;
  const suspendedCount = agents.filter((a) => a.status === "suspended").length;
  const highRiskCount = agents.filter((a) => a.risk_classification === "HIGH" || a.risk_classification === "CRITICAL").length;

  const handleSelectAll = () => {
    if (selectedIds.length === filteredAgents.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filteredAgents.map((a) => a.id));
    }
  };

  const handleToggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleExecuteBulk = async () => {
    if (!bulkAction || !selectedIds.length) return;
    try {
      const res = await fetch("/api/v1/governance/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: bulkAction,
          agent_ids: selectedIds,
          params: { reason: "Bulk governance action from web dashboard" },
        }),
      });
      if (res.ok) {
        setBulkSuccessMsg(`Successfully executed ${bulkAction} on ${selectedIds.length} agents.`);
        setSelectedIds([]);
        setBulkAction("");
        query.reload();
        setTimeout(() => setBulkSuccessMsg(""), 4000);
      }
    } catch {
      // ignore
    }
  };

  return (
    <div className="space-y-7">
      <PageHeader
        title="Agent Inventory & Governance"
        description="Authoritative registry of AI software identities, ownership accountability, and lifecycle governance."
        action={
          <div className="flex items-center gap-3">
            <Link
              href="/dashboard/governance"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <Shield size={16} /> Governance Dashboard
            </Link>
            {canManage && <PrimaryLink href="/dashboard/agents/new">Create Agent</PrimaryLink>}
          </div>
        }
      />

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Total Agents</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900">{totalCount}</span>
            <span className="text-xs text-slate-400">governed assets</span>
          </div>
        </div>

        <div className="rounded-xl border border-emerald-100 bg-emerald-50/50 p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-emerald-700">Active Agents</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-emerald-900">{activeCount}</span>
            <span className="text-xs text-emerald-600">operational</span>
          </div>
        </div>

        <div className="rounded-xl border border-amber-100 bg-amber-50/50 p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-amber-700">Review Due</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-900">{reviewDueCount}</span>
            <span className="text-xs text-amber-600">pending sign-off</span>
          </div>
        </div>

        <div className="rounded-xl border border-rose-100 bg-rose-50/50 p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-rose-700">Suspended</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-900">{suspendedCount}</span>
            <span className="text-xs text-rose-600">fail-closed</span>
          </div>
        </div>

        <div className="rounded-xl border border-purple-100 bg-purple-50/50 p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-purple-700">High / Critical</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-purple-900">{highRiskCount}</span>
            <span className="text-xs text-purple-600">high exposure</span>
          </div>
        </div>
      </div>

      {bulkSuccessMsg && (
        <div className="flex items-center gap-2 rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800">
          <CheckCircle2 size={16} /> {bulkSuccessMsg}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <div className="flex flex-1 items-center gap-3">
          <div className="relative min-w-[240px] flex-1 max-w-md">
            <Search className="absolute left-3 top-2.5 size-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by name, ID, or team..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full rounded-lg border border-slate-200 pl-9 pr-3 py-1.5 text-sm outline-none focus:border-[#3157d5] focus:ring-1 focus:ring-[#3157d5]"
            />
          </div>

          <div className="flex items-center gap-1.5 border-l border-slate-200 pl-3">
            <Filter size={14} className="text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
            >
              <option value="all">All States</option>
              <option value="active">Active</option>
              <option value="draft">Draft</option>
              <option value="registered">Registered</option>
              <option value="review_required">Review Required</option>
              <option value="approved">Approved</option>
              <option value="suspended">Suspended</option>
              <option value="retired">Retired</option>
            </select>

            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700"
            >
              <option value="all">All Risk</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
        </div>

        {/* Bulk Action Controls */}
        {selectedIds.length > 0 && canManage && (
          <div className="flex items-center gap-2 bg-blue-50/70 px-3 py-1.5 rounded-lg border border-blue-200">
            <span className="text-xs font-semibold text-[#3157d5]">{selectedIds.length} selected</span>
            <select
              value={bulkAction}
              onChange={(e) => setBulkAction(e.target.value)}
              className="rounded border border-blue-200 bg-white px-2 py-1 text-xs text-slate-700"
            >
              <option value="">Bulk Action...</option>
              <option value="trigger_review">Trigger Certification Review</option>
              <option value="suspend">Emergency Suspend</option>
            </select>
            <button
              onClick={handleExecuteBulk}
              disabled={!bulkAction}
              className="rounded bg-[#3157d5] px-2.5 py-1 text-xs font-medium text-white hover:bg-[#2847b3] disabled:opacity-50"
            >
              Apply
            </button>
          </div>
        )}
      </div>

      {/* Agents Grid */}
      {!filteredAgents.length ? (
        <EmptyState
          title="No agents found"
          description="Try adjusting your search criteria or register a new agent."
        />
      ) : (
        <div className="grid gap-4 xl:grid-cols-2">
          {filteredAgents.map((agent) => {
            const isSelected = selectedIds.includes(agent.id);
            const risk = (agent.risk_classification || "LOW").toUpperCase();
            const riskColor =
              risk === "CRITICAL"
                ? "bg-rose-100 text-rose-800 border-rose-200"
                : risk === "HIGH"
                ? "bg-amber-100 text-amber-800 border-amber-200"
                : risk === "MEDIUM"
                ? "bg-blue-100 text-blue-800 border-blue-200"
                : "bg-slate-100 text-slate-700 border-slate-200";

            return (
              <article
                key={agent.id}
                className={`rounded-xl border bg-white p-5 shadow-sm transition hover:shadow-md ${
                  isSelected ? "border-[#3157d5] ring-1 ring-[#3157d5]" : "border-slate-200 hover:border-slate-300"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 gap-3">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleToggleSelect(agent.id)}
                      className="mt-1 size-4 rounded border-slate-300 text-[#3157d5] focus:ring-[#3157d5]"
                    />
                    <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-blue-50 text-[#3157d5]">
                      <Bot size={21} />
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <h2 className="font-semibold text-slate-950 truncate">{agent.name}</h2>
                        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold border ${riskColor}`}>
                          {risk} RISK
                        </span>
                      </div>
                      <button
                        title="Copy agent ID"
                        onClick={() => navigator.clipboard.writeText(agent.agent_identifier)}
                        className="mt-1 flex max-w-full items-center gap-1.5 text-left text-xs text-slate-500 hover:text-[#3157d5]"
                      >
                        <span className="truncate font-mono">{agent.agent_identifier}</span>
                        <Copy size={12} />
                      </button>
                    </div>
                  </div>
                  <StatusBadge value={agent.status} />
                </div>

                <p className="mt-4 line-clamp-2 min-h-10 text-sm leading-5 text-slate-600">
                  {agent.purpose || agent.description || "No business purpose or description documented."}
                </p>

                {/* Governance Metadata Badges */}
                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  <span className="inline-flex items-center gap-1 rounded bg-slate-100 px-2 py-0.5">
                    <Users size={12} /> {agent.team || agent.owner_type || "USER"}
                  </span>
                  {agent.business_function && (
                    <span className="inline-flex items-center gap-1 rounded bg-slate-100 px-2 py-0.5">
                      <Layers size={12} /> {agent.business_function}
                    </span>
                  )}
                  {agent.certified_until && (
                    <span className="inline-flex items-center gap-1 rounded bg-emerald-50 text-emerald-700 px-2 py-0.5">
                      <Calendar size={12} /> Certified until {formatDate(agent.certified_until)}
                    </span>
                  )}
                </div>

                {/* Footer Controls */}
                <div className="mt-4 flex items-center justify-between border-t border-slate-100 pt-3 text-xs">
                  <span className="text-slate-400">
                    Created {formatDate(agent.created_at)}
                  </span>
                  <div className="flex items-center gap-3">
                    <Link
                      href={`/dashboard/agents/${agent.agent_identifier}/relationships`}
                      className="inline-flex items-center gap-1 text-slate-600 hover:text-[#3157d5]"
                      title="View dependency and blast-radius graph"
                    >
                      <Network size={14} /> Blast Radius
                    </Link>
                    <Link
                      href={`/dashboard/agents/${agent.agent_identifier}`}
                      className="inline-flex items-center gap-1 font-semibold text-[#3157d5] hover:underline"
                    >
                      Workbench <ChevronRight size={15} />
                    </Link>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
