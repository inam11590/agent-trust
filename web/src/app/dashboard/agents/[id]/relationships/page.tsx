"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Bot,
  ChevronRight,
  ExternalLink,
  Key,
  Network,
  RefreshCw,
  Shield,
  ShieldAlert,
  Zap,
} from "lucide-react";

import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import type { DependencyGraph } from "@/types";

export default function AgentRelationshipsPage() {
  const params = useParams<{ id: string }>();
  const agentIdentifier = String(params.id);

  const query = useApiQuery<DependencyGraph>(`/agents/${encodeURIComponent(agentIdentifier)}/relationships`);

  if (query.loading) return <LoadingState label="Analyzing agent dependency graph..." />;
  if (query.error) return <ErrorState message={query.error} retry={query.reload} />;

  const graph = query.data;
  if (!graph) return <EmptyState title="No graph data" description="Could not load relationship graph." />;

  const metrics = graph.metrics || {
    total_nodes: 1,
    total_edges: 0,
    connected_agents_count: 0,
    active_credentials_count: 0,
    bound_policies_count: 0,
    blast_radius_score: 0,
  };

  const blastScore = metrics.blast_radius_score;
  const blastColor =
    blastScore > 80
      ? "text-rose-600 bg-rose-50 border-rose-200"
      : blastScore > 40
      ? "text-amber-600 bg-amber-50 border-amber-200"
      : "text-emerald-600 bg-emerald-50 border-emerald-200";

  return (
    <div className="space-y-7">
      <div className="flex items-center gap-2 text-sm text-slate-500">
        <Link href="/dashboard/agents" className="hover:text-slate-800">
          Agents
        </Link>
        <ChevronRight size={14} />
        <Link href={`/dashboard/agents/${agentIdentifier}`} className="hover:text-slate-800">
          {graph.root_agent_name}
        </Link>
        <ChevronRight size={14} />
        <span className="font-semibold text-slate-900">Blast Radius & Relationships</span>
      </div>

      <PageHeader
        title={`${graph.root_agent_name} — Blast Radius Analysis`}
        description={`Authoritative dependency topology and security impact radius for ${agentIdentifier}.`}
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => query.reload()}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <RefreshCw size={13} /> Refresh Topology
            </button>
            <Link
              href={`/dashboard/agents/${agentIdentifier}`}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#3157d5] px-3 py-1.5 text-xs font-medium text-white hover:bg-[#2847b3]"
            >
              <ArrowLeft size={13} /> Return to Workbench
            </Link>
          </div>
        }
      />

      {/* Blast Radius Metrics Summary */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <div className={`rounded-xl border p-4 shadow-sm ${blastColor}`}>
          <div className="text-xs font-semibold uppercase tracking-wider">Blast Radius Score</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold">{blastScore}</span>
            <span className="text-xs font-medium">exposure index</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Connected Agents</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900">{metrics.connected_agents_count}</span>
            <span className="text-xs text-slate-400">callers / targets</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Active Credentials</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900">{metrics.active_credentials_count}</span>
            <span className="text-xs text-slate-400">verifiable keys</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Bound Policies</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900">{metrics.bound_policies_count}</span>
            <span className="text-xs text-slate-400">APL/1.0</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Total Graph Nodes</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900">{metrics.total_nodes}</span>
            <span className="text-xs text-slate-400">topology entities</span>
          </div>
        </div>
      </div>

      {/* Visual Topology Representation */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <h3 className="text-base font-semibold text-slate-900 mb-4 flex items-center gap-2">
          <Network size={18} className="text-[#3157d5]" /> Topology Graph Nodes & Edges
        </h3>

        <div className="grid gap-6 md:grid-cols-2">
          {/* Nodes list */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Connected Nodes ({graph.nodes.length})
            </h4>
            <div className="space-y-2 max-h-96 overflow-y-auto pr-2">
              {graph.nodes.map((node) => {
                const isRoot = node.is_root;
                const icon =
                  node.type === "credential" ? (
                    <Key size={14} className="text-emerald-600" />
                  ) : node.type === "policy" ? (
                    <Shield size={14} className="text-purple-600" />
                  ) : (
                    <Bot size={14} className={isRoot ? "text-[#3157d5]" : "text-slate-600"} />
                  );

                return (
                  <div
                    key={node.id}
                    className={`flex items-center justify-between rounded-lg border p-3 text-xs ${
                      isRoot ? "border-[#3157d5] bg-blue-50/50" : "border-slate-200 bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      {icon}
                      <div className="min-w-0">
                        <div className="font-semibold text-slate-900 truncate">
                          {node.label} {isRoot && <span className="text-[#3157d5]">(Root Agent)</span>}
                        </div>
                        {node.identifier && (
                          <div className="text-[10px] font-mono text-slate-500 truncate">{node.identifier}</div>
                        )}
                      </div>
                    </div>
                    <span className="rounded bg-white px-2 py-0.5 font-mono text-[10px] text-slate-600 border border-slate-200 shrink-0">
                      {node.type}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Edges list */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">
              Relationship Links ({graph.edges.length})
            </h4>
            {!graph.edges.length ? (
              <div className="rounded-lg border border-dashed border-slate-200 p-8 text-center text-xs text-slate-500">
                No active delegations or linked dependencies detected. This agent operates as a standalone identity.
              </div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-2">
                {graph.edges.map((edge, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between rounded-lg border border-slate-200 bg-white p-3 text-xs"
                  >
                    <div className="flex flex-col gap-0.5 min-w-0">
                      <span className="font-semibold text-slate-800 truncate">
                        {edge.relationship}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400 truncate">
                        {edge.source} &rarr; {edge.target}
                      </span>
                    </div>
                    {edge.actions && (
                      <span className="rounded bg-slate-100 px-2 py-0.5 text-[10px] text-slate-600 truncate max-w-[120px]">
                        {edge.actions.join(", ")}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
