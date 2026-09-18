"use client";

import { Bot, ChevronRight, Copy } from "lucide-react";
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
  if (query.loading) return <LoadingState label="Loading agents" />;
  if (query.error) return <ErrorState message={query.error} retry={query.reload} />;

  return <div className="space-y-7"><PageHeader title="My Agents" description="Software identities registered to your workspace." action={canManage ? <PrimaryLink href="/dashboard/agents/new">Create Agent</PrimaryLink> : undefined} />
    {!query.data?.length ? <EmptyState title="No agents created yet" description="Create your first agent to begin assigning controlled permissions." /> : <div className="grid gap-4 xl:grid-cols-2">{query.data.map((agent) => <article key={agent.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-slate-300 hover:shadow-md"><div className="flex items-start justify-between gap-4"><div className="flex min-w-0 gap-4"><span className="grid size-11 shrink-0 place-items-center rounded-xl bg-blue-50 text-[#3157d5]"><Bot size={21} /></span><div className="min-w-0"><h2 className="font-semibold text-slate-950">{agent.name}</h2><button title="Copy agent ID" onClick={() => navigator.clipboard.writeText(agent.agent_identifier)} className="mt-1 flex max-w-full items-center gap-1.5 text-left text-xs text-slate-500 hover:text-[#3157d5]"><span className="truncate font-mono">{agent.agent_identifier}</span><Copy size={12} /></button></div></div><StatusBadge value={agent.status} /></div><p className="mt-5 line-clamp-2 min-h-10 text-sm leading-5 text-slate-500">{agent.description ?? "No description provided."}</p><div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4"><span className="text-xs text-slate-400">Created {formatDate(agent.created_at)}</span><Link href={`/dashboard/agents/${agent.agent_identifier}`} className="inline-flex items-center gap-1 text-sm font-semibold text-[#3157d5]">View <ChevronRight size={15} /></Link></div></article>)}</div>}
  </div>;
}
