"use client";

import { FormEvent, useMemo, useState } from "react";

import { ActivityTable } from "@/components/activity-table";
import { EmptyState, ErrorState, LoadingState, PageHeader, inputClass, secondaryButtonClass } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import type { Agent, PaginatedAuditLogs } from "@/types";

type Filters = { agent: string; decision: string; action: string; resource: string; start: string; end: string };
const emptyFilters: Filters = { agent: "", decision: "", action: "", resource: "", start: "", end: "" };

export default function AuditLogsPage() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [draft, setDraft] = useState<Filters>(emptyFilters);
  const agents = useApiQuery<Agent[]>("/agents");
  const path = useMemo(() => {
    const params = new URLSearchParams({ page: String(page), page_size: "20" });
    if (filters.agent) params.set("agent_id", filters.agent);
    if (filters.decision) params.set("decision", filters.decision);
    if (filters.action) params.set("action", filters.action.toLowerCase());
    if (filters.resource) params.set("resource", filters.resource.toLowerCase());
    if (filters.start) params.set("start_date", new Date(filters.start).toISOString());
    if (filters.end) params.set("end_date", new Date(filters.end).toISOString());
    return `/audit-logs?${params}`;
  }, [filters, page]);
  const logs = useApiQuery<PaginatedAuditLogs>(path);
  if (agents.loading || logs.loading) return <LoadingState label="Loading audit history" />;
  if (agents.error || logs.error) return <ErrorState message={agents.error ?? logs.error ?? "Unable to load audit history."} retry={() => { agents.reload(); logs.reload(); }} />;

  function apply(event: FormEvent) { event.preventDefault(); setPage(1); setFilters(draft); }
  function clear() { setDraft(emptyFilters); setFilters(emptyFilters); setPage(1); }

  return <div className="space-y-7"><PageHeader title="Audit Logs" description="Permanent records of authorization approvals and rejections." /><form onSubmit={apply} className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-2 xl:grid-cols-7"><select aria-label="Agent filter" className={inputClass} value={draft.agent} onChange={(event) => setDraft({ ...draft, agent: event.target.value })}><option value="">All agents</option>{agents.data?.map((agent) => <option key={agent.id} value={agent.agent_identifier}>{agent.name}</option>)}</select><select aria-label="Decision filter" className={inputClass} value={draft.decision} onChange={(event) => setDraft({ ...draft, decision: event.target.value })}><option value="">All decisions</option><option value="APPROVED">Approved</option><option value="REJECTED">Rejected</option></select><input aria-label="Action filter" className={inputClass} placeholder="Action" value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value })} /><input aria-label="Resource filter" className={inputClass} placeholder="Resource" value={draft.resource} onChange={(event) => setDraft({ ...draft, resource: event.target.value })} /><input aria-label="Start date" title="Start date" className={inputClass} type="datetime-local" value={draft.start} onChange={(event) => setDraft({ ...draft, start: event.target.value })} /><input aria-label="End date" title="End date" className={inputClass} type="datetime-local" value={draft.end} onChange={(event) => setDraft({ ...draft, end: event.target.value })} /><div className="flex gap-2"><button className={`${secondaryButtonClass} flex-1 border-[#3157d5] text-[#3157d5]`}>Filter</button><button type="button" onClick={clear} className="px-2 text-xs font-semibold text-slate-500">Clear</button></div></form>{logs.data?.items.length ? <><ActivityTable logs={logs.data.items} agents={agents.data ?? []} /><div className="flex items-center justify-between"><p className="text-sm text-slate-500">Page {logs.data.page} of {logs.data.total_pages} · {logs.data.total} records</p><div className="flex gap-2"><button className={secondaryButtonClass} disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button><button className={secondaryButtonClass} disabled={page >= logs.data.total_pages} onClick={() => setPage((value) => value + 1)}>Next</button></div></div></> : <EmptyState title="No audit activity yet" description="Try changing the filters, or send an authorization request to create an audit record." />}</div>;
}
