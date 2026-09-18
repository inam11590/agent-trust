"use client";

import { useParams } from "next/navigation";

import { ErrorState, LoadingState, PageHeader, StatusBadge } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { formatDate, formatMoney } from "@/lib/format";
import type { Agent, AuditLog } from "@/types";

export default function AuditLogDetailsPage() {
  const id = String(useParams<{ id: string }>().id);
  const log = useApiQuery<AuditLog>(`/audit-logs/${encodeURIComponent(id)}`);
  const agents = useApiQuery<Agent[]>("/agents");
  if (log.loading || agents.loading) return <LoadingState label="Loading audit record" />;
  if (log.error || agents.error || !log.data) return <ErrorState message={log.error ?? agents.error ?? "Audit record not found."} retry={() => { log.reload(); agents.reload(); }} />;
  const agent = agents.data?.find((item) => item.agent_identifier === log.data?.agent_identifier);
  const rows = [
    ["Request ID", log.data.request_id], ["Agent", agent?.name ?? log.data.agent_identifier], ["Public Agent ID", log.data.agent_identifier],
    ["Action", log.data.action], ["Resource", log.data.resource], ["Amount", formatMoney(log.data.amount, log.data.currency)],
    ["Currency", log.data.currency ?? "—"], ["Reason", log.data.reason], ["Requested time", formatDate(log.data.requested_at, true)],
  ];
  return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Audit record" description="This historical authorization record is read-only." action={<StatusBadge value={log.data.decision} />} /><div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><dl className="divide-y divide-slate-100">{rows.map(([label, value]) => <div key={label} className="grid gap-1 py-4 sm:grid-cols-[180px_1fr]"><dt className="text-sm font-medium text-slate-500">{label}</dt><dd className="break-all text-sm font-semibold text-slate-800">{value}</dd></div>)}</dl></div></div>;
}
