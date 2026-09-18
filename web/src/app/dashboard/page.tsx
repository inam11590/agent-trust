"use client";

import { Bot, CheckCircle2, FileCheck2, ShieldAlert, ShieldCheck } from "lucide-react";

import { ActivityTable } from "@/components/activity-table";
import { EmptyState, ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import type { Agent, AuditLog, PaginatedAuditLogs, Permission } from "@/types";

export default function DashboardPage() {
  const agents = useApiQuery<Agent[]>("/agents");
  const permissions = useApiQuery<Permission[]>("/permissions");
  const activity = useApiQuery<PaginatedAuditLogs>("/audit-logs?page=1&page_size=6");
  const approved = useApiQuery<PaginatedAuditLogs>("/audit-logs?decision=APPROVED&page=1&page_size=1");
  const rejected = useApiQuery<PaginatedAuditLogs>("/audit-logs?decision=REJECTED&page=1&page_size=1");
  const queries = [agents, permissions, activity, approved, rejected];
  const loading = queries.some((query) => query.loading);
  const error = queries.find((query) => query.error)?.error;

  if (loading) return <LoadingState label="Loading your security overview" />;
  if (error) return <ErrorState message={error} retry={() => queries.forEach((query) => query.reload())} />;

  const cards = [
    { label: "Total Agents", value: agents.data?.length ?? 0, icon: Bot, tone: "bg-blue-50 text-blue-700" },
    { label: "Active Agents", value: agents.data?.filter((agent) => agent.status === "active").length ?? 0, icon: ShieldCheck, tone: "bg-emerald-50 text-emerald-700" },
    { label: "Active Permissions", value: permissions.data?.filter((permission) => permission.status === "active").length ?? 0, icon: FileCheck2, tone: "bg-violet-50 text-violet-700" },
    { label: "Approved Requests", value: approved.data?.total ?? 0, icon: CheckCircle2, tone: "bg-teal-50 text-teal-700" },
    { label: "Rejected Requests", value: rejected.data?.total ?? 0, icon: ShieldAlert, tone: "bg-red-50 text-red-700" },
  ];

  return (
    <div className="space-y-8">
      <PageHeader title="Security overview" description="A live view of your agents, grants, and authorization decisions." />
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {cards.map(({ label, value, icon: Icon, tone }) => <div key={label} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><div className={`mb-5 grid size-10 place-items-center rounded-lg ${tone}`}><Icon size={20} /></div><p className="text-3xl font-semibold tracking-tight text-slate-950">{value}</p><p className="mt-1 text-sm text-slate-500">{label}</p></div>)}
      </section>
      <section>
        <div className="mb-4"><h2 className="text-lg font-semibold text-slate-950">Recent authorization activity</h2><p className="mt-1 text-sm text-slate-500">The latest approval and rejection decisions.</p></div>
        {activity.data?.items.length ? <ActivityTable logs={activity.data.items as AuditLog[]} agents={agents.data ?? []} /> : <EmptyState title="No audit activity yet" description="Authorization decisions will appear here as soon as an agent makes a request." />}
      </section>
    </div>
  );
}
