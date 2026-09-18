"use client";

import { FormEvent, useState } from "react";
import { useParams } from "next/navigation";
import { Copy } from "lucide-react";

import { ActivityTable } from "@/components/activity-table";
import { EmptyState, ErrorState, Field, LoadingState, PageHeader, StatusBadge, buttonClass, inputClass, secondaryButtonClass, textareaClass } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate, formatMoney } from "@/lib/format";
import type { Agent, PaginatedAuditLogs, Permission } from "@/types";
import { useAuth } from "@/contexts/auth-context";
import { SigningKeys } from "@/components/signing-keys";

export default function AgentDetailsPage() {
  const { role = "owner" } = useAuth();
  const id = String(useParams<{ id: string }>().id);
  const agent = useApiQuery<Agent>(`/agents/${encodeURIComponent(id)}`);
  const permissions = useApiQuery<Permission[]>("/permissions");
  const activity = useApiQuery<PaginatedAuditLogs>(`/agents/${encodeURIComponent(id)}/audit-logs?page=1&page_size=5`);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  if ([agent, permissions, activity].some((query) => query.loading)) return <LoadingState label="Loading agent" />;
  const error = [agent, permissions, activity].find((query) => query.error)?.error;
  if (error || !agent.data) return <ErrorState message={error ?? "Agent not found."} retry={() => { agent.reload(); permissions.reload(); activity.reload(); }} />;
  const grants = permissions.data?.filter((permission) => permission.agent_id === agent.data?.id) ?? [];
  if (role !== "owner" && role !== "admin") {
    return <div className="space-y-7"><PageHeader title={agent.data.name} description="Read-only agent details." action={<StatusBadge value={agent.data.status} />} /><section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><dl className="grid gap-5 sm:grid-cols-2"><Detail label="Public Agent ID">{agent.data.agent_identifier}</Detail><Detail label="Created">{formatDate(agent.data.created_at, true)}</Detail><Detail label="Description" wide>{agent.data.description ?? "No description provided."}</Detail></dl></section><section><h2 className="mb-4 text-lg font-semibold">Permissions</h2>{grants.length ? <PermissionsTableReadOnly permissions={grants} /> : <EmptyState title="No permissions found" description="This agent does not have a permission yet." />}</section></div>;
  }

  async function update(payload: object, success: string) {
    setBusy(true); setMessage("");
    try { await apiRequest(`/agents/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) }); setMessage(success); setEditing(false); agent.reload(); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to update agent."); }
    finally { setBusy(false); }
  }

  function saveDetails(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    void update({ name: String(form.get("name")), description: String(form.get("description")) || null }, "Agent details updated.");
  }

  return <div className="space-y-8"><PageHeader title={agent.data.name} description="Agent identity, permissions, and recent authorization activity." action={<StatusBadge value={agent.data.status} />} />{message && <div role="status" className="rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-800">{message}</div>}
    <section className="grid gap-5 lg:grid-cols-[1.15fr_0.85fr]"><div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-center justify-between"><h2 className="font-semibold text-slate-950">Agent details</h2><button onClick={() => setEditing(!editing)} className="text-sm font-semibold text-[#3157d5]">{editing ? "Cancel" : "Edit"}</button></div>{editing ? <form onSubmit={saveDetails} className="mt-5 space-y-4"><Field label="Agent name"><input name="name" defaultValue={agent.data.name} className={inputClass} required maxLength={200} /></Field><Field label="Description"><textarea name="description" defaultValue={agent.data.description ?? ""} className={textareaClass} maxLength={2000} /></Field><button disabled={busy} className={buttonClass}>{busy ? "Saving…" : "Save changes"}</button></form> : <dl className="mt-5 grid gap-5 sm:grid-cols-2"><Detail label="Public Agent ID"><button onClick={() => navigator.clipboard.writeText(agent.data!.agent_identifier)} className="flex items-center gap-2 break-all text-left font-mono text-xs font-semibold text-[#3157d5]">{agent.data.agent_identifier}<Copy size={13} /></button></Detail><Detail label="Created">{formatDate(agent.data.created_at, true)}</Detail><Detail label="Description" wide>{agent.data.description ?? "No description provided."}</Detail></dl>}</div><div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h2 className="font-semibold text-slate-950">Lifecycle controls</h2><p className="mt-2 text-sm leading-6 text-slate-500">Authorization accepts only active agents. Revocation is permanent.</p><div className="mt-5 flex flex-wrap gap-2">{agent.data.status !== "revoked" && agent.data.status !== "active" && <button disabled={busy} onClick={() => update({ status: "active" }, "Agent activated.")} className={buttonClass}>Activate</button>}{agent.data.status === "active" && <button disabled={busy} onClick={() => update({ status: "suspended" }, "Agent suspended.")} className={secondaryButtonClass}>Suspend</button>}{agent.data.status !== "revoked" && <button disabled={busy} onClick={() => { if (window.confirm("Revoke this agent permanently?")) void update({ status: "revoked" }, "Agent revoked."); }} className="inline-flex h-10 items-center rounded-lg px-4 text-sm font-semibold text-red-600 hover:bg-red-50">Revoke</button>}</div></div></section>
    <SigningKeys agentId={agent.data.id} />
    <section><h2 className="mb-4 text-lg font-semibold text-slate-950">Permissions for this agent</h2>{grants.length ? <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white"><table className="w-full min-w-[700px] text-left text-sm"><thead className="border-b bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="px-5 py-3">Scope</th><th className="px-5 py-3">Limit</th><th className="px-5 py-3">Status</th><th className="px-5 py-3">Expires</th></tr></thead><tbody className="divide-y divide-slate-100">{grants.map((permission) => <tr key={permission.id}><td className="px-5 py-4 font-medium">{permission.action} · {permission.resource}</td><td className="px-5 py-4">{formatMoney(permission.maximum_amount, permission.currency)}</td><td className="px-5 py-4"><StatusBadge value={permission.status} /></td><td className="px-5 py-4 text-slate-500">{formatDate(permission.expires_at, true)}</td></tr>)}</tbody></table></div> : <EmptyState title="No permissions found" description="This agent does not have a permission yet." />}</section>
    <section><h2 className="mb-4 text-lg font-semibold text-slate-950">Recent activity</h2>{activity.data?.items.length ? <ActivityTable logs={activity.data.items} agents={[agent.data]} /> : <EmptyState title="No audit activity yet" description="Authorization decisions for this agent will appear here." />}</section>
  </div>;
}

function Detail({ label, children, wide = false }: { label: string; children: React.ReactNode; wide?: boolean }) {
  return <div className={wide ? "sm:col-span-2" : ""}><dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">{label}</dt><dd className="mt-1.5 text-sm leading-6 text-slate-700">{children}</dd></div>;
}

function PermissionsTableReadOnly({ permissions }: { permissions: Permission[] }) {
  return <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><ul className="space-y-3">{permissions.map((permission) => <li key={permission.id} className="flex items-center justify-between border-b border-slate-100 pb-3 text-sm"><span>{permission.action} · {permission.resource}</span><StatusBadge value={permission.status} /></li>)}</ul></div>;
}
