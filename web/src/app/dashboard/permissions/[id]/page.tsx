"use client";

import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { ErrorState, LoadingState, PageHeader, StatusBadge, buttonClass } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate, formatMoney } from "@/lib/format";
import type { Agent, Permission } from "@/types";
import { useAuth } from "@/contexts/auth-context";

export default function PermissionDetailsPage() {
  const { role = "owner" } = useAuth();
  const id = String(useParams<{ id: string }>().id);
  const router = useRouter();
  const created = useSearchParams().get("created") === "1";
  const permission = useApiQuery<Permission>(`/permissions/${encodeURIComponent(id)}`);
  const agents = useApiQuery<Agent[]>("/agents");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  if (permission.loading || agents.loading) return <LoadingState label="Loading permission" />;
  if (permission.error || agents.error || !permission.data) return <ErrorState message={permission.error ?? agents.error ?? "Permission not found."} retry={() => { permission.reload(); agents.reload(); }} />;
  const agent = agents.data?.find((item) => item.id === permission.data?.agent_id);

  async function revoke() {
    if (!window.confirm("Revoke this permission immediately?")) return;
    setBusy(true); setError("");
    try { await apiRequest(`/permissions/${id}/revoke`, { method: "POST" }); permission.reload(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to revoke permission."); }
    finally { setBusy(false); }
  }

  const rows = [
    ["Agent", agent?.name ?? "Unknown agent"], ["Action", permission.data.action], ["Resource", permission.data.resource],
    ["Maximum", formatMoney(permission.data.maximum_amount, permission.data.currency)], ["Valid from", formatDate(permission.data.valid_from, true)],
    ["Expires at", formatDate(permission.data.expires_at, true)], ["Permission ID", permission.data.id],
  ];
  if (role !== "owner" && role !== "admin") {
    return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Permission details" description="Read-only capability grant." action={<StatusBadge value={permission.data.status} />} /><div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><dl className="divide-y divide-slate-100">{rows.map(([label, value]) => <div key={label} className="grid gap-1 py-4 sm:grid-cols-[180px_1fr]"><dt className="text-sm font-medium text-slate-500">{label}</dt><dd className="break-all text-sm font-semibold text-slate-800">{value}</dd></div>)}</dl></div></div>;
  }
  return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Permission details" description="A read-only view of this capability grant." action={<StatusBadge value={permission.data.status} />} />{created && <div role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-700">Permission created successfully.</div>}{error && <div role="alert" className="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}<div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><dl className="divide-y divide-slate-100">{rows.map(([label, value]) => <div key={label} className="grid gap-1 py-4 sm:grid-cols-[180px_1fr]"><dt className="text-sm font-medium text-slate-500">{label}</dt><dd className="break-all text-sm font-semibold text-slate-800">{value}</dd></div>)}</dl>{permission.data.status === "active" && <div className="mt-5 flex justify-end border-t border-slate-100 pt-5"><button onClick={revoke} disabled={busy} className={`${buttonClass} bg-red-600 hover:bg-red-700`}>{busy ? "Revoking…" : "Revoke Permission"}</button></div>}</div><button onClick={() => router.push("/dashboard/permissions")} className="text-sm font-semibold text-[#3157d5]">← Back to permissions</button></div>;
}
