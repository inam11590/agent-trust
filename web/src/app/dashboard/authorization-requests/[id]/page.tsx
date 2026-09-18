"use client";

import { useParams } from "next/navigation";
import { useState } from "react";

import { ErrorState, LoadingState, PageHeader, StatusBadge, buttonClass, secondaryButtonClass } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate, formatMoney } from "@/lib/format";
import type { AuthorizationRequestItem } from "@/types";

export default function AuthorizationRequestPage() {
  const id = String(useParams().id);
  const query = useApiQuery<AuthorizationRequestItem>(`/authorization-requests/${id}`);
  const [busy, setBusy] = useState(false);
  async function decide(action: "approve" | "reject") {
    setBusy(true);
    try { await apiRequest(`/authorization-requests/${id}/${action}`, { method: "POST" }); query.reload(); }
    finally { setBusy(false); }
  }
  if (query.loading) return <LoadingState label="Loading request" />;
  if (query.error || !query.data) return <ErrorState message={query.error ?? "Request not found."} retry={query.reload} />;
  const item = query.data;
  return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Authorization Request" description="Review the live request before making a decision." /><section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-start justify-between gap-4"><div><h2 className="text-xl font-semibold text-slate-950">{item.agent_name}</h2><p className="mt-1 text-sm text-slate-500">{item.request_id}</p></div><StatusBadge value={item.status} /></div>{item.risk_level && <div className={`mt-5 rounded-lg border p-4 ${item.risk_level === "HIGH" || item.risk_level === "CRITICAL" ? "border-amber-200 bg-amber-50" : "border-blue-100 bg-blue-50"}`}><p className="font-semibold text-slate-900">{item.risk_level} RISK · {item.risk_score}/100</p><p className="mt-1 text-sm text-slate-600">Why this request needs attention:</p><ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-700">{(item.risk_reasons ?? []).map((reason) => <li key={reason}>{reason}</li>)}</ul></div>}<dl className="mt-6 grid gap-5 border-t border-slate-100 pt-6 sm:grid-cols-2"><Detail label="Action" value={item.action} /><Detail label="Resource" value={item.resource} /><Detail label="Amount" value={formatMoney(item.amount, item.currency)} /><Detail label="Expires" value={formatDate(item.expires_at, true)} /><Detail label="Reason" value={item.reason} /></dl>{item.status === "PENDING" && <div className="mt-7 flex gap-3 border-t border-slate-100 pt-6"><button disabled={busy} onClick={() => void decide("approve")} className={buttonClass}>Approve</button><button disabled={busy} onClick={() => void decide("reject")} className={secondaryButtonClass}>Reject</button></div>}</section></div>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs font-semibold uppercase text-slate-400">{label}</dt><dd className="mt-1 text-sm font-medium text-slate-800">{value}</dd></div>;
}
