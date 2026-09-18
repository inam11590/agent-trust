"use client";

import Link from "next/link";
import { useState } from "react";

import { ErrorState, LoadingState, PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate, formatMoney } from "@/lib/format";
import type { PaginatedRiskAssessments, RiskAction, RiskOverview, RiskPolicy } from "@/types";

export default function RiskPage() {
  const { role } = useAuth();
  const overview = useApiQuery<RiskOverview>("/risk/overview");
  const assessments = useApiQuery<PaginatedRiskAssessments>("/risk/assessments?page=1&page_size=20");
  const policy = useApiQuery<RiskPolicy>("/risk/policy");
  const [saving, setSaving] = useState(false);
  const canEdit = role === "owner" || role === "admin";
  const error = overview.error || assessments.error || policy.error;
  if (overview.loading || assessments.loading || policy.loading) return <LoadingState label="Loading risk overview" />;
  if (error || !overview.data || !assessments.data || !policy.data) return <ErrorState message={error ?? "Risk data is unavailable."} retry={() => { overview.reload(); assessments.reload(); policy.reload(); }} />;
  const policyData = policy.data;

  async function change(name: string, value: boolean | RiskAction) {
    setSaving(true);
    try { await apiRequest("/risk/policy", { method: "PATCH", body: JSON.stringify({ [name]: value }) }); policy.reload(); }
    finally { setSaving(false); }
  }
  const cards = [["Low Risk Requests", overview.data.low, "text-emerald-700"], ["Medium Risk Requests", overview.data.medium, "text-amber-700"], ["High Risk Requests", overview.data.high, "text-orange-700"], ["Critical Requests", overview.data.critical, "text-red-700"]] as const;
  return <div className="space-y-8"><PageHeader title="Risk Overview" description="Clear signals for unusual agent requests." />
    <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{cards.map(([label, value, tone]) => <div key={label} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><p className={`text-3xl font-semibold ${tone}`}>{value}</p><p className="mt-1 text-sm text-slate-500">{label}</p></div>)}</section>
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-center justify-between"><div><h2 className="font-semibold text-slate-950">Risk policy</h2><p className="mt-1 text-sm text-slate-500">High risk needs approval. Critical risk is rejected by default.</p></div><label className="flex items-center gap-2 text-sm"><input aria-label="Risk Engine" type="checkbox" checked={policyData.enabled} disabled={!canEdit || saving} onChange={(e) => void change("enabled", e.target.checked)} /> Enabled</label></div>
      <div className="mt-5 grid gap-4 sm:grid-cols-3">{(["medium", "high", "critical"] as const).map((level) => <label key={level} className="text-sm font-medium capitalize text-slate-700">{level} risk<select aria-label={`${level} risk action`} className="mt-2 w-full rounded-lg border border-slate-200 p-2.5" value={policyData[`${level}_action`]} disabled={!canEdit || saving} onChange={(e) => void change(`${level}_action`, e.target.value as RiskAction)}><option value="ALLOW">Allow</option><option value="REQUIRE_APPROVAL">Require approval</option><option value="REJECT">Reject</option></select></label>)}</div>{!canEdit && <p className="mt-4 text-sm text-slate-500">Your role can view this policy but cannot change it.</p>}</section>
    <section><h2 className="mb-4 text-lg font-semibold text-slate-950">Recent assessments</h2><div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm"><table className="w-full text-left text-sm"><thead className="border-b bg-slate-50 text-xs uppercase text-slate-500"><tr>{["Request ID","Agent","Action","Amount","Risk Score","Risk Level","Decision","Time"].map((h) => <th className="px-4 py-3" key={h}>{h}</th>)}</tr></thead><tbody>{assessments.data.items.map((item) => <tr key={item.id} className="border-b border-slate-100"><td className="px-4 py-3"><Link className="font-medium text-blue-700 hover:underline" href={`/dashboard/risk/${item.id}`}>{item.request_id}</Link></td><td className="px-4 py-3">{item.agent_name}</td><td className="px-4 py-3">{item.action}</td><td className="px-4 py-3">{formatMoney(item.amount, item.currency)}</td><td className="px-4 py-3 font-semibold">{item.risk_score}/100</td><td className="px-4 py-3"><span className="rounded-full bg-slate-100 px-2 py-1 text-xs font-semibold">{item.risk_level}</span></td><td className="px-4 py-3">{item.final_status}</td><td className="px-4 py-3 text-slate-500">{formatDate(item.created_at, true)}</td></tr>)}</tbody></table>{!assessments.data.items.length && <p className="p-8 text-center text-sm text-slate-500">No risk assessments yet.</p>}</div></section>
  </div>;
}
