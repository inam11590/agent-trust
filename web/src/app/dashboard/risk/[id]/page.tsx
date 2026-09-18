"use client";

import { useParams } from "next/navigation";
import { ErrorState, LoadingState, PageHeader, StatusBadge } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { formatDate, formatMoney } from "@/lib/format";
import type { RiskAssessment } from "@/types";

export default function RiskDetailPage() {
  const id = String(useParams().id);
  const query = useApiQuery<RiskAssessment>(`/risk/assessments/${id}`);
  if (query.loading) return <LoadingState label="Loading risk assessment" />;
  if (query.error || !query.data) return <ErrorState message={query.error ?? "Risk assessment not found."} retry={query.reload} />;
  const item = query.data;
  return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Risk Assessment" description="A simple explanation of this request's risk score." /><section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex justify-between gap-4"><div><p className="text-4xl font-semibold text-slate-950">{item.risk_score}<span className="text-lg text-slate-400">/100</span></p><p className="mt-1 font-semibold">{item.risk_level} RISK</p></div><StatusBadge value={item.final_status} /></div><div className="mt-6 rounded-lg bg-slate-50 p-5"><h2 className="font-semibold text-slate-900">Why</h2><ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-700">{item.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></div><dl className="mt-6 grid gap-5 sm:grid-cols-2"><Detail label="Request ID" value={item.request_id} /><Detail label="Agent" value={item.agent_name} /><Detail label="Action" value={`${item.action} ${item.resource}`} /><Detail label="Amount" value={formatMoney(item.amount, item.currency)} /><Detail label="Recommendation" value={item.recommendation.replaceAll("_", " ")} /><Detail label="Time" value={formatDate(item.created_at, true)} /></dl></section></div>;
}
function Detail({ label, value }: { label: string; value: string }) { return <div><dt className="text-xs font-semibold uppercase text-slate-400">{label}</dt><dd className="mt-1 text-sm font-medium text-slate-800">{value}</dd></div>; }
