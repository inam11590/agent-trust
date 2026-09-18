"use client";

import { useState } from "react";
import { Check, CreditCard } from "lucide-react";
import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { ErrorState, LoadingState, PageHeader, buttonClass, secondaryButtonClass } from "@/components/ui";
import type { BillingPlan, BillingSubscription, BillingUsage } from "@/types";

export default function BillingPage() {
  const { organization } = useAuth();
  if (!organization) return <div className="mx-auto max-w-2xl space-y-6"><PageHeader title="Billing" description="Plans and usage belong to an organization." /><div className="rounded-xl border border-slate-200 bg-white p-7 shadow-sm"><CreditCard className="text-blue-600" /><h2 className="mt-4 text-lg font-semibold">Select or create an organization</h2><p className="mt-2 text-sm text-slate-600">Use the workspace selector above, then return here to see its plan and limits.</p></div></div>;
  return <OrganizationBilling />;
}

function OrganizationBilling() {
  const { role } = useAuth();
  const plans = useApiQuery<BillingPlan[]>("/billing/plans");
  const subscription = useApiQuery<BillingSubscription>("/billing/subscription");
  const usage = useApiQuery<BillingUsage>("/billing/usage");
  const [busy, setBusy] = useState(""); const [error, setError] = useState("");
  const canManage = role === "owner" || role === "admin";
  if (plans.loading || subscription.loading || usage.loading) return <LoadingState label="Loading billing" />;
  if (plans.error || subscription.error || usage.error) return <ErrorState message={plans.error ?? subscription.error ?? usage.error ?? "Unable to load billing."} retry={() => { plans.reload(); subscription.reload(); usage.reload(); }} />;
  async function navigate(path: "/billing/checkout" | "/billing/portal", body?: object) {
    setBusy(path); setError("");
    try {
      const result = await apiRequest<{checkout_url?: string; portal_url?: string}>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
      const target = result.checkout_url ?? result.portal_url;
      if (!target) throw new Error("Billing link was unavailable.");
      const url = new URL(target, window.location.origin);
      if (!["http:", "https:"].includes(url.protocol)) throw new Error("Billing link was unsafe.");
      window.location.assign(url.href);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to open billing."); setBusy(""); }
  }
  async function cancelPlan() {
    if (!window.confirm("Cancel at the end of the current billing period? Existing data will be kept.")) return;
    setBusy("cancel"); setError("");
    try { await apiRequest("/billing/cancel", { method: "POST" }); subscription.reload(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to cancel subscription."); }
    finally { setBusy(""); }
  }
  const labels: Record<string,string> = { authorization_requests: "Authorization requests", agents: "Agents", api_keys: "API keys", team_members: "Team members", webhooks: "Webhooks" };
  return <div className="space-y-8"><PageHeader title="Billing & usage" description="Review your organization plan and current monthly limits." action={canManage && subscription.data?.plan.code !== "free" ? <button className={secondaryButtonClass} onClick={() => navigate("/billing/portal")}>Manage billing</button> : undefined} />
    {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
    <section className="rounded-xl border border-blue-100 bg-gradient-to-br from-blue-50 to-white p-6 shadow-sm"><p className="text-xs font-bold uppercase tracking-wider text-blue-700">Current plan</p><div className="mt-2 flex flex-wrap items-end justify-between gap-4"><div><h2 className="text-3xl font-semibold text-slate-950">{subscription.data?.plan.name}</h2><p className="mt-1 text-sm capitalize text-slate-600">{subscription.data?.status.replace("_", " ")}{subscription.data?.cancel_at_period_end ? " · cancels at period end" : ""}</p></div>{role === "owner" && subscription.data?.plan.code !== "free" && <button className="text-sm font-semibold text-red-600" disabled={busy === "cancel"} onClick={cancelPlan}>Cancel plan</button>}</div></section>
    <section><h2 className="text-lg font-semibold">This month</h2><div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">{Object.entries(usage.data?.usage ?? {}).map(([key,item]) => { const pct = item.limit ? Math.min(100, Math.round(item.used * 100 / item.limit)) : 0; return <div key={key} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex justify-between text-sm"><span className="font-medium">{labels[key] ?? key}</span><span>{item.used.toLocaleString()} / {item.limit?.toLocaleString() ?? "Unlimited"}</span></div><div className="mt-3 h-2 overflow-hidden rounded bg-slate-100"><div className={`${pct >= 90 ? "bg-red-500" : pct >= 80 ? "bg-amber-500" : "bg-blue-600"} h-full`} style={{width: `${item.limit ? pct : 0}%`}} /></div></div>; })}</div></section>
    <section><h2 className="text-lg font-semibold">Plans</h2><div className="mt-4 grid gap-5 lg:grid-cols-4">{plans.data?.map(plan => <article key={plan.id} className={`rounded-xl border bg-white p-5 shadow-sm ${plan.code === subscription.data?.plan.code ? "border-blue-400 ring-2 ring-blue-100" : "border-slate-200"}`}><h3 className="text-lg font-semibold">{plan.name}</h3><p className="mt-1 min-h-10 text-sm text-slate-500">{plan.description}</p><p className="mt-5 text-2xl font-bold">{plan.monthly_price === null ? "Custom" : `$${Number(plan.monthly_price).toLocaleString()}`}<span className="text-sm font-normal text-slate-500">{plan.monthly_price !== null && "/month"}</span></p><ul className="mt-5 space-y-2 text-sm text-slate-600"><li className="flex gap-2"><Check size={16} /> {plan.max_agents ?? "Unlimited"} agents</li><li className="flex gap-2"><Check size={16} /> {(plan.max_authorization_requests_monthly ?? "Unlimited").toLocaleString()} requests/month</li><li className="flex gap-2"><Check size={16} /> {plan.max_api_keys ?? "Unlimited"} API keys</li></ul>{canManage && ["starter","business"].includes(plan.code) && plan.code !== subscription.data?.plan.code && <button className={`${buttonClass} mt-6 w-full`} disabled={!!busy} onClick={() => navigate("/billing/checkout", { plan_code: plan.code })}>{busy ? "Opening…" : `Choose ${plan.name}`}</button>}{plan.code === "enterprise" && <p className="mt-6 text-center text-sm font-semibold text-blue-700">Contact sales</p>}</article>)}</div></section>
  </div>;
}
