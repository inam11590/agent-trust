"use client";

import { FormEvent, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { ErrorState, Field, LoadingState, PageHeader, buttonClass, inputClass, secondaryButtonClass } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import type { Agent, Permission } from "@/types";
import { useAuth } from "@/contexts/auth-context";

function localInput(date: Date) {
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

export default function NewPermissionPage() {
  const { role = "owner" } = useAuth();
  const router = useRouter();
  const agents = useApiQuery<Agent[]>("/agents");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const defaults = useMemo(() => {
    const now = new Date();
    return { start: localInput(now), end: localInput(new Date(now.getTime() + 86_400_000)) };
  }, []);
  if (role !== "owner" && role !== "admin") return <ErrorState message="This workspace is read-only for your role." />;
  if (agents.loading) return <LoadingState label="Loading agents" />;
  if (agents.error) return <ErrorState message={agents.error} retry={agents.reload} />;
  if (!agents.data?.length) return <div className="space-y-6"><PageHeader title="Create Permission" /><ErrorState message="Create an agent before adding a permission." /></div>;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const amount = String(form.get("maximum_amount")).trim();
    const currency = String(form.get("currency")).trim();
    const validFrom = new Date(String(form.get("valid_from")));
    const expiresAt = new Date(String(form.get("expires_at")));
    if (amount && Number(amount) <= 0) { setError("Maximum amount must be greater than zero."); return; }
    if (expiresAt <= validFrom) { setError("Expiry must be after the start time."); return; }
    setLoading(true); setError("");
    try {
      const permission = await apiRequest<Permission>("/permissions", { method: "POST", body: JSON.stringify({
        agent_id: String(form.get("agent_id")), action: String(form.get("action")), resource: String(form.get("resource")),
        maximum_amount: amount || null, currency: amount ? currency : null,
        valid_from: validFrom.toISOString(), expires_at: expiresAt.toISOString(),
      }) });
      router.push(`/dashboard/permissions/${permission.id}?created=1`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to create permission."); }
    finally { setLoading(false); }
  }

  return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Create Permission" description="Give one agent a specific capability for a limited time." /><form onSubmit={submit} className="grid gap-5 rounded-xl border border-slate-200 bg-white p-6 shadow-sm sm:grid-cols-2">{error && <div role="alert" className="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 sm:col-span-2">{error}</div>}<div className="sm:col-span-2"><Field label="Agent"><select name="agent_id" required className={inputClass} defaultValue=""><option value="" disabled>Select an agent</option>{agents.data.map((agent) => <option key={agent.id} value={agent.id}>{agent.name} · {agent.agent_identifier}</option>)}</select></Field></div><Field label="Action"><input name="action" required className={inputClass} placeholder="purchase" pattern="[a-z][a-z0-9:_-]*" /></Field><Field label="Resource"><input name="resource" required className={inputClass} placeholder="flight" pattern="[a-z][a-z0-9:_-]*" /></Field><Field label="Maximum amount"><input name="maximum_amount" type="number" min="0.0001" step="0.0001" className={inputClass} placeholder="500" /></Field><Field label="Currency"><input name="currency" className={inputClass} defaultValue="USD" maxLength={3} pattern="[A-Za-z]{3}" /></Field><Field label="Valid from"><input name="valid_from" required type="datetime-local" className={inputClass} defaultValue={defaults.start} /></Field><Field label="Expires at"><input name="expires_at" required type="datetime-local" className={inputClass} defaultValue={defaults.end} /></Field><div className="flex justify-end gap-3 border-t border-slate-100 pt-5 sm:col-span-2"><Link href="/dashboard/permissions" className={secondaryButtonClass}>Cancel</Link><button disabled={loading} className={buttonClass}>{loading ? "Creating…" : "Create Permission"}</button></div></form></div>;
}
