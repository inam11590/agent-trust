"use client";

import { FormEvent, useState } from "react";
import { CheckCircle2, Copy } from "lucide-react";
import Link from "next/link";

import { ErrorState, Field, PageHeader, buttonClass, inputClass, secondaryButtonClass, textareaClass } from "@/components/ui";
import { apiRequest } from "@/lib/api/client";
import type { Agent } from "@/types";
import { useAuth } from "@/contexts/auth-context";

export default function NewAgentPage() {
  const { role = "owner" } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<Agent | null>(null);

  if (role !== "owner" && role !== "admin") return <ErrorState message="This workspace is read-only for your role." />;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError("");
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    try {
      setCreated(await apiRequest<Agent>("/agents", { method: "POST", body: JSON.stringify({ name: String(form.get("name")), description: String(form.get("description")) || null }) }));
      formElement.reset();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to create agent."); }
    finally { setLoading(false); }
  }

  if (created) return <div className="mx-auto max-w-2xl"><div className="rounded-2xl border border-emerald-200 bg-white p-8 text-center shadow-sm"><span className="mx-auto grid size-14 place-items-center rounded-full bg-emerald-50 text-emerald-600"><CheckCircle2 size={28} /></span><h1 className="mt-5 text-2xl font-semibold text-slate-950">Agent created successfully</h1><p className="mt-2 text-sm text-slate-500">Save this public Agent ID for API requests.</p><button onClick={() => navigator.clipboard.writeText(created.agent_identifier)} className="mx-auto mt-6 flex items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-5 py-4 font-mono text-sm font-semibold text-slate-800 hover:bg-slate-100">{created.agent_identifier}<Copy size={16} /></button><div className="mt-7 flex justify-center gap-3"><Link className={secondaryButtonClass} href="/dashboard/agents">All agents</Link><Link className={buttonClass} href={`/dashboard/agents/${created.agent_identifier}`}>View agent</Link></div></div></div>;

  return <div className="mx-auto max-w-2xl space-y-7"><PageHeader title="Create Agent" description="Register a new software identity under your account." /><form onSubmit={submit} className="space-y-5 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">{error && <div role="alert" className="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}<Field label="Agent name"><input name="name" className={inputClass} required maxLength={200} placeholder="Travel Assistant" /></Field><Field label="Description" hint="Explain what this agent is expected to do."><textarea name="description" className={textareaClass} maxLength={2000} placeholder="Helps plan and purchase approved travel." /></Field><div className="flex justify-end gap-3 border-t border-slate-100 pt-5"><Link href="/dashboard/agents" className={secondaryButtonClass}>Cancel</Link><button className={buttonClass} disabled={loading}>{loading ? "Creating…" : "Create Agent"}</button></div></form></div>;
}
