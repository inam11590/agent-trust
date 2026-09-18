"use client";

import Link from "next/link";

import { StatusBadge, secondaryButtonClass } from "@/components/ui";
import { formatDate, formatMoney } from "@/lib/format";
import type { Agent, Permission } from "@/types";

export function PermissionsTable({ permissions, agents, onRevoke, revoking }: { permissions: Permission[]; agents: Agent[]; onRevoke?: (id: string) => void; revoking?: string }) {
  const names = new Map(agents.map((agent) => [agent.id, agent.name]));
  return <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm"><table className="w-full min-w-[1050px] text-left text-sm"><thead className="border-b border-slate-200 bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500"><tr><th className="px-5 py-3.5">Agent</th><th className="px-5 py-3.5">Action</th><th className="px-5 py-3.5">Resource</th><th className="px-5 py-3.5">Maximum</th><th className="px-5 py-3.5">Status</th><th className="px-5 py-3.5">Valid from</th><th className="px-5 py-3.5">Expires</th><th className="px-5 py-3.5"><span className="sr-only">Actions</span></th></tr></thead><tbody className="divide-y divide-slate-100">{permissions.map((permission) => <tr key={permission.id} className="hover:bg-slate-50"><td className="px-5 py-4 font-medium text-slate-900">{names.get(permission.agent_id) ?? "Unknown agent"}</td><td className="px-5 py-4">{permission.action}</td><td className="px-5 py-4">{permission.resource}</td><td className="px-5 py-4 font-medium">{formatMoney(permission.maximum_amount, permission.currency)}</td><td className="px-5 py-4"><StatusBadge value={permission.status} /></td><td className="px-5 py-4 whitespace-nowrap text-slate-500">{formatDate(permission.valid_from, true)}</td><td className="px-5 py-4 whitespace-nowrap text-slate-500">{formatDate(permission.expires_at, true)}</td><td className="px-5 py-4"><div className="flex justify-end gap-2"><Link className={secondaryButtonClass} href={`/dashboard/permissions/${permission.id}`}>View</Link>{onRevoke && permission.status === "active" && <button className="inline-flex h-10 items-center rounded-lg px-3 text-sm font-semibold text-red-600 hover:bg-red-50 disabled:opacity-50" disabled={revoking === permission.id} onClick={() => onRevoke(permission.id)}>{revoking === permission.id ? "Revoking…" : "Revoke"}</button>}</div></td></tr>)}</tbody></table></div>;
}
