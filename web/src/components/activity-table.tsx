import Link from "next/link";

import { StatusBadge } from "@/components/ui";
import { formatDate, formatMoney } from "@/lib/format";
import type { Agent, AuditLog } from "@/types";

export function ActivityTable({ logs, agents }: { logs: AuditLog[]; agents: Agent[] }) {
  const names = new Map(agents.map((agent) => [agent.agent_identifier, agent.name]));
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
      <table className="w-full min-w-[760px] text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50/80 text-[11px] font-semibold uppercase tracking-wider text-slate-500"><tr><th className="px-5 py-3.5">Agent</th><th className="px-5 py-3.5">Action</th><th className="px-5 py-3.5">Resource</th><th className="px-5 py-3.5">Amount</th><th className="px-5 py-3.5">Decision</th><th className="px-5 py-3.5">Time</th></tr></thead>
        <tbody className="divide-y divide-slate-100">
          {logs.map((log) => <tr key={log.id} className="transition hover:bg-slate-50"><td className="px-5 py-4 font-medium text-slate-900"><Link href={`/dashboard/audit-logs/${log.id}`} className="hover:text-[#3157d5]">{names.get(log.agent_identifier) ?? log.agent_identifier}</Link></td><td className="px-5 py-4 text-slate-600">{log.action}</td><td className="px-5 py-4 text-slate-600">{log.resource}</td><td className="px-5 py-4 font-medium text-slate-700">{formatMoney(log.amount, log.currency)}</td><td className="px-5 py-4"><StatusBadge value={log.decision} /></td><td className="px-5 py-4 whitespace-nowrap text-slate-500">{formatDate(log.requested_at, true)}</td></tr>)}
        </tbody>
      </table>
    </div>
  );
}
