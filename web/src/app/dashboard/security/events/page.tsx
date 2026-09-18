"use client";

import { useEffect, useState } from "react";

import { PageHeader, inputClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

type Event = { id: string; actor_user_id: string | null; actor_name: string | null; event_type: string; severity: string; description: string | null; created_at: string };
type Page = { items: Event[]; page: number; page_size: number; total: number };

export default function SecurityEventsPage() {
  const { organization, role } = useAuth();
  const [scope, setScope] = useState("personal");
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");
  const [actor, setActor] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Page | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const query = new URLSearchParams({ page: String(page), page_size: "20" });
    if (scope === "organization" && organization) query.set("organization_id", organization.id);
    if (type) query.set("event_type", type);
    if (severity) query.set("severity", severity);
    if (actor) query.set("actor_user_id", actor);
    if (fromDate) query.set("from_date", new Date(fromDate).toISOString());
    if (toDate) query.set("to_date", new Date(`${toDate}T23:59:59`).toISOString());
    apiRequest<Page>(`/security/events?${query}`).then((value) => { setData(value); setError(""); })
      .catch((reason: Error) => setError(reason.message));
  }, [organization, scope, type, severity, actor, fromDate, toDate, page]);
  return <div className="space-y-5"><PageHeader title="Security events" description="Private account and organization security history." />
    <div className="grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-3 lg:grid-cols-6">
      <select className={inputClass} aria-label="Scope" value={scope} onChange={(event) => { setScope(event.target.value); setPage(1); }}><option value="personal">My account</option>{organization && ["owner", "admin"].includes(role) && <option value="organization">{organization.name}</option>}</select>
      <input className={inputClass} aria-label="Event type" value={type} onChange={(event) => { setType(event.target.value); setPage(1); }} placeholder="Event type" />
      <select className={inputClass} aria-label="Severity" value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(1); }}><option value="">All severity</option><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option></select>
      <input className={inputClass} aria-label="User ID" value={actor} onChange={(event) => { setActor(event.target.value); setPage(1); }} placeholder="User ID" />
      <input className={inputClass} aria-label="From date" type="date" value={fromDate} onChange={(event) => { setFromDate(event.target.value); setPage(1); }} />
      <input className={inputClass} aria-label="To date" type="date" value={toDate} onChange={(event) => { setToDate(event.target.value); setPage(1); }} />
    </div>
    {error && <p role="alert" className="text-red-700">{error}</p>}
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white"><table className="w-full text-left text-sm"><thead className="bg-slate-50 text-slate-500"><tr><th className="p-3">Event</th><th className="p-3">User</th><th className="p-3">Severity</th><th className="p-3">Time</th></tr></thead><tbody>{data?.items.map((item) => <tr key={item.id} className="border-t border-slate-100"><td className="p-3"><p className="font-medium">{item.event_type.replaceAll("_", " ")}</p><p className="text-slate-500">{item.description}</p></td><td className="p-3 text-slate-600">{item.actor_name ?? item.actor_user_id ?? "System"}</td><td className="p-3 capitalize">{item.severity}</td><td className="p-3 text-slate-600">{formatDate(item.created_at)}</td></tr>)}</tbody></table>{data?.items.length === 0 && <p className="p-4 text-sm text-slate-500">No events match these filters.</p>}</div>
    <div className="flex items-center justify-between text-sm"><p>{data?.total ?? 0} events</p><div className="flex gap-3"><button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page}</span><button disabled={!data || page * data.page_size >= data.total} onClick={() => setPage(page + 1)}>Next</button></div></div>
  </div>;
}

