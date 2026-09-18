"use client";

import { Bell, CheckCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { notificationHref } from "@/components/notification-bell";
import { EmptyState, ErrorState, LoadingState, PageHeader, secondaryButtonClass } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";
import type { Notification, PaginatedNotifications } from "@/types";

export default function NotificationsPage() {
  const router = useRouter();
  const [page, setPage] = useState(1);
  const query = useApiQuery<PaginatedNotifications>(`/notifications?page=${page}&page_size=20`);
  async function open(item: Notification) {
    if (item.status === "unread") await apiRequest(`/notifications/${item.id}/read`, { method: "POST" });
    router.push(notificationHref(item));
  }
  async function readAll() {
    await apiRequest("/notifications/read-all", { method: "POST" });
    query.reload();
  }
  return <div className="space-y-7">
    <PageHeader title="Notifications" description="Approval requests and important AgentTrust activity." action={<button onClick={() => void readAll()} className={secondaryButtonClass}><CheckCheck size={17} className="mr-2" />Mark all as read</button>} />
    {query.loading ? <LoadingState label="Loading notifications" /> : query.error ? <ErrorState message={query.error} retry={query.reload} /> : !query.data?.items.length ? <EmptyState title="No notifications" description="Important updates will appear here." /> : <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      {query.data.items.map((item) => <button key={item.id} onClick={() => void open(item)} className={`flex w-full gap-4 border-b border-slate-100 p-5 text-left hover:bg-slate-50 ${item.status === "unread" ? "bg-blue-50/40" : ""}`}>
        <span className={`mt-1 grid size-9 shrink-0 place-items-center rounded-full ${item.priority === "critical" || item.priority === "high" ? "bg-red-50 text-red-600" : "bg-blue-50 text-blue-700"}`}><Bell size={17} /></span>
        <span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><strong className="text-sm text-slate-950">{item.title}</strong><span className="rounded bg-slate-100 px-2 py-0.5 text-[10px] font-bold uppercase text-slate-600">{item.priority}</span>{item.status === "unread" && <span className="size-2 rounded-full bg-blue-600" aria-label="Unread" />}</span><span className="mt-1 block text-sm leading-6 text-slate-600">{item.message}</span><span className="mt-1 block text-xs text-slate-400">{item.type.replaceAll("_", " ")} · {formatDate(item.created_at, true)}</span></span>
      </button>)}
      <div className="flex items-center justify-between p-4"><button disabled={page <= 1} onClick={() => setPage((value) => value - 1)} className={secondaryButtonClass}>Previous</button><span className="text-xs text-slate-500">Page {query.data.page} of {Math.max(1, query.data.total_pages)}</span><button disabled={page >= query.data.total_pages} onClick={() => setPage((value) => value + 1)} className={secondaryButtonClass}>Next</button></div>
    </section>}
  </div>;
}
