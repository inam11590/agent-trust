"use client";

import { Bell } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { apiRequest } from "@/lib/api/client";
import { useApiQuery } from "@/hooks/use-api-query";
import type { Notification, PaginatedNotifications } from "@/types";

export function notificationHref(item: Notification): string {
  if (item.related_request_id) return `/dashboard/authorization-requests/${item.related_request_id}`;
  if (item.related_permission_id) return `/dashboard/permissions/${item.related_permission_id}`;
  if (item.related_agent_id) return "/dashboard/agents";
  return "/dashboard/notifications";
}

export function NotificationBell() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const counter = useApiQuery<{ count: number }>("/notifications/unread-count");
  const latest = useApiQuery<PaginatedNotifications>("/notifications?page=1&page_size=5");
  const count = counter.data?.count ?? 0;
  const items = latest.data?.items ?? [];
  const reloadCounter = counter.reload;
  const reloadLatest = latest.reload;
  useEffect(() => {
    if (typeof EventSource === "undefined") return;
    const stream = new EventSource("/api/backend/notifications/stream");
    stream.addEventListener("notifications", () => { reloadCounter(); reloadLatest(); });
    return () => stream.close();
  }, [reloadCounter, reloadLatest]);
  async function openItem(item: Notification) {
    if (item.status === "unread") {
      await apiRequest(`/notifications/${item.id}/read`, { method: "POST" });
      counter.reload(); latest.reload();
    }
    setOpen(false); router.push(notificationHref(item));
  }
  return <div className="relative">
    <button aria-label={`Notifications, ${count} unread`} onClick={() => setOpen((value) => !value)} className="relative rounded-lg border border-slate-200 bg-white p-2.5 text-slate-600 hover:bg-slate-50"><Bell size={19} />{count > 0 && <span className="absolute -right-1.5 -top-1.5 min-w-5 rounded-full bg-red-600 px-1 text-center text-[10px] font-bold leading-5 text-white">{count > 99 ? "99+" : count}</span>}</button>
    {open && <div className="absolute right-0 top-12 z-50 w-[min(24rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl"><div className="flex items-center justify-between border-b border-slate-100 px-4 py-3"><p className="font-semibold text-slate-900">Notifications</p><Link href="/dashboard/notifications" onClick={() => setOpen(false)} className="text-xs font-semibold text-blue-700">View all</Link></div><div className="max-h-96 overflow-y-auto">{items.length === 0 ? <p className="px-4 py-8 text-center text-sm text-slate-500">No notifications yet.</p> : items.map((item) => <button key={item.id} onClick={() => void openItem(item)} className={`block w-full border-b border-slate-100 px-4 py-3 text-left hover:bg-slate-50 ${item.status === "unread" ? "bg-blue-50/50" : ""}`}><span className="block text-sm font-semibold text-slate-900">{item.title}</span><span className="mt-1 block line-clamp-2 text-xs leading-5 text-slate-600">{item.message}</span></button>)}</div></div>}
  </div>;
}
