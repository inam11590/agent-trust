"use client";

import { Bell, Mail, UserRound } from "lucide-react";
import { useEffect, useState } from "react";
import { ErrorState, LoadingState, PageHeader, StatusBadge, buttonClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";
import type { NotificationPreferences } from "@/types";

const controls: Array<[keyof NotificationPreferences, string, string]> = [
  ["push_enabled", "Push notifications", "Allow notifications on registered phones."],
  ["email_enabled", "Email notifications", "Allow important messages by email."],
  ["approval_push_enabled", "Approval push alerts", "Alert your phone when an agent needs approval."],
  ["approval_email_enabled", "Approval email alerts", "Email important approval requests."],
  ["security_email_enabled", "Security alerts", "Email important account and key security changes."],
  ["permission_expiry_enabled", "Permission expiry alerts", "Warn before permissions expire."],
  ["general_activity_enabled", "General activity", "Show normal AgentTrust activity."],
];

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const [preferences, setPreferences] = useState<NotificationPreferences | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { apiRequest<NotificationPreferences>("/notification-preferences").then(setPreferences).catch((reason: Error) => setError(reason.message)); }, []);
  async function toggle(key: keyof NotificationPreferences) {
    if (!preferences || typeof preferences[key] !== "boolean") return;
    const updated = await apiRequest<NotificationPreferences>("/notification-preferences", { method: "PATCH", body: JSON.stringify({ [key]: !preferences[key] }) });
    setPreferences(updated);
  }
  return <div className="mx-auto max-w-3xl space-y-7"><PageHeader title="Settings" description="Your account and notification choices." /><section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-center gap-4 border-b border-slate-100 pb-6"><span className="grid size-12 place-items-center rounded-full bg-blue-50 text-[#3157d5]"><UserRound /></span><div><h2 className="font-semibold text-slate-950">{user.full_name}</h2><p className="text-sm text-slate-500">Member since {formatDate(user.created_at)}</p></div></div><dl className="mt-2 divide-y divide-slate-100"><div className="flex items-center justify-between py-5"><div className="flex items-center gap-3"><Mail size={18} className="text-slate-400" /><div><dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">Email</dt><dd className="mt-1 text-sm font-medium text-slate-800">{user.email}</dd></div></div></div><div className="flex items-center justify-between py-5"><div><dt className="text-xs font-semibold uppercase tracking-wide text-slate-400">Account status</dt><dd className="mt-2"><StatusBadge value={user.is_active ? "ACTIVE" : "INACTIVE"} /></dd></div></div></dl></section><section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="mb-5 flex items-center gap-3"><Bell className="text-blue-700" /><div><h2 className="font-semibold text-slate-950">Notifications</h2><p className="text-sm text-slate-500">Choose which useful alerts AgentTrust sends.</p></div></div>{error ? <ErrorState message={error} /> : !preferences ? <LoadingState label="Loading preferences" /> : <div className="divide-y divide-slate-100">{controls.map(([key, label, description]) => <label key={key} className="flex cursor-pointer items-center justify-between gap-5 py-4"><span><span className="block text-sm font-semibold text-slate-800">{label}</span><span className="mt-1 block text-xs text-slate-500">{description}</span></span><input type="checkbox" aria-label={label} checked={Boolean(preferences[key])} onChange={() => void toggle(key)} className="size-5 accent-blue-600" /></label>)}</div>}</section><button onClick={logout} className={`${buttonClass} bg-slate-800 hover:bg-slate-900`}>Log out</button></div>;
}
