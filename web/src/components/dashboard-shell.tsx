"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { BadgeCheck, Bot, Braces, ChevronDown, CreditCard, FileClock, GitFork, KeyRound, LayoutDashboard, LogOut, Menu, Network, Server, Settings, ShieldAlert, ShieldCheck, Users, Waypoints, X } from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { NotificationBell } from "@/components/notification-bell";

const navigation = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/dashboard/gateway", label: "Protocol Gateway", icon: Waypoints },
  { href: "/dashboard/gateways", label: "Enterprise Gateways", icon: Server },
  { href: "/dashboard/agents", label: "My Agents", icon: Bot },
  { href: "/dashboard/permissions", label: "Permissions", icon: KeyRound },
  { href: "/dashboard/delegations", label: "Delegations", icon: GitFork },
  { href: "/dashboard/trust", label: "Partner Trust", icon: Network },
  { href: "/dashboard/trust-registry", label: "Trust Registry", icon: BadgeCheck },
  { href: "/dashboard/audit-logs", label: "Audit Logs", icon: FileClock },
  { href: "/dashboard/risk", label: "Risk", icon: ShieldAlert },
  { href: "/dashboard/developers", label: "Developers", icon: Braces },
  { href: "/dashboard/team", label: "Team", icon: Users },
  { href: "/dashboard/billing", label: "Billing", icon: CreditCard },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
  { href: "/dashboard/security", label: "Security", icon: ShieldCheck },
];

export function DashboardShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { user, organizations = [], organization = null, role = "owner", switchOrganization = () => undefined, logout } = useAuth();
  const [open, setOpen] = useState(false);

  const sidebar = (
    <>
      <div className="flex h-20 items-center border-b border-white/10 px-5">
        <Link href="/dashboard" className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-xl bg-[#4168e8] text-white"><ShieldCheck size={20} /></span>
          <span className="text-lg font-semibold tracking-tight text-white">AgentTrust</span>
        </Link>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-5" aria-label="Main navigation">
        <p className="px-3 pb-2 text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">Workspace</p>
        {navigation.filter((item) => item.label !== "Developers" || role !== "viewer").map((item) => {
          const active = item.href === "/dashboard" ? pathname === item.href : pathname.startsWith(item.href);
          return (
            <Link key={item.href} href={item.href} onClick={() => setOpen(false)} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition ${active ? "bg-white/10 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-100"}`}>
              <item.icon size={18} /> {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-white/10 p-3">
        <div className="mb-2 flex items-center gap-3 rounded-lg px-3 py-2.5">
          <span className="grid size-9 shrink-0 place-items-center rounded-full bg-blue-100 text-sm font-bold text-blue-700">{user.full_name.slice(0, 1).toUpperCase()}</span>
          <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium text-white">{user.full_name}</p><p className="truncate text-xs text-slate-500">{user.email}</p></div>
          <ChevronDown size={15} className="text-slate-500" />
        </div>
        <button onClick={logout} className="flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-slate-400 transition hover:bg-white/5 hover:text-white"><LogOut size={17} /> Log out</button>
      </div>
    </>
  );

  const current = navigation.find((item) => item.href === "/dashboard" ? pathname === item.href : pathname.startsWith(item.href));
  return (
    <div className="min-h-screen bg-[#f6f8fb]">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 flex-col bg-[#101b35] lg:flex">{sidebar}</aside>
      {open && <div className="fixed inset-0 z-50 lg:hidden"><button aria-label="Close menu" className="absolute inset-0 bg-slate-950/50" onClick={() => setOpen(false)} /><aside className="relative flex h-full w-72 flex-col bg-[#101b35] shadow-2xl">{sidebar}<button aria-label="Close menu" onClick={() => setOpen(false)} className="absolute right-4 top-6 text-slate-400"><X /></button></aside></div>}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 flex h-20 items-center justify-between border-b border-slate-200 bg-white/95 px-5 backdrop-blur sm:px-8">
          <div className="flex items-center gap-3"><button aria-label="Open menu" onClick={() => setOpen(true)} className="rounded-lg p-2 text-slate-600 hover:bg-slate-100 lg:hidden"><Menu /></button><div><p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400">AgentTrust</p><p className="font-semibold text-slate-900">{current?.label ?? "Workspace"}</p></div></div>
          <div className="flex items-center gap-3">
            <NotificationBell />
            <select aria-label="Organization" value={organization?.id ?? ""} onChange={(event) => switchOrganization(event.target.value || null)} className="max-w-48 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700">
              <option value="">Personal Workspace</option>
              {organizations.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.role}</option>)}
            </select>
            <div className="hidden items-center gap-3 sm:flex"><span className="size-2 rounded-full bg-emerald-500" /><span className="text-xs font-medium text-slate-500">Systems operational</span></div>
          </div>
        </header>
        <main className="mx-auto max-w-[1500px] p-5 sm:p-8">{children}</main>
      </div>
    </div>
  );
}
