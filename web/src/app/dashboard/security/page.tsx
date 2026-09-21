"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  BadgeAlert,
  CheckCircle2,
  Clock,
  ExternalLink,
  Filter,
  KeyRound,
  Lock,
  Radio,
  Repeat,
  RotateCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";

import { PageHeader, buttonClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";

type SOCStats = {
  security_status: string;
  total_events: number;
  critical_alerts: number;
  high_alerts: number;
  denied_actions: number;
  replay_attempts: number;
  invalid_signatures: number;
  revoked_credential_usage: number;
  trust_violations: number;
  gateway_problems: number;
  high_risk_actions: number;
  admin_security_changes: number;
  window_hours: number;
};

export default function SecurityCenterPage() {
  const { organization } = useAuth();
  const [windowHours, setWindowHours] = useState(24);
  const [stats, setStats] = useState<SOCStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadData() {
    setLoading(true);
    setError("");
    try {
      const q = new URLSearchParams({ window_hours: String(windowHours) });
      if (organization?.id) q.set("organization_id", organization.id);
      const res = await apiRequest<SOCStats>(`/security/overview?${q}`);
      setStats(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load SOC overview.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [organization, windowHours]);

  const isCritical = (stats?.critical_alerts ?? 0) > 0;
  const isElevated = (stats?.high_alerts ?? 0) > 0 || (stats?.denied_actions ?? 0) > 10;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <PageHeader
            title="Security Center (SOC)"
            description="Real-time observability, autonomous agent threat detection, and incident response."
          />
        </div>
        <div className="flex items-center gap-3">
          <select
            value={windowHours}
            onChange={(e) => setWindowHours(Number(e.target.value))}
            className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm"
          >
            <option value={1}>Last 1 hour</option>
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={168}>Last 7 days</option>
            <option value={720}>Last 30 days</option>
          </select>
          <button
            onClick={() => loadData()}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
          >
            <RotateCw size={15} className={loading ? "animate-spin" : ""} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">
          {error}
        </div>
      )}

      {/* Security Posture Status Banner */}
      <div
        className={`flex flex-col gap-4 rounded-xl border p-5 sm:flex-row sm:items-center sm:justify-between ${
          isCritical
            ? "border-rose-300 bg-rose-50 text-rose-950"
            : isElevated
            ? "border-amber-300 bg-amber-50 text-amber-950"
            : "border-emerald-200 bg-emerald-50 text-emerald-950"
        }`}
      >
        <div className="flex items-center gap-3">
          {isCritical ? (
            <AlertOctagon className="size-8 text-rose-600" />
          ) : isElevated ? (
            <AlertTriangle className="size-8 text-amber-600" />
          ) : (
            <CheckCircle2 className="size-8 text-emerald-600" />
          )}
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold">
                Security Posture:{" "}
                {stats?.security_status === "CRITICAL"
                  ? "Critical Threat Detected"
                  : stats?.security_status === "ELEVATED"
                  ? "Elevated Risk Actions"
                  : "All Systems Normal"}
              </h2>
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-bold uppercase ${
                  isCritical
                    ? "bg-rose-200 text-rose-800"
                    : isElevated
                    ? "bg-amber-200 text-amber-800"
                    : "bg-emerald-200 text-emerald-800"
                }`}
              >
                {stats?.security_status ?? "OPERATIONAL"}
              </span>
            </div>
            <p className="text-xs opacity-90">
              {stats?.total_events ?? 0} total events processed in the last {windowHours}h. Zero raw customer prompts
              or business payloads stored.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Link
            href="/dashboard/security/alerts"
            className="flex items-center gap-1.5 rounded-lg bg-white px-3.5 py-2 text-sm font-semibold text-slate-800 shadow-sm hover:bg-slate-50"
          >
            Triage Alerts ({stats?.critical_alerts ?? 0} Critical) <ArrowRight size={14} />
          </Link>
        </div>
      </div>

      {/* Quick Navigation Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Link
          href="/dashboard/security/alerts"
          className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-slate-300 hover:shadow"
        >
          <div className="grid size-10 place-items-center rounded-lg bg-rose-50 text-rose-600">
            <BadgeAlert size={20} />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500">Security Alerts</p>
            <p className="text-lg font-bold text-slate-900">
              {(stats?.critical_alerts ?? 0) + (stats?.high_alerts ?? 0)} Open
            </p>
          </div>
        </Link>

        <Link
          href="/dashboard/security/events"
          className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-slate-300 hover:shadow"
        >
          <div className="grid size-10 place-items-center rounded-lg bg-blue-50 text-blue-600">
            <Radio size={20} />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500">Event Explorer</p>
            <p className="text-lg font-bold text-slate-900">{stats?.total_events ?? 0} Events</p>
          </div>
        </Link>

        <Link
          href="/dashboard/security/hardening"
          className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-slate-300 hover:shadow"
        >
          <div className="grid size-10 place-items-center rounded-lg bg-emerald-50 text-emerald-600">
            <Lock size={20} />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500">KMS & Hardening</p>
            <p className="text-lg font-bold text-slate-900">Step 25 Active</p>
          </div>
        </Link>

        <Link
          href="/dashboard/security/organization"
          className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-slate-300 hover:shadow"
        >
          <div className="grid size-10 place-items-center rounded-lg bg-purple-50 text-purple-600">
            <Shield size={20} />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500">Org Policies & MFA</p>
            <p className="text-lg font-bold text-slate-900">Enforced</p>
          </div>
        </Link>
      </div>

      {/* Security Operations Metric Grid */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Denied Agent Actions</p>
            <ShieldAlert size={18} className="text-rose-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.denied_actions ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">Blocked by authorization & risk engine</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Replay Attack Attempts</p>
            <Repeat size={18} className="text-amber-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.replay_attempts ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">Nonce reuse or timestamp skew</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Invalid Signatures</p>
            <KeyRound size={18} className="text-indigo-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.invalid_signatures ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">Cryptographic verification failures</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Revoked Credential Usage</p>
            <AlertOctagon size={18} className="text-red-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.revoked_credential_usage ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">ATC/1.0 used post-revocation</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Trust Violations</p>
            <BadgeAlert size={18} className="text-orange-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.trust_violations ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">Unauthorized cross-org calls</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Gateway Problems</p>
            <Server size={18} className="text-yellow-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.gateway_problems ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">Auth failures, offline, or rollback</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">High-Risk Agent Actions</p>
            <Zap size={18} className="text-purple-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.high_risk_actions ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">Scored High or Critical by risk engine</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">Admin Security Changes</p>
            <Clock size={18} className="text-blue-600" />
          </div>
          <p className="mt-2 text-3xl font-extrabold text-slate-900">{stats?.admin_security_changes ?? 0}</p>
          <p className="mt-1 text-xs text-slate-500">MFA, SSO, or role modifications</p>
        </div>
      </div>
    </div>
  );
}
