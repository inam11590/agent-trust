"use client";

import Link from "next/link";
import { use, useEffect, useState } from "react";
import { ArrowLeft, Clock, Fingerprint, RotateCw, Server, ShieldAlert, ShieldCheck } from "lucide-react";

import { PageHeader } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

type GatewayProfile = {
  gateway_id: string;
  name: string;
  status: string;
  deployment_type: string;
  software_version: string;
  config_version: number;
  identity_fingerprint: string;
  last_seen_at: string | null;
  offline_age_seconds: number;
  recent_auth_failures: number;
  recent_replay_events: number;
};

export default function GatewaySecurityProfilePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { organization } = useAuth();
  const [profile, setProfile] = useState<GatewayProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadProfile() {
    setLoading(true);
    setError("");
    try {
      const q = organization?.id ? `?organization_id=${organization.id}` : "";
      const data = await apiRequest<GatewayProfile>(`/security/gateways/${id}/profile${q}`);
      setProfile(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load gateway profile.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProfile();
  }, [id, organization]);

  const isOffline = (profile?.offline_age_seconds ?? 0) > 300;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2">
            <Link href="/dashboard/security" className="text-xs font-medium text-slate-500 hover:text-slate-800 flex items-center gap-1">
              <ArrowLeft size={12} /> Back to Security Center
            </Link>
          </div>
          <PageHeader
            title={profile ? `Gateway Security Profile: ${profile.name}` : "Gateway Security Profile"}
            description={`Heartbeat health, identity fingerprints, and auth failure telemetry for Gateway ID: ${id}`}
          />
        </div>
        <button
          onClick={() => loadProfile()}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
        >
          <RotateCw size={15} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">
          {error}
        </div>
      )}

      {profile && (
        <>
          {/* Posture Overview */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Gateway Status</p>
              <div className="mt-2 flex items-center gap-2">
                <span className={`size-2.5 rounded-full ${isOffline ? "bg-rose-500" : "bg-emerald-500"}`} />
                <p className="text-xl font-bold text-slate-900 uppercase">{profile.status}</p>
              </div>
              <p className="mt-1 text-xs text-slate-500">{profile.deployment_type}</p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Offline Duration</p>
              <p className="mt-2 text-xl font-bold text-slate-900">{profile.offline_age_seconds}s</p>
              <p className="mt-1 text-xs text-slate-500">Last seen: {profile.last_seen_at ? formatDate(profile.last_seen_at) : "Never"}</p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Auth Failures</p>
              <p className="mt-2 text-xl font-bold text-slate-900">{profile.recent_auth_failures}</p>
              <p className="mt-1 text-xs text-slate-500">mTLS / token rejection count</p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <p className="text-xs font-semibold uppercase text-slate-400">Config Version</p>
              <p className="mt-2 text-xl font-bold text-slate-900">v{profile.config_version}</p>
              <p className="mt-1 text-xs text-slate-500">Software: v{profile.software_version}</p>
            </div>
          </div>

          {/* Cryptographic Identity Fingerprint */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
            <div className="flex items-center gap-2 text-slate-900 font-bold">
              <Fingerprint size={18} className="text-blue-600" /> Cryptographic Identity & Verification
            </div>
            <p className="text-xs text-slate-500">
              Deterministic sha256 identity fingerprint verified during mutual authentication and control plane registration.
            </p>
            <div className="rounded-lg bg-slate-50 p-3 border border-slate-200 font-mono text-xs text-slate-800 break-all">
              {profile.identity_fingerprint}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
