"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  Activity,
  AlertOctagon,
  ArrowLeft,
  CheckCircle2,
  Clock,
  Key,
  PauseCircle,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Trash2,
  XCircle,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import type { EnterpriseGateway } from "@/types";

export default function GatewayDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { organization } = useAuth();

  const [gateway, setGateway] = useState<EnterpriseGateway | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchGateway = async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<EnterpriseGateway>(`/v1/gateways/${id}`);
      setGateway(res);
    } catch (err: any) {
      setError(err?.message || "Failed to load gateway details.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGateway();
  }, [id, organization?.id]);

  const handleSuspend = async () => {
    if (!gateway) return;
    if (!confirm("Are you sure you want to suspend this gateway? All incoming authorization requests will be rejected immediately.")) {
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      const res = await apiRequest<EnterpriseGateway>(`/v1/gateways/${gateway.id}/suspend`, {
        method: "POST",
      });
      setGateway(res);
      setActionSuccess("Gateway suspended successfully.");
    } catch (err: any) {
      setError(err?.message || "Failed to suspend gateway.");
    } finally {
      setActionLoading(false);
    }
  };

  const handleRevoke = async () => {
    if (!gateway) return;
    if (!confirm("CRITICAL: Are you sure you want to PERMANENTLY REVOKE this gateway? This action cannot be undone.")) {
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      const res = await apiRequest<EnterpriseGateway>(`/v1/gateways/${gateway.id}/revoke`, {
        method: "POST",
      });
      setGateway(res);
      setActionSuccess("Gateway permanently revoked.");
    } catch (err: any) {
      setError(err?.message || "Failed to revoke gateway.");
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <RefreshCw size={24} className="animate-spin text-blue-600" />
      </div>
    );
  }

  if (!gateway) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-8 text-center">
        <ShieldAlert size={36} className="mx-auto text-amber-500" />
        <h2 className="mt-3 text-lg font-bold text-slate-900">Gateway Not Found</h2>
        <p className="mt-1 text-sm text-slate-500">The requested gateway does not exist or has been removed.</p>
        <Link
          href="/dashboard/gateways"
          className="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-blue-600 hover:text-blue-800"
        >
          <ArrowLeft size={16} /> Back to Gateways
        </Link>
      </div>
    );
  }

  const heartbeat = gateway.heartbeat_data || {};
  const uptimeSec = typeof heartbeat.uptime_seconds === "number" ? heartbeat.uptime_seconds : 0;
  const hours = Math.floor(uptimeSec / 3600);
  const minutes = Math.floor((uptimeSec % 3600) / 60);

  return (
    <div className="space-y-6">
      {/* Back Link & Header */}
      <div>
        <Link
          href="/dashboard/gateways"
          className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500 hover:text-slate-800"
        >
          <ArrowLeft size={14} /> Back to Gateways
        </Link>

        <div className="mt-3 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="grid size-12 place-items-center rounded-xl bg-blue-50 text-blue-600 border border-blue-200">
              <Server size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold tracking-tight text-slate-900">{gateway.name}</h1>
                <span
                  className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                    gateway.status === "ACTIVE"
                      ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                      : gateway.status === "PENDING_ENROLLMENT"
                      ? "bg-amber-50 text-amber-700 border border-amber-200"
                      : gateway.status === "OFFLINE"
                      ? "bg-slate-100 text-slate-600 border border-slate-300"
                      : "bg-red-50 text-red-700 border border-red-200"
                  }`}
                >
                  <span
                    className={`size-1.5 rounded-full ${
                      gateway.status === "ACTIVE"
                        ? "bg-emerald-500"
                        : gateway.status === "PENDING_ENROLLMENT"
                        ? "bg-amber-500"
                        : gateway.status === "OFFLINE"
                        ? "bg-slate-400"
                        : "bg-red-500"
                    }`}
                  />
                  {gateway.status}
                </span>
              </div>
              <div className="mt-1 flex items-center gap-3 text-xs text-slate-500">
                <span className="font-mono">{gateway.id}</span>
                <span>•</span>
                <span>Type: {gateway.deployment_type}</span>
                <span>•</span>
                <span>Env: {gateway.environment}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchGateway}
              className="flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 transition"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
            {gateway.status === "ACTIVE" && (
              <button
                onClick={handleSuspend}
                disabled={actionLoading}
                className="flex items-center gap-1.5 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-xs font-semibold text-amber-800 hover:bg-amber-100 transition disabled:opacity-50"
              >
                <PauseCircle size={14} /> Suspend
              </button>
            )}
            {gateway.status !== "REVOKED" && (
              <button
                onClick={handleRevoke}
                disabled={actionLoading}
                className="flex items-center gap-1.5 rounded-lg border border-red-300 bg-red-50 px-3 py-2 text-xs font-semibold text-red-800 hover:bg-red-100 transition disabled:opacity-50"
              >
                <Trash2 size={14} /> Revoke
              </button>
            )}
          </div>
        </div>
      </div>

      {actionSuccess && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs font-medium text-emerald-800 flex items-center justify-between">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-emerald-700 hover:text-emerald-900">×</button>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-700 hover:text-red-900">×</button>
        </div>
      )}

      {/* Telemetry Metrics */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase text-slate-500">Uptime</div>
          <div className="mt-2 text-xl font-bold text-slate-900">
            {hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`}
          </div>
          <p className="mt-1 text-xs text-slate-500">Since sidecar launch</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase text-slate-500">Evaluations Total</div>
          <div className="mt-2 text-xl font-bold text-slate-900">
            {Number(heartbeat.evaluations_total ?? 0).toLocaleString()}
          </div>
          <p className="mt-1 text-xs text-slate-500">Local sub-millisecond decisions</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase text-slate-500">Approved / Rejected</div>
          <div className="mt-2 text-xl font-bold text-slate-900">
            <span className="text-emerald-600">{Number(heartbeat.evaluations_approved ?? 0).toLocaleString()}</span>
            <span className="text-slate-400"> / </span>
            <span className="text-red-600">{Number(heartbeat.evaluations_rejected ?? 0).toLocaleString()}</span>
          </div>
          <p className="mt-1 text-xs text-slate-500">Policy enforcement ratio</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="text-xs font-semibold uppercase text-slate-500">Config Version</div>
          <div className="mt-2 text-xl font-bold font-mono text-slate-900">
            v{gateway.current_config_version}
          </div>
          <p className="mt-1 text-xs text-slate-500">Monotonically signed state</p>
        </div>
      </div>

      {/* Gateway Security & Cryptographic Identity */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
            <Key className="size-4 text-blue-600" />
            <h3 className="font-bold text-slate-900">Cryptographic Identity</h3>
          </div>

          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase">Public Key Fingerprint (SHA-256)</div>
            <div className="mt-1 rounded bg-slate-50 p-2 font-mono text-xs text-slate-800 border border-slate-200 break-all">
              {gateway.public_key_fingerprint || "None (Pending enrollment)"}
            </div>
          </div>

          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase">Gateway Ed25519 Public Key (Base64)</div>
            <div className="mt-1 rounded bg-slate-50 p-2 font-mono text-xs text-slate-600 border border-slate-200 break-all max-h-24 overflow-y-auto">
              {gateway.public_key || "Not enrolled yet. Node generates Ed25519 keypair locally on first launch."}
            </div>
          </div>

          <div className="text-xs text-slate-500">
            <strong>Key Isolation Invariant:</strong> The private Ed25519 key is generated locally on the gateway node and NEVER transmitted over the wire or stored in the Control Plane database.
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
            <Shield className="size-4 text-emerald-600" />
            <h3 className="font-bold text-slate-900">Policy &amp; Health Telemetry</h3>
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-xs font-semibold uppercase text-slate-500">Offline Policy</span>
              <p className="mt-1 font-mono text-xs font-semibold text-slate-800">{gateway.offline_policy}</p>
            </div>
            <div>
              <span className="text-xs font-semibold uppercase text-slate-500">Cached Policies</span>
              <p className="mt-1 font-semibold text-slate-800">{Number(heartbeat.cached_policies_count ?? 0)} active</p>
            </div>
            <div>
              <span className="text-xs font-semibold uppercase text-slate-500">Clock Skew</span>
              <p className="mt-1 font-semibold text-slate-800">{Number(heartbeat.clock_skew_ms ?? 0)} ms</p>
            </div>
            <div>
              <span className="text-xs font-semibold uppercase text-slate-500">Enrolled At</span>
              <p className="mt-1 text-xs text-slate-600">
                {gateway.enrolled_at ? new Date(gateway.enrolled_at).toLocaleString() : "Pending"}
              </p>
            </div>
          </div>

          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase">Last Heartbeat</div>
            <p className="mt-1 text-xs text-slate-600">
              {gateway.last_heartbeat_at
                ? `${new Date(gateway.last_heartbeat_at).toLocaleString()} (checked every 30s)`
                : "No heartbeats recorded yet."}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
