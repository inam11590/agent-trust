"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Copy,
  ExternalLink,
  Plus,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  X,
  XCircle,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import type {
  EnterpriseGateway,
  GatewayDeploymentType,
  GatewayEnvironment,
  GatewayOfflinePolicy,
  GatewayRegistrationResult,
} from "@/types";

export default function EnterpriseGatewaysPage() {
  const { organization } = useAuth();
  const [gateways, setGateways] = useState<EnterpriseGateway[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [envFilter, setEnvFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [typeFilter, setTypeFilter] = useState<string>("ALL");

  // Registration Modal State
  const [modalOpen, setModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createType, setCreateType] = useState<GatewayDeploymentType>("SELF_HOSTED_GATEWAY");
  const [createEnv, setCreateEnv] = useState<GatewayEnvironment>("PRODUCTION");
  const [createPolicy, setCreatePolicy] = useState<GatewayOfflinePolicy>("FAIL_CLOSED");
  const [registrationResult, setRegistrationResult] = useState<GatewayRegistrationResult | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const fetchGateways = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<EnterpriseGateway[]>("/v1/gateways");
      setGateways(res || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load Enterprise Gateways.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGateways();
  }, [organization?.id]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createName.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const res = await apiRequest<GatewayRegistrationResult>("/v1/gateways", {
        method: "POST",
        body: JSON.stringify({
          name: createName.trim(),
          deployment_type: createType,
          environment: createEnv,
          offline_policy: createPolicy,
        }),
      });
      setRegistrationResult(res);
      fetchGateways();
    } catch (err: any) {
      setError(err?.message || "Failed to register gateway.");
    } finally {
      setCreating(false);
    }
  };

  const copyToClipboard = (text: string, type: "token" | "cmd") => {
    navigator.clipboard.writeText(text);
    if (type === "token") {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    } else {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  // Filtered List
  const filtered = gateways.filter((gw) => {
    if (envFilter !== "ALL" && gw.environment !== envFilter) return false;
    if (statusFilter !== "ALL" && gw.status !== statusFilter) return false;
    if (typeFilter !== "ALL" && gw.deployment_type !== typeFilter) return false;
    return true;
  });

  const activeCount = gateways.filter((g) => g.status === "ACTIVE").length;
  const offlineCount = gateways.filter((g) => g.status === "OFFLINE").length;
  const pendingCount = gateways.filter((g) => g.status === "PENDING_ENROLLMENT").length;
  const suspendedCount = gateways.filter((g) => g.status === "SUSPENDED" || g.status === "REVOKED").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">Enterprise Gateways & Fleet</h1>
            <span className="rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold text-blue-600 border border-blue-500/20">
              Control Plane
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-600">
            Centrally manage policy distribution, cryptographic key binding, and zero-trust sidecars across your infrastructure.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/dashboard/gateways/config"
            className="flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 transition"
          >
            <Activity size={16} className="text-blue-600" />
            Config Bundles
          </Link>
          <button
            onClick={() => {
              setRegistrationResult(null);
              setCreateName("");
              setModalOpen(true);
            }}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-blue-700 transition"
          >
            <Plus size={16} />
            Register Gateway
          </button>
          <button
            onClick={fetchGateways}
            className="flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 transition"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {/* Zero Trust Invariant Banner */}
      <div className="rounded-xl border border-indigo-200 bg-indigo-50/50 p-4">
        <div className="flex gap-3">
          <Shield className="size-5 shrink-0 text-indigo-600 mt-0.5" />
          <div className="text-sm">
            <span className="font-semibold text-indigo-900">Core Architectural Invariant: </span>
            <span className="text-indigo-800">
              Control Plane manages policies, identities, and trust bundles. <strong>Data Plane sidecars enforce authorization locally in microsecond latencies.</strong> Raw business payloads NEVER touch the Control Plane by default.
            </span>
          </div>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Active Gateways</span>
            <CheckCircle2 size={16} className="text-emerald-500" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900">{activeCount}</div>
          <p className="mt-1 text-xs text-slate-500">Enforcing live policies</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Pending Enrollment</span>
            <Clock size={16} className="text-amber-500" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900">{pendingCount}</div>
          <p className="mt-1 text-xs text-slate-500">Awaiting initial keypair handshake</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Offline Gateways</span>
            <AlertTriangle size={16} className="text-slate-400" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900">{offlineCount}</div>
          <p className="mt-1 text-xs text-slate-500">Heartbeat missed (&gt; 90s)</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Suspended / Revoked</span>
            <XCircle size={16} className="text-red-500" />
          </div>
          <div className="mt-2 text-2xl font-bold text-slate-900">{suspendedCount}</div>
          <p className="mt-1 text-xs text-slate-500">Emergency block active</p>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-red-600" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-600 hover:text-red-800"><X size={16} /></button>
        </div>
      )}

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Filters:</span>
        <select
          value={envFilter}
          onChange={(e) => setEnvFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-medium text-slate-700"
        >
          <option value="ALL">All Environments</option>
          <option value="PRODUCTION">Production</option>
          <option value="SANDBOX">Sandbox</option>
        </select>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-medium text-slate-700"
        >
          <option value="ALL">All Types</option>
          <option value="SELF_HOSTED_GATEWAY">Self-Hosted Gateway</option>
          <option value="SIDECAR">Sidecar</option>
          <option value="CLOUD_GATEWAY">Cloud Gateway</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-xs font-medium text-slate-700"
        >
          <option value="ALL">All Statuses</option>
          <option value="ACTIVE">Active</option>
          <option value="PENDING_ENROLLMENT">Pending Enrollment</option>
          <option value="OFFLINE">Offline</option>
          <option value="SUSPENDED">Suspended</option>
          <option value="REVOKED">Revoked</option>
        </select>

        <div className="ml-auto text-xs text-slate-500">
          Showing {filtered.length} of {gateways.length} gateway instances
        </div>
      </div>

      {/* Gateways Table */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="min-w-full divide-y divide-slate-200 text-left text-sm">
          <thead className="bg-slate-50 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-5 py-3">Gateway Name / ID</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Environment</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Offline Safety</th>
              <th className="px-4 py-3">Config Ver</th>
              <th className="px-4 py-3">Last Heartbeat</th>
              <th className="px-4 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-5 py-12 text-center text-slate-500">
                  {loading ? "Loading gateways..." : "No enterprise gateways found matching criteria."}
                </td>
              </tr>
            ) : (
              filtered.map((gw) => (
                <tr key={gw.id} className="hover:bg-slate-50/75 transition">
                  <td className="px-5 py-4">
                    <div className="font-medium text-slate-900">{gw.name}</div>
                    <div className="font-mono text-xs text-slate-400">{gw.id}</div>
                  </td>
                  <td className="px-4 py-4">
                    <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs font-medium text-slate-700">
                      {gw.deployment_type === "SELF_HOSTED_GATEWAY"
                        ? "Gateway"
                        : gw.deployment_type === "SIDECAR"
                        ? "Sidecar"
                        : "Cloud"}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                        gw.environment === "PRODUCTION"
                          ? "bg-purple-50 text-purple-700 border border-purple-200"
                          : "bg-blue-50 text-blue-700 border border-blue-200"
                      }`}
                    >
                      {gw.environment}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                        gw.status === "ACTIVE"
                          ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          : gw.status === "PENDING_ENROLLMENT"
                          ? "bg-amber-50 text-amber-700 border border-amber-200"
                          : gw.status === "OFFLINE"
                          ? "bg-slate-100 text-slate-600 border border-slate-300"
                          : "bg-red-50 text-red-700 border border-red-200"
                      }`}
                    >
                      <span
                        className={`size-1.5 rounded-full ${
                          gw.status === "ACTIVE"
                            ? "bg-emerald-500"
                            : gw.status === "PENDING_ENROLLMENT"
                            ? "bg-amber-500"
                            : gw.status === "OFFLINE"
                            ? "bg-slate-400"
                            : "bg-red-500"
                        }`}
                      />
                      {gw.status}
                    </span>
                  </td>
                  <td className="px-4 py-4">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-mono font-medium ${
                        gw.offline_policy === "FAIL_CLOSED"
                          ? "bg-slate-100 text-slate-800"
                          : "bg-amber-50 text-amber-800 border border-amber-200"
                      }`}
                    >
                      {gw.offline_policy}
                    </span>
                  </td>
                  <td className="px-4 py-4 font-mono text-xs font-semibold text-slate-700">
                    v{gw.current_config_version}
                  </td>
                  <td className="px-4 py-4 text-xs text-slate-500">
                    {gw.last_heartbeat_at
                      ? new Date(gw.last_heartbeat_at).toLocaleTimeString()
                      : "Never"}
                  </td>
                  <td className="px-4 py-4 text-right">
                    <Link
                      href={`/dashboard/gateways/${gw.id}`}
                      className="inline-flex items-center gap-1 text-xs font-semibold text-blue-600 hover:text-blue-800"
                    >
                      Inspect <ExternalLink size={12} />
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Registration Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-xl rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div className="flex items-center gap-2">
                <Server className="size-5 text-blue-600" />
                <h3 className="text-lg font-bold text-slate-900">
                  {registrationResult ? "Gateway Registration Complete" : "Register Enterprise Gateway"}
                </h3>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 transition"
              >
                <X size={18} />
              </button>
            </div>

            {!registrationResult ? (
              <form onSubmit={handleCreate} className="mt-4 space-y-4">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-600">Gateway Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. us-east-k8s-sidecar-mesh"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold uppercase text-slate-600">Deployment Type</label>
                    <select
                      value={createType}
                      onChange={(e) => setCreateType(e.target.value as GatewayDeploymentType)}
                      className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none"
                    >
                      <option value="SELF_HOSTED_GATEWAY">Self-Hosted Gateway</option>
                      <option value="SIDECAR">Sidecar (Local Proxy)</option>
                      <option value="CLOUD_GATEWAY">Cloud Managed</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase text-slate-600">Environment</label>
                    <select
                      value={createEnv}
                      onChange={(e) => setCreateEnv(e.target.value as GatewayEnvironment)}
                      className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none"
                    >
                      <option value="PRODUCTION">PRODUCTION</option>
                      <option value="SANDBOX">SANDBOX</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-600">Offline Policy</label>
                  <select
                    value={createPolicy}
                    onChange={(e) => setCreatePolicy(e.target.value as GatewayOfflinePolicy)}
                    className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none"
                  >
                    <option value="FAIL_CLOSED">FAIL_CLOSED (Strict Zero-Trust - recommended)</option>
                    <option value="LIMITED_OFFLINE">LIMITED_OFFLINE (Cached read &amp; low-risk only)</option>
                  </select>
                  <p className="mt-1 text-xs text-slate-500">
                    High-risk actions (&gt; $5,000 or admin capabilities) always fail closed regardless of offline policy.
                  </p>
                </div>

                <div className="mt-6 flex justify-end gap-3 border-t border-slate-100 pt-4">
                  <button
                    type="button"
                    onClick={() => setModalOpen(false)}
                    className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creating}
                    className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
                  >
                    {creating && <RefreshCw size={14} className="animate-spin" />}
                    Generate One-Time Token
                  </button>
                </div>
              </form>
            ) : (
              <div className="mt-4 space-y-4">
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
                  <span className="font-bold">Security Notice: </span>
                  This enrollment token is valid for 1 hour and can only be used once. The private key is generated locally on the gateway node and NEVER leaves your environment.
                </div>

                <div>
                  <div className="text-xs font-semibold uppercase text-slate-600">Gateway ID</div>
                  <div className="mt-1 font-mono text-sm font-bold text-slate-900">{registrationResult.gateway_id}</div>
                </div>

                <div>
                  <div className="text-xs font-semibold uppercase text-slate-600">Single-Use Enrollment Token</div>
                  <div className="mt-1 flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs text-slate-800">
                    <span className="truncate">{registrationResult.enrollment_token}</span>
                    <button
                      onClick={() => copyToClipboard(registrationResult.enrollment_token, "token")}
                      className="ml-2 inline-flex items-center gap-1 rounded bg-white px-2 py-1 text-xs font-medium text-slate-700 border border-slate-300 shadow-sm hover:bg-slate-100"
                    >
                      <Copy size={12} />
                      {copiedToken ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>

                <div>
                  <div className="text-xs font-semibold uppercase text-slate-600">CLI Enrollment Command</div>
                  <div className="mt-1 flex items-center justify-between rounded-lg border border-slate-900 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200">
                    <div className="flex items-center gap-2 truncate">
                      <Terminal size={14} className="text-emerald-400 shrink-0" />
                      <span className="truncate">{registrationResult.enrollment_command}</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(registrationResult.enrollment_command, "cmd")}
                      className="ml-2 inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-xs font-medium text-slate-200 border border-slate-700 shadow-sm hover:bg-slate-700 shrink-0"
                    >
                      <Copy size={12} />
                      {copiedCmd ? "Copied" : "Copy"}
                    </button>
                  </div>
                </div>

                <div className="mt-6 flex justify-end border-t border-slate-100 pt-4">
                  <button
                    onClick={() => setModalOpen(false)}
                    className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
