"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, CheckCircle2, Key, Lock, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { PageHeader } from "@/components/ui";
import { apiRequest } from "@/lib/api/client";

type HardeningStatus = {
  environment: string;
  debug_mode: boolean;
  secret_provider: {
    status: string;
    provider: string;
    mode: string;
    cached_entries?: number;
  };
  key_provider_mode: string;
  compliance_label: string;
  hsts_enabled: boolean;
  insecure_tls_allowed: boolean;
  cors_wildcard_prohibited: boolean;
  active_keys_count: number;
};

type KeyItem = {
  key_id: string;
  purpose: string;
  status: string;
  algorithm: string;
  public_key: string;
  created_at: string;
  rotated_at?: string;
  revoked_at?: string;
};

export default function SecurityHardeningPage() {
  const [status, setStatus] = useState<HardeningStatus | null>(null);
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionMsg, setActionMsg] = useState("");

  async function loadData() {
    try {
      const [statusRes, keysRes] = await Promise.all([
        apiRequest<HardeningStatus>("/v1/security/hardening/status"),
        apiRequest<KeyItem[]>("/v1/security/keys"),
      ]);
      setStatus(statusRes);
      setKeys(keysRes);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load security status";
      setActionMsg(msg);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  async function handleRotate(keyId: string) {
    setActionMsg("");
    try {
      await apiRequest(`/v1/security/keys/${keyId}/rotate`, { method: "POST" });
      setActionMsg(`Successfully rotated key: ${keyId}`);
      await loadData();
    } catch (err: unknown) {
      setActionMsg(err instanceof Error ? err.message : "Rotation failed");
    }
  }

  async function handleCompromise(keyId: string) {
    if (!confirm(`EMERGENCY: Are you sure you want to mark key ${keyId} as COMPROMISED? This will immediately halt all signing and reject valid signatures.`)) {
      return;
    }
    setActionMsg("");
    try {
      await apiRequest(`/v1/security/keys/${keyId}/compromise`, {
        method: "POST",
        body: JSON.stringify({ reason: "Manually declared compromised via security dashboard" }),
      });
      setActionMsg(`Key ${keyId} marked COMPROMISED. Signing operations blocked.`);
      await loadData();
    } catch (err: unknown) {
      setActionMsg(err instanceof Error ? err.message : "Compromise declaration failed");
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Production Security & Key Hardening"
        description="Central secret management, KMS/HSM key lifecycle, log redaction, container security, and compliance verification."
      />

      {actionMsg && (
        <div className="rounded-lg bg-slate-900 border border-slate-700 p-4 text-sm text-slate-200">
          {actionMsg}
        </div>
      )}

      {/* Top Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="rounded-xl border border-white/10 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Secret Provider</span>
            <Lock className="size-5 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {status?.secret_provider.provider || "EnvSecretProvider"}
          </div>
          <div className="text-xs text-slate-400">
            Mode: <span className="text-slate-200">{status?.secret_provider.mode || "ENVIRONMENT"}</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="inline-block size-2 rounded-full bg-emerald-500" />
            <span className="text-emerald-400">Status: {status?.secret_provider.status || "HEALTHY"}</span>
          </div>
        </div>

        <div className="rounded-xl border border-white/10 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Key Provider & KMS</span>
            <Key className="size-5 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {status?.key_provider_mode || "LocalKeyProvider"}
          </div>
          <div className="text-xs">
            <span className="rounded bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 text-amber-300 font-medium">
              {status?.compliance_label || "TEST / MOCK ONLY"}
            </span>
          </div>
          <div className="text-xs text-slate-400">
            Active Keys: <span className="font-semibold text-white">{status?.active_keys_count ?? 0}</span>
          </div>
        </div>

        <div className="rounded-xl border border-white/10 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-400">Environment Invariants</span>
            <ShieldCheck className="size-5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold uppercase text-white">
            {status?.environment || "local"}
          </div>
          <div className="space-y-1 text-xs text-slate-300">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="size-3.5 text-emerald-400" />
              <span>Debug Mode Disabled: {status?.debug_mode ? "No" : "Yes"}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="size-3.5 text-emerald-400" />
              <span>CORS Wildcard Blocked: {status?.cors_wildcard_prohibited ? "Yes" : "No"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Cryptographic Key Lifecycle Table */}
      <div className="rounded-xl border border-white/10 bg-slate-900/50 overflow-hidden">
        <div className="p-5 border-b border-white/10 flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-white">Cryptographic Key Inventory</h3>
            <p className="text-xs text-slate-400">Private keys are strictly encapsulated within provider. Only public metadata is exposed.</p>
          </div>
          <button
            onClick={loadData}
            className="flex items-center gap-2 rounded-lg bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-white/10 transition"
          >
            <RefreshCw className="size-3.5" /> Refresh
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="border-b border-white/5 bg-slate-950/40 text-xs uppercase text-slate-400">
              <tr>
                <th className="px-5 py-3">Key ID</th>
                <th className="px-5 py-3">Purpose</th>
                <th className="px-5 py-3">Algorithm</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Public Key Preview</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {keys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-slate-500">
                    No keys found.
                  </td>
                </tr>
              ) : (
                keys.map((k) => (
                  <tr key={k.key_id} className="hover:bg-white/[0.02]">
                    <td className="px-5 py-3.5 font-mono text-xs text-white">{k.key_id}</td>
                    <td className="px-5 py-3.5 text-xs font-medium text-slate-200">{k.purpose}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-400">{k.algorithm}</td>
                    <td className="px-5 py-3.5">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold ${
                          k.status === "ACTIVE"
                            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            : k.status === "COMPROMISED"
                            ? "bg-red-500/20 text-red-300 border border-red-500/30"
                            : k.status === "ROTATING"
                            ? "bg-amber-500/10 text-amber-300 border border-amber-500/20"
                            : "bg-slate-700/50 text-slate-400"
                        }`}
                      >
                        {k.status}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[11px] text-slate-400 truncate max-w-[140px]">
                      {k.public_key.slice(0, 20)}...
                    </td>
                    <td className="px-5 py-3.5 text-right space-x-2">
                      {k.status === "ACTIVE" && (
                        <>
                          <button
                            onClick={() => handleRotate(k.key_id)}
                            className="rounded bg-blue-600/20 px-2.5 py-1 text-xs font-medium text-blue-300 hover:bg-blue-600/30 transition"
                          >
                            Rotate
                          </button>
                          <button
                            onClick={() => handleCompromise(k.key_id)}
                            className="rounded bg-red-600/20 px-2.5 py-1 text-xs font-medium text-red-300 hover:bg-red-600/30 transition"
                          >
                            Declare Compromised
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Runbooks Links */}
      <div className="rounded-xl border border-white/10 bg-slate-900/50 p-5 space-y-3">
        <h3 className="text-base font-semibold text-white">Incident Response & Security Runbooks</h3>
        <p className="text-xs text-slate-400">Operational response procedures for leaked credentials and compromised keys.</p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="rounded-lg border border-white/5 bg-slate-950/40 p-3 space-y-1">
            <span className="text-xs font-semibold text-amber-400">Secret Leak Runbook</span>
            <p className="text-[11px] text-slate-400">Step-by-step procedures to contain and rotate exposed database or application secrets.</p>
          </div>
          <div className="rounded-lg border border-white/5 bg-slate-950/40 p-3 space-y-1">
            <span className="text-xs font-semibold text-red-400">Key Compromise Runbook</span>
            <p className="text-[11px] text-slate-400">Emergency protocol to invalidate signing keys and halt unauthorized delegation.</p>
          </div>
          <div className="rounded-lg border border-white/5 bg-slate-950/40 p-3 space-y-1">
            <span className="text-xs font-semibold text-blue-400">Supply Chain Threat Model</span>
            <p className="text-[11px] text-slate-400">Analysis of upstream dependencies, CI/CD pipeline integrity, and build provenance.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
