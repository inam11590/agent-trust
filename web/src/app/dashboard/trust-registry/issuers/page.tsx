"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Award,
  CheckCircle2,
  ChevronLeft,
  Copy,
  Key,
  Plus,
  RefreshCw,
  RotateCw,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import type { CredentialIssuer } from "@/types";

export default function IssuersManagementPage() {
  const { organization } = useAuth();
  const [issuers, setIssuers] = useState<CredentialIssuer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rotatingKeyId, setRotatingKeyId] = useState<string | null>(null);

  const fetchIssuers = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<CredentialIssuer[]>("/v1/trust-registry/issuers");
      setIssuers(res || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load issuers.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIssuers();
  }, [organization?.id]);

  const handleRotateKey = async (issuerId: string) => {
    if (!confirm("Rotate active signing key for this issuer? Existing credentials signed by the previous key will remain verifiable unless revoked.")) {
      return;
    }
    setRotatingKeyId(issuerId);
    try {
      await apiRequest(`/v1/trust-registry/issuers/${issuerId}/rotate-key`, {
        method: "POST",
        body: JSON.stringify({ revoke_old_key: false }),
      });
      await fetchIssuers();
    } catch (err: any) {
      alert(`Key rotation failed: ${err?.message || "Unknown error"}`);
    } finally {
      setRotatingKeyId(null);
    }
  };

  const handleSuspend = async (issuerId: string) => {
    if (!confirm("Are you sure you want to suspend this issuer? Credential verification for this issuer will immediately fail.")) {
      return;
    }
    try {
      await apiRequest(`/v1/trust-registry/issuers/${issuerId}/suspend`, { method: "POST" });
      await fetchIssuers();
    } catch (err: any) {
      alert(`Failed to suspend issuer: ${err?.message}`);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Link href="/dashboard/trust-registry" className="hover:text-white transition flex items-center gap-1">
          <ChevronLeft size={16} /> Trust Registry
        </Link>
        <span>/</span>
        <span className="text-white">Organization Issuers</span>
      </div>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Credential Issuers</h1>
          <p className="mt-1 text-sm text-slate-400">
            Manage organization identity issuing authorities, active Ed25519 signing keys, and rotation status.
          </p>
        </div>
        <button
          onClick={fetchIssuers}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3.5 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800 transition"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {loading ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center text-sm text-slate-500">
          Loading issuers...
        </div>
      ) : issuers.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-12 text-center text-sm text-slate-400">
          No credential issuers provisioned yet. Issuers are automatically created on first credential issuance.
        </div>
      ) : (
        <div className="space-y-4">
          {issuers.map((issuer) => (
            <div key={issuer.id} className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                  <div className="grid size-10 place-items-center rounded-lg bg-blue-500/10 text-blue-400">
                    <Award size={20} />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-white">{issuer.name}</h2>
                    <p className="font-mono text-xs text-blue-400">{issuer.issuer_id}</p>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${issuer.status === "ACTIVE" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"}`}>
                    {issuer.status === "ACTIVE" ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                    {issuer.status}
                  </span>
                  {issuer.status === "ACTIVE" && (
                    <>
                      <button
                        onClick={() => handleRotateKey(issuer.issuer_id)}
                        disabled={rotatingKeyId === issuer.issuer_id}
                        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition"
                      >
                        <RotateCw size={12} className={rotatingKeyId === issuer.issuer_id ? "animate-spin" : ""} />
                        Rotate Key
                      </button>
                      <button
                        onClick={() => handleSuspend(issuer.issuer_id)}
                        className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-400 hover:bg-amber-500/20 transition"
                      >
                        Suspend
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Signing Keys List */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Registered Public Keys</h3>
                {issuer.signing_keys && issuer.signing_keys.length > 0 ? (
                  <div className="grid grid-cols-1 gap-2">
                    {issuer.signing_keys.map((k) => (
                      <div key={k.key_id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg bg-slate-950/40 p-3 text-xs border border-slate-800/80">
                        <div className="flex items-center gap-2">
                          <Key size={14} className="text-slate-400" />
                          <span className="font-mono text-slate-200">{k.key_id}</span>
                          <span className="text-slate-500">({k.algorithm})</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-slate-400 truncate max-w-[200px]" title={k.fingerprint}>
                            FP: {k.fingerprint.slice(0, 16)}...
                          </span>
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${k.status === "ACTIVE" ? "bg-emerald-500/20 text-emerald-400" : "bg-slate-700 text-slate-300"}`}>
                            {k.status}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">No keys loaded.</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
