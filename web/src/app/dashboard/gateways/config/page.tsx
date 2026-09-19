"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Clock,
  Code2,
  FileCheck,
  History,
  Lock,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import type { GatewayConfigBundle } from "@/types";

export default function GatewayConfigPage() {
  const { organization } = useAuth();
  const [activeBundle, setActiveBundle] = useState<GatewayConfigBundle | null>(null);
  const [history, setHistory] = useState<GatewayConfigBundle[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Selected bundle for inspection
  const [selectedBundle, setSelectedBundle] = useState<GatewayConfigBundle | null>(null);
  const [publishing, setPublishing] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [curr, hist] = await Promise.all([
        apiRequest<GatewayConfigBundle>("/v1/gateways/config/bundle").catch(() => null),
        apiRequest<GatewayConfigBundle[]>("/v1/gateways/config/history").catch(() => []),
      ]);
      setActiveBundle(curr);
      setHistory(hist || []);
      if (curr) setSelectedBundle(curr);
    } catch (err: any) {
      setError(err?.message || "Failed to load configuration bundle state.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [organization?.id]);

  const handlePublish = async () => {
    setPublishing(true);
    setError(null);
    try {
      const res = await apiRequest<GatewayConfigBundle>("/v1/gateways/config/publish", {
        method: "POST",
      });
      setActiveBundle(res);
      setSelectedBundle(res);
      setActionSuccess(`Configuration bundle v${res.version} successfully signed and published.`);
      fetchData();
    } catch (err: any) {
      setError(err?.message || "Failed to publish configuration bundle.");
    } finally {
      setPublishing(false);
    }
  };

  const handleRollback = async (targetVersion: number) => {
    if (!confirm(`Are you sure you want to rollback to configuration v${targetVersion}? A new bundle will be re-signed with an incremented monotonic version to prevent replay attacks.`)) {
      return;
    }
    setRollingBack(true);
    setError(null);
    try {
      const res = await apiRequest<GatewayConfigBundle>("/v1/gateways/config/rollback", {
        method: "POST",
        body: JSON.stringify({ target_version: targetVersion }),
      });
      setActiveBundle(res);
      setSelectedBundle(res);
      setActionSuccess(`Rollback executed: Re-signed v${targetVersion} as new monotonic version v${res.version}.`);
      fetchData();
    } catch (err: any) {
      setError(err?.message || "Rollback failed.");
    } finally {
      setRollingBack(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Link
          href="/dashboard/gateways"
          className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500 hover:text-slate-800"
        >
          <ArrowLeft size={14} /> Back to Gateways Fleet
        </Link>

        <div className="mt-3 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900">Configuration Bundles &amp; Policies</h1>
              <span className="rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold text-blue-600 border border-blue-500/20">
                Monotonic Anti-Rollback
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-600">
              Centrally compiled, cryptographically signed policy bundles distributed to edge sidecars.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchData}
              className="flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 transition"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
            <button
              onClick={handlePublish}
              disabled={publishing}
              className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-700 transition disabled:opacity-50"
            >
              {publishing ? <RefreshCw size={14} className="animate-spin" /> : <Activity size={14} />}
              Publish Fresh Bundle
            </button>
          </div>
        </div>
      </div>

      {/* Security Rule Notice */}
      <div className="rounded-xl border border-indigo-200 bg-indigo-50/50 p-4">
        <div className="flex gap-3">
          <ShieldCheck className="size-5 shrink-0 text-indigo-600 mt-0.5" />
          <div className="text-sm">
            <span className="font-semibold text-indigo-900">Anti-Rollback Security Invariant: </span>
            <span className="text-indigo-800">
              Gateways strictly reject any configuration bundle with a version number less than or equal to their currently active version.
              To roll back, the Control Plane <strong>re-signs previous policy definitions under a strictly incremented version number</strong>.
            </span>
          </div>
        </div>
      </div>

      {actionSuccess && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-xs font-medium text-emerald-800 flex items-center justify-between">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-emerald-700 hover:text-emerald-900"><X size={14} /></button>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert size={14} className="text-red-600" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-700 hover:text-red-900"><X size={14} /></button>
        </div>
      )}

      {/* Main Grid: Bundle Inspector + History */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Bundle History List (Left Column) */}
        <div className="space-y-4 lg:col-span-1">
          <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
              <History size={16} className="text-blue-600" />
              <h3 className="font-bold text-slate-900">Version History</h3>
            </div>

            <div className="mt-3 divide-y divide-slate-100 max-h-[600px] overflow-y-auto">
              {history.length === 0 ? (
                <div className="py-6 text-center text-xs text-slate-500">
                  No configuration bundles published yet. Click &quot;Publish Fresh Bundle&quot; to initialize.
                </div>
              ) : (
                history.map((bundle) => {
                  const isActive = activeBundle?.version === bundle.version;
                  const isSelected = selectedBundle?.version === bundle.version;
                  return (
                    <div
                      key={bundle.id}
                      onClick={() => setSelectedBundle(bundle)}
                      className={`cursor-pointer p-3 transition rounded-lg my-1 ${
                        isSelected
                          ? "bg-blue-50 border border-blue-200"
                          : "hover:bg-slate-50"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm font-bold text-slate-900">v{bundle.version}</span>
                          {isActive && (
                            <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 border border-emerald-200">
                              CURRENT
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] text-slate-400">
                          {new Date(bundle.published_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-slate-500 truncate">
                        Hash: {bundle.hash.slice(0, 16)}...
                      </div>
                      {!isActive && (
                        <div className="mt-2 flex justify-end">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRollback(bundle.version);
                            }}
                            disabled={rollingBack}
                            className="inline-flex items-center gap-1 rounded bg-white px-2 py-1 text-[11px] font-medium text-slate-700 border border-slate-200 shadow-sm hover:bg-slate-100 disabled:opacity-50"
                          >
                            <RotateCcw size={11} /> Rollback to v{bundle.version}
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Bundle Inspector (Right 2 Columns) */}
        <div className="space-y-4 lg:col-span-2">
          {selectedBundle ? (
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                <div className="flex items-center gap-2">
                  <Code2 className="size-5 text-blue-600" />
                  <h3 className="text-lg font-bold text-slate-900">
                    Bundle Details: v{selectedBundle.version}
                  </h3>
                  {activeBundle?.version === selectedBundle.version && (
                    <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-700 border border-emerald-200">
                      Active at Fleet
                    </span>
                  )}
                </div>
                <span className="text-xs text-slate-500">
                  Published: {new Date(selectedBundle.published_at).toLocaleString()}
                </span>
              </div>

              {/* Cryptographic Signature & Hash */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
                <div>
                  <span className="font-semibold text-slate-600">Signing Key ID</span>
                  <p className="mt-0.5 font-mono text-slate-800 truncate">{selectedBundle.signing_key_id}</p>
                </div>
                <div>
                  <span className="font-semibold text-slate-600">Payload SHA-256 Hash</span>
                  <p className="mt-0.5 font-mono text-slate-800 truncate">{selectedBundle.hash}</p>
                </div>
                <div className="sm:col-span-2">
                  <span className="font-semibold text-slate-600">Ed25519 Cryptographic Signature</span>
                  <p className="mt-0.5 font-mono text-slate-600 bg-slate-50 p-2 rounded border border-slate-200 break-all max-h-16 overflow-y-auto">
                    {selectedBundle.signature}
                  </p>
                </div>
              </div>

              {/* JSON Payload Viewer */}
              <div>
                <div className="flex items-center justify-between text-xs font-semibold text-slate-700 mb-1">
                  <span>Compiled Policy Payload</span>
                  <span className="text-slate-400 font-normal">
                    {Object.keys(selectedBundle.payload || {}).length} sections compiled
                  </span>
                </div>
                <pre className="max-h-96 overflow-auto rounded-lg border border-slate-900 bg-slate-950 p-4 font-mono text-xs text-emerald-400">
                  {JSON.stringify(selectedBundle.payload, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-200 bg-white p-12 text-center text-slate-500 shadow-sm">
              <FileCheck size={36} className="mx-auto text-slate-400" />
              <p className="mt-2 text-sm font-medium">Select a bundle from the history list to inspect.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
