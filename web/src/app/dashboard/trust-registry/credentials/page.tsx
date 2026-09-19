"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  BadgeCheck,
  CheckCircle2,
  ChevronLeft,
  Clock,
  Eye,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  X,
  XCircle,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import type { AgentCredential } from "@/types";

export default function CredentialsListPage() {
  const { organization } = useAuth();
  const [credentials, setCredentials] = useState<AgentCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [selectedCred, setSelectedCred] = useState<AgentCredential | null>(null);
  const [revoking, setRevoking] = useState(false);

  const fetchCredentials = async () => {
    setLoading(true);
    setError(null);
    try {
      let url = "/v1/credentials?limit=100";
      if (statusFilter !== "ALL") {
        url += `&status_filter=${statusFilter}`;
      }
      const res = await apiRequest<{ items: AgentCredential[] }>(url);
      setCredentials(res?.items || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load credentials.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, [organization?.id, statusFilter]);

  const handleRevoke = async (credId: string) => {
    if (!confirm(`Are you sure you want to revoke credential '${credId}'? This will immediately fail any future verifications.`)) {
      return;
    }
    setRevoking(true);
    try {
      await apiRequest(`/v1/credentials/${credId}/revoke`, {
        method: "POST",
        body: JSON.stringify({ reason_code: "ISSUER_ACTION" }),
      });
      setSelectedCred(null);
      await fetchCredentials();
    } catch (err: any) {
      alert(`Revocation failed: ${err?.message || "Unknown error"}`);
    } finally {
      setRevoking(false);
    }
  };

  const filtered = credentials.filter((c) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      c.credential_id.toLowerCase().includes(q) ||
      c.credential_type.toLowerCase().includes(q) ||
      c.subject_agent_id.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Link href="/dashboard/trust-registry" className="hover:text-white transition flex items-center gap-1">
          <ChevronLeft size={16} /> Trust Registry
        </Link>
        <span>/</span>
        <span className="text-white">Credentials Registry</span>
      </div>

      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Verifiable Agent Credentials</h1>
          <p className="mt-1 text-sm text-slate-400">
            Authoritative registry of signed ATC/1.0 credentials issued to organization agents.
          </p>
        </div>
        <button
          onClick={fetchCredentials}
          className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3.5 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800 transition"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Filter and Search */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center justify-between">
        <div className="relative max-w-sm flex-1">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search credential or agent ID..."
            className="w-full rounded-lg border border-slate-800 bg-slate-900/60 pl-9 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          {["ALL", "ACTIVE", "REVOKED", "EXPIRED"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${statusFilter === st ? "bg-blue-600 text-white" : "bg-slate-900 border border-slate-800 text-slate-400 hover:bg-slate-800 hover:text-white"}`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-sm text-slate-500">Loading credentials...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-sm text-slate-400">
            No credentials found matching filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/40 text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Credential ID</th>
                  <th className="px-5 py-3">Type</th>
                  <th className="px-5 py-3">Subject Agent</th>
                  <th className="px-5 py-3">Environment</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Expires</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {filtered.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-3.5 font-mono text-xs text-blue-400">{c.credential_id}</td>
                    <td className="px-5 py-3.5 font-medium text-white">{c.credential_type}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-300">{c.subject_agent_id}</td>
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold ${c.environment === "sandbox" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"}`}>
                        {c.environment}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${c.status === "ACTIVE" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-red-500/10 text-red-400 border border-red-500/20"}`}>
                        {c.status === "ACTIVE" ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                        {c.status}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs text-slate-400">
                      {new Date(c.expires_at).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <button
                        onClick={() => setSelectedCred(c)}
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 transition"
                      >
                        <Eye size={12} /> Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details Drawer / Modal */}
      {selectedCred && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-semibold text-white">Credential Details</h3>
                <p className="font-mono text-xs text-blue-400">{selectedCred.credential_id}</p>
              </div>
              <button
                onClick={() => setSelectedCred(null)}
                className="text-slate-400 hover:text-white transition"
              >
                <X size={18} />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-500">Type:</span>
                  <p className="font-medium text-white">{selectedCred.credential_type}</p>
                </div>
                <div>
                  <span className="text-slate-500">Status:</span>
                  <p className="font-medium text-white">{selectedCred.status}</p>
                </div>
                <div>
                  <span className="text-slate-500">Issued At:</span>
                  <p className="font-mono text-slate-300">{new Date(selectedCred.issued_at).toLocaleString()}</p>
                </div>
                <div>
                  <span className="text-slate-500">Expires At:</span>
                  <p className="font-mono text-slate-300">{new Date(selectedCred.expires_at).toLocaleString()}</p>
                </div>
                <div>
                  <span className="text-slate-500">Signing Key ID:</span>
                  <p className="font-mono text-slate-300">{selectedCred.signing_key_id}</p>
                </div>
                <div>
                  <span className="text-slate-500">Environment:</span>
                  <p className="font-mono text-slate-300">{selectedCred.environment}</p>
                </div>
              </div>

              <div>
                <span className="text-slate-500">Attested Claims:</span>
                <pre className="mt-1 rounded-lg bg-slate-950 p-3 font-mono text-[11px] text-emerald-400 overflow-x-auto border border-slate-800">
                  {JSON.stringify(selectedCred.claims, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-slate-800 pt-4">
              {selectedCred.status === "ACTIVE" ? (
                <button
                  onClick={() => handleRevoke(selectedCred.credential_id)}
                  disabled={revoking}
                  className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3.5 py-2 text-xs font-medium text-red-400 hover:bg-red-500/20 transition"
                >
                  <Trash2 size={14} />
                  {revoking ? "Revoking..." : "Revoke Credential"}
                </button>
              ) : (
                <span className="text-xs text-slate-500">Credential is {selectedCred.status.toLowerCase()}</span>
              )}
              <button
                onClick={() => setSelectedCred(null)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
