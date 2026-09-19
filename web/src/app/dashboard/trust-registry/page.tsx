"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Award,
  BadgeCheck,
  CheckCircle2,
  Clock,
  ExternalLink,
  Key,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import type { AgentCredential, CredentialIssuer } from "@/types";

export default function TrustRegistryPage() {
  const { organization } = useAuth();
  const [issuers, setIssuers] = useState<CredentialIssuer[]>([]);
  const [credentials, setCredentials] = useState<AgentCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [issRes, credRes] = await Promise.all([
        apiRequest<CredentialIssuer[]>("/v1/trust-registry/issuers"),
        apiRequest<{ items: AgentCredential[] }>("/v1/credentials?limit=10"),
      ]);
      setIssuers(issRes || []);
      setCredentials(credRes?.items || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load Trust Registry data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [organization?.id]);

  const activeIssuersCount = issuers.filter((i) => i.status === "ACTIVE").length;
  const activeCredsCount = credentials.filter((c) => c.status === "ACTIVE").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-white">Trust Registry & Agent Credentials</h1>
            <span className="rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold text-blue-400 border border-blue-500/20">
              ATC/1.0
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Publish verifiable organizational claims and attestations for autonomous AI agents.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/dashboard/trust-registry/verify"
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-sm font-medium text-slate-200 hover:bg-slate-700 transition"
          >
            <ShieldCheck size={16} className="text-emerald-400" />
            Verify Credential
          </Link>
          <button
            onClick={fetchData}
            className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3.5 py-2 text-sm font-medium text-slate-300 hover:bg-slate-800 transition"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* Security Rule Notice */}
      <div className="rounded-xl border border-blue-500/20 bg-blue-950/20 p-4">
        <div className="flex gap-3">
          <Shield className="size-5 shrink-0 text-blue-400 mt-0.5" />
          <div className="text-sm">
            <span className="font-semibold text-blue-300">Core Zero-Trust Invariant: </span>
            <span className="text-blue-200/80">
              A credential cryptographically asserts claims made by an issuer (e.g. organizational membership or published capability).
              <strong> A credential NEVER equals permission, trust, or universal authorization.</strong> Verifications occur prior to evaluation by Gateway authorization, trust, and risk engines.
            </span>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-950/30 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-sm font-medium">Active Issuers</span>
            <Award size={18} className="text-blue-400" />
          </div>
          <p className="mt-2 text-3xl font-bold text-white">{activeIssuersCount}</p>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-xs text-slate-500">Organization authorities</span>
            <Link href="/dashboard/trust-registry/issuers" className="text-xs font-medium text-blue-400 hover:underline">
              Manage Issuers &rarr;
            </Link>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-sm font-medium">Active Credentials</span>
            <BadgeCheck size={18} className="text-emerald-400" />
          </div>
          <p className="mt-2 text-3xl font-bold text-white">{activeCredsCount}</p>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-xs text-slate-500">ATC/1.0 Ed25519 tokens</span>
            <Link href="/dashboard/trust-registry/credentials" className="text-xs font-medium text-blue-400 hover:underline">
              View All &rarr;
            </Link>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-sm font-medium">Cryptographic Standard</span>
            <Key size={18} className="text-purple-400" />
          </div>
          <p className="mt-2 text-xl font-bold text-white">ATC-SIG/1</p>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-xs text-slate-500">Deterministic Ed25519</span>
            <Link href="/dashboard/trust-registry/verify" className="text-xs font-medium text-purple-400 hover:underline">
              Test Verifier &rarr;
            </Link>
          </div>
        </div>
      </div>

      {/* Quick Navigation Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Link
          href="/dashboard/trust-registry/issuers"
          className="group rounded-xl border border-slate-800 bg-slate-900/40 p-5 transition hover:border-slate-700 hover:bg-slate-900/80"
        >
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="grid size-10 place-items-center rounded-lg bg-blue-500/10 text-blue-400">
                <Award size={20} />
              </div>
              <div>
                <h2 className="font-semibold text-white group-hover:text-blue-400 transition">Organization Issuers</h2>
                <p className="text-xs text-slate-400">Configure issuer identity keys, rotation policies, and statuses.</p>
              </div>
            </div>
            <ExternalLink size={16} className="text-slate-600 group-hover:text-slate-300" />
          </div>
        </Link>

        <Link
          href="/dashboard/trust-registry/credentials"
          className="group rounded-xl border border-slate-800 bg-slate-900/40 p-5 transition hover:border-slate-700 hover:bg-slate-900/80"
        >
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="grid size-10 place-items-center rounded-lg bg-emerald-500/10 text-emerald-400">
                <BadgeCheck size={20} />
              </div>
              <div>
                <h2 className="font-semibold text-white group-hover:text-emerald-400 transition">Credential Registry</h2>
                <p className="text-xs text-slate-400">View issued credentials, expiration bounds, and execute revocations.</p>
              </div>
            </div>
            <ExternalLink size={16} className="text-slate-600 group-hover:text-slate-300" />
          </div>
        </Link>
      </div>

      {/* Recent Credentials Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2">
            <Clock size={16} className="text-slate-400" />
            <h2 className="font-semibold text-white">Recent Credentials</h2>
          </div>
          <Link href="/dashboard/trust-registry/credentials" className="text-xs font-medium text-blue-400 hover:underline">
            View All Credentials
          </Link>
        </div>

        {loading ? (
          <div className="p-8 text-center text-sm text-slate-500">Loading credentials...</div>
        ) : credentials.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No credentials issued yet for this organization.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/40 text-xs uppercase text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3">Credential ID</th>
                  <th className="px-5 py-3">Type</th>
                  <th className="px-5 py-3">Environment</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Expires</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {credentials.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-800/30 transition">
                    <td className="px-5 py-3.5 font-mono text-xs text-blue-400">{c.credential_id}</td>
                    <td className="px-5 py-3.5 font-medium text-white">{c.credential_type}</td>
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${c.environment === "sandbox" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"}`}>
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
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
