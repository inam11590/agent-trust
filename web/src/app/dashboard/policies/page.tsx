"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  Braces,
  CheckCircle2,
  Clock,
  ExternalLink,
  FileCode,
  History,
  Layers,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";

interface PolicyItem {
  id: string;
  name: string;
  description?: string;
  category: string;
  tags: string[];
  active_version?: number;
  total_versions: number;
  status: string;
  created_at: string;
  updated_at: string;
}

export default function PoliciesPage() {
  const { organization } = useAuth();
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("ALL");

  const fetchPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiRequest<PolicyItem[]>("/v1/policies");
      setPolicies(res || []);
    } catch (err: any) {
      setError(err?.message || "Failed to load policies.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, [organization?.id]);

  const categories = ["ALL", ...Array.from(new Set(policies.map((p) => p.category || "General")))];

  const filtered = policies.filter((p) => {
    const matchesSearch =
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.id.toLowerCase().includes(search.toLowerCase()) ||
      (p.description && p.description.toLowerCase().includes(search.toLowerCase()));
    const matchesCategory = categoryFilter === "ALL" || p.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">Policy-as-Code (APL/1.0)</h1>
            <span className="rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-semibold text-blue-700">
              Deterministic
            </span>
          </div>
          <p className="text-sm text-slate-500">
            Declarative governance, versioning, simulation, and zero-downtime monotonic gateway distribution.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchPolicies}
            disabled={loading}
            className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
          <Link
            href="/dashboard/policies/new"
            className="flex items-center gap-2 rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-600 transition"
          >
            <Plus size={16} />
            New Policy
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Total Policies</span>
            <Braces size={16} className="text-blue-500" />
          </div>
          <p className="mt-2 text-2xl font-bold text-slate-900">{policies.length}</p>
          <p className="mt-1 text-xs text-slate-500">Registered governance policies</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Active & Enforcing</span>
            <ShieldCheck size={16} className="text-emerald-500" />
          </div>
          <p className="mt-2 text-2xl font-bold text-emerald-600">
            {policies.filter((p) => p.status === "ACTIVE" && p.active_version).length}
          </p>
          <p className="mt-1 text-xs text-slate-500">Live in Control & Data Planes</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Drafts</span>
            <FileCode size={16} className="text-amber-500" />
          </div>
          <p className="mt-2 text-2xl font-bold text-amber-600">
            {policies.filter((p) => p.status === "DRAFT" || !p.active_version).length}
          </p>
          <p className="mt-1 text-xs text-slate-500">Under development or review</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 text-xs font-semibold uppercase tracking-wider">
            <span>Precedence Hierarchy</span>
            <Layers size={16} className="text-purple-500" />
          </div>
          <p className="mt-2 text-sm font-semibold text-purple-700">DENY &gt; APPROVAL &gt; ALLOW</p>
          <p className="mt-1 text-xs text-slate-500">Fail-closed default</p>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search policies by name, ID, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:outline-none"
          />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Category:</span>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 focus:border-blue-500 focus:outline-none"
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-600">
            <thead className="bg-slate-50 text-xs font-bold uppercase tracking-wider text-slate-500 border-b border-slate-200">
              <tr>
                <th className="py-3 px-4">Policy</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Active Version</th>
                <th className="py-3 px-4">Total Versions</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Last Updated</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <RefreshCw size={24} className="mx-auto mb-2 animate-spin text-blue-500" />
                    Loading enterprise policies...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <Braces size={28} className="mx-auto mb-2 text-slate-300" />
                    No policies found. Click &quot;New Policy&quot; to create your first Policy-as-Code rule set.
                  </td>
                </tr>
              ) : (
                filtered.map((p) => (
                  <tr key={p.id} className="hover:bg-slate-50/80 transition">
                    <td className="py-3 px-4">
                      <Link href={`/dashboard/policies/${p.id}`} className="font-semibold text-slate-900 hover:text-blue-600 transition">
                        {p.name}
                      </Link>
                      <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mt-0.5">
                        <span>{p.id}</span>
                        {p.description && <span className="text-slate-500 truncate max-w-xs">• {p.description}</span>}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-700">
                        {p.category || "General"}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {p.active_version ? (
                        <span className="font-semibold text-slate-900">v{p.active_version}</span>
                      ) : (
                        <span className="text-xs text-slate-400 italic">None (Draft)</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-xs font-medium text-slate-600">{p.total_versions} versions</span>
                    </td>
                    <td className="py-3 px-4">
                      {p.status === "ACTIVE" && p.active_version ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 border border-emerald-200">
                          <CheckCircle2 size={12} /> Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700 border border-amber-200">
                          <Clock size={12} /> Draft
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-500">
                      {new Date(p.updated_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        href={`/dashboard/policies/${p.id}`}
                        className="inline-flex items-center gap-1 text-sm font-semibold text-blue-600 hover:text-blue-800 transition"
                      >
                        Inspect
                        <ArrowRight size={14} />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
