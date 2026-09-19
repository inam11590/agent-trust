"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, CheckCircle2, Globe, Layers, Plus, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import { EmptyState, LoadingState, PageHeader, StatusBadge } from "@/components/ui";
import { Agent, AgentEndpoint } from "@/types";

export default function GatewayEndpointsPage() {
  const [endpoints, setEndpoints] = useState<AgentEndpoint[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);

  // Registration modal / form state
  const [showModal, setShowModal] = useState(false);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [eps, agts] = await Promise.all([
        apiRequest<AgentEndpoint[]>("/atp/endpoints"),
        apiRequest<Agent[]>("/agents"),
      ]);
      setEndpoints(eps || []);
      setAgents(agts || []);
      if (agts && agts.length > 0 && !selectedAgentId) {
        setSelectedAgentId(agts[0].id);
      }
    } catch (err) {
      console.error("Failed to load endpoints", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      await apiRequest<AgentEndpoint>("/atp/endpoints", {
        method: "POST",
        body: JSON.stringify({
          agent_id: selectedAgentId,
          endpoint_url: endpointUrl,
        }),
      });
      setShowModal(false);
      setEndpointUrl("");
      fetchData();
    } catch (err: any) {
      setFormError(err.message || "Failed to register endpoint");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to remove this endpoint?")) return;
    try {
      await apiRequest(`/atp/endpoints/${id}`, { method: "DELETE" });
      fetchData();
    } catch (err) {
      console.error("Failed to delete endpoint", err);
    }
  };

  return (
    <div className="space-y-8 p-6 lg:p-8">
      <div className="flex items-center gap-2 text-sm text-slate-500">
        <Link href="/dashboard/gateway" className="inline-flex items-center gap-1 hover:text-slate-800">
          <ArrowLeft size={14} /> Protocol Gateway
        </Link>
        <span>/</span>
        <span className="font-semibold text-slate-900">Endpoints & SSRF Boundary</span>
      </div>

      <PageHeader
        title="Agent Destination Endpoints"
        description="Controlled HTTP(S) destinations for AI agents with automatic SSRF IP resolution defense and DNS rebinding protections."
        action={
          <div className="flex gap-3">
            <button
              onClick={fetchData}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold text-slate-700 shadow-xs hover:bg-slate-50"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="inline-flex items-center gap-2 rounded-lg bg-[#3157d5] px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#2949b7]"
            >
              <Plus size={16} /> Register Endpoint
            </button>
          </div>
        }
      />

      {/* Security notice banner */}
      <div className="flex items-start gap-3 rounded-xl border border-blue-100 bg-blue-50/60 p-4 text-xs text-blue-900">
        <CheckCircle2 size={18} className="shrink-0 text-blue-600 mt-0.5" />
        <p className="leading-relaxed">
          <strong>SSRF Boundary Enforcement:</strong> All registered URLs are validated before registration and verified immediately before outbound dispatch. Connections to private RFC 1918 subnets, AWS/GCP metadata services (<code>169.254.169.254</code>), loopback (<code>127.0.0.0/8</code>, <code>::1</code>), and IPv4-mapped IPv6 are strictly rejected.
        </p>
      </div>

      {loading ? (
        <LoadingState label="Loading endpoints" />
      ) : endpoints.length === 0 ? (
        <EmptyState
          title="No registered endpoints"
          description="Register an HTTP(S) endpoint URL to allow other verified agents to route ATP messages to your agent."
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs">
          <table className="w-full text-left text-sm text-slate-600">
            <thead className="border-b border-slate-200 bg-slate-50 text-xs font-semibold uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-3">Agent</th>
                <th className="px-5 py-3">Endpoint Destination URL</th>
                <th className="px-5 py-3">SSRF Verification</th>
                <th className="px-5 py-3">Registered At</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-normal">
              {endpoints.map((ep) => {
                const agent = agents.find((a) => a.id === ep.agent_id);
                return (
                  <tr key={ep.id} className="hover:bg-slate-50/80 transition">
                    <td className="px-5 py-3.5">
                      <p className="font-semibold text-slate-900">{agent?.name ?? "Unknown Agent"}</p>
                      <p className="font-mono text-xs text-slate-500">{agent?.agent_identifier ?? ep.agent_id}</p>
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-800 break-all">
                      {ep.endpoint_url}
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-semibold text-emerald-700">
                        <CheckCircle2 size={12} /> VERIFIED
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs text-slate-500">
                      {new Date(ep.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <button
                        onClick={() => handleDelete(ep.id)}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-red-600 hover:text-red-800"
                      >
                        <Trash2 size={13} /> Remove
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Registration Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-4 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl border border-slate-200">
            <h3 className="text-base font-semibold text-slate-900">Register Agent Destination Endpoint</h3>
            <p className="mt-1 text-xs text-slate-500">
              The Gateway will route ATP/1.0 messages addressed to this agent to the specified HTTPS URL.
            </p>

            <form onSubmit={handleRegister} className="mt-5 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wide">
                  Select Target Agent
                </label>
                <select
                  value={selectedAgentId}
                  onChange={(e) => setSelectedAgentId(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-800 focus:border-blue-500 focus:outline-none"
                  required
                >
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.agent_identifier})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wide">
                  Destination Endpoint URL (HTTPS)
                </label>
                <input
                  type="url"
                  placeholder="https://agent.example.com/atp/v1"
                  value={endpointUrl}
                  onChange={(e) => setEndpointUrl(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-800 focus:border-blue-500 focus:outline-none"
                  required
                />
                <p className="mt-1 text-[11px] text-slate-400">
                  Must be publicly resolvable. Private IPs and loopbacks will be rejected by SSRF protection.
                </p>
              </div>

              {formError && (
                <div className="rounded-lg bg-red-50 p-3 text-xs text-red-700 border border-red-200">
                  {formError}
                </div>
              )}

              <div className="mt-6 flex justify-end gap-3 border-t border-slate-200 pt-4">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="rounded-lg border border-slate-200 px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="rounded-lg bg-[#3157d5] px-4 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-[#2949b7] disabled:opacity-50"
                >
                  {submitting ? "Verifying SSRF..." : "Validate & Register"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
