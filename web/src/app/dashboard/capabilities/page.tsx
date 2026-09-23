"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { 
  ArrowLeft, 
  CheckCircle2, 
  Layers, 
  RefreshCw, 
  Search, 
  Server, 
  Shield, 
  ShieldAlert, 
  Zap 
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import { PageHeader, StatusBadge } from "@/components/ui";

interface CapabilityCatalogItem {
  id: string;
  capability_id: string;
  organization_id: string;
  agent_id: string;
  service_id?: string;
  name: string;
  version: string;
  description?: string;
  risk_classification: string;
  requires_approval: boolean;
  approval_threshold_amount?: number;
  rate_limit_per_minute?: number;
  is_active: boolean;
}

export default function CapabilitiesCatalogPage() {
  const [capabilities, setCapabilities] = useState<CapabilityCatalogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("");

  const fetchCapabilities = async () => {
    setLoading(true);
    try {
      const res = await apiRequest<{ items: CapabilityCatalogItem[]; total: number }>("/api/v1/capabilities");
      setCapabilities(res.items || []);
    } catch (err) {
      console.error("Failed to load capabilities", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCapabilities();
  }, []);

  const filtered = capabilities.filter((c) => {
    const matchesSearch = c.name.toLowerCase().includes(search.toLowerCase()) ||
                          (c.capability_id && c.capability_id.toLowerCase().includes(search.toLowerCase()));
    const matchesRisk = !riskFilter || c.risk_classification === riskFilter;
    return matchesSearch && matchesRisk;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Link href="/dashboard/services" className="hover:underline flex items-center gap-1">
          <ArrowLeft className="w-4 h-4" /> Back to Services
        </Link>
      </div>

      <PageHeader
        title="Agent Capability Catalog"
        description="Global catalog of published AI agent capabilities, risk classifications, and schema specifications."
        action={
          <button
            onClick={fetchCapabilities}
            className="inline-flex items-center gap-1 px-3 py-2 border rounded-md text-sm hover:bg-muted"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        }
      />

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-card p-4 rounded-lg border">
        <div className="relative w-full sm:w-96">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search capability (e.g. text.summarize or cap_...)"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm rounded-md border bg-background"
          />
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="text-sm px-3 py-2 rounded-md border bg-background"
          >
            <option value="">All Risk Tiers</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
        </div>
      </div>

      {/* Capabilities Table */}
      <div className="border rounded-lg bg-card overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
            <tr>
              <th className="p-4">Capability Name</th>
              <th className="p-4">Version</th>
              <th className="p-4">Risk Tier</th>
              <th className="p-4">Human Approval</th>
              <th className="p-4">Monetary Limit</th>
              <th className="p-4">Rate Limit</th>
              <th className="p-4">Service Binding</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-muted-foreground">
                  {loading ? "Loading capabilities..." : "No capabilities found matching criteria."}
                </td>
              </tr>
            ) : (
              filtered.map((c) => (
                <tr key={c.id} className="hover:bg-muted/30">
                  <td className="p-4">
                    <div className="font-semibold text-foreground font-mono flex items-center gap-1.5">
                      <Zap className="w-4 h-4 text-amber-500" />
                      {c.name}
                    </div>
                    <div className="text-xs text-muted-foreground font-mono mt-0.5">
                      {c.capability_id || "Legacy Capability"}
                    </div>
                  </td>
                  <td className="p-4 text-xs font-mono">v{c.version}</td>
                  <td className="p-4">
                    <span className="text-xs font-mono px-2 py-0.5 rounded border">
                      {c.risk_classification}
                    </span>
                  </td>
                  <td className="p-4">
                    {c.requires_approval ? (
                      <span className="text-xs text-amber-600 font-semibold flex items-center gap-1">
                        <ShieldAlert className="w-3.5 h-3.5" /> Required
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">Standard</span>
                    )}
                  </td>
                  <td className="p-4 text-xs font-mono">
                    {c.approval_threshold_amount ? `$${c.approval_threshold_amount}` : "None"}
                  </td>
                  <td className="p-4 text-xs font-mono">
                    {c.rate_limit_per_minute ? `${c.rate_limit_per_minute}/min` : "Unlimited"}
                  </td>
                  <td className="p-4 text-xs font-mono text-muted-foreground">
                    {c.service_id ? "Bound to Service" : "Agent Direct"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
