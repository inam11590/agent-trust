"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { 
  CheckCircle2, 
  Globe, 
  Layers, 
  Plus, 
  RefreshCw, 
  Search, 
  Server, 
  Shield, 
  ShieldAlert, 
  Zap 
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import { PageHeader, StatusBadge } from "@/components/ui";

interface ServiceItem {
  id: string;
  service_id: string;
  name: string;
  description?: string;
  version: string;
  status: string;
  visibility: string;
  environment: string;
  capabilities_count: number;
  endpoints_count: number;
  created_at: string;
}

export default function ServicesPage() {
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [visibilityFilter, setVisibilityFilter] = useState("");

  const fetchServices = async () => {
    setLoading(true);
    try {
      const res = await apiRequest<{ items: ServiceItem[]; total: number }>("/api/v1/services");
      setServices(res.items || []);
    } catch (err) {
      console.error("Failed to load services", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchServices();
  }, []);

  const filtered = services.filter((s) => {
    const matchesSearch = s.name.toLowerCase().includes(search.toLowerCase()) ||
                          s.service_id.toLowerCase().includes(search.toLowerCase());
    const matchesStatus = !statusFilter || s.status === statusFilter;
    const matchesVisibility = !visibilityFilter || s.visibility === visibilityFilter;
    return matchesSearch && matchesStatus && matchesVisibility;
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Service Registry"
        description="Authoritative, tenant-isolated catalog of AI agent services, endpoints, and capabilities."
        action={
          <div className="flex gap-2">
            <button
              onClick={fetchServices}
              className="inline-flex items-center gap-1 px-3 py-2 border rounded-md text-sm hover:bg-muted"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
            <Link
              href="/dashboard/capabilities"
              className="inline-flex items-center gap-1 px-3 py-2 border rounded-md text-sm hover:bg-muted"
            >
              <Zap className="w-4 h-4 text-amber-500" />
              Capabilities Catalog
            </Link>
          </div>
        }
      />

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between items-center bg-card p-4 rounded-lg border">
        <div className="relative w-full sm:w-96">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search service name or svc_..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm rounded-md border bg-background"
          />
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="text-sm px-3 py-2 rounded-md border bg-background"
          >
            <option value="">All Statuses</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="DEGRADED">DEGRADED</option>
            <option value="DISABLED">DISABLED</option>
            <option value="RETIRED">RETIRED</option>
          </select>
          <select
            value={visibilityFilter}
            onChange={(e) => setVisibilityFilter(e.target.value)}
            className="text-sm px-3 py-2 rounded-md border bg-background"
          >
            <option value="">All Visibilities</option>
            <option value="PRIVATE">PRIVATE</option>
            <option value="ORGANIZATION">ORGANIZATION</option>
            <option value="TRUSTED_ORGANIZATIONS">TRUSTED_ORGANIZATIONS</option>
            <option value="PUBLIC_DISCOVERABLE">PUBLIC_DISCOVERABLE</option>
          </select>
        </div>
      </div>

      {/* Services Table */}
      <div className="border rounded-lg bg-card overflow-hidden">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
            <tr>
              <th className="p-4">Service</th>
              <th className="p-4">Status</th>
              <th className="p-4">Visibility</th>
              <th className="p-4">Environment</th>
              <th className="p-4">Capabilities</th>
              <th className="p-4">Endpoints</th>
              <th className="p-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="p-8 text-center text-muted-foreground">
                  {loading ? "Loading services..." : "No registered services found."}
                </td>
              </tr>
            ) : (
              filtered.map((s) => (
                <tr key={s.id} className="hover:bg-muted/30">
                  <td className="p-4">
                    <div className="font-semibold text-foreground flex items-center gap-2">
                      <Server className="w-4 h-4 text-blue-500" />
                      <Link href={`/dashboard/services/${s.service_id}`} className="hover:underline">
                        {s.name}
                      </Link>
                    </div>
                    <div className="text-xs text-muted-foreground font-mono mt-0.5">
                      {s.service_id} &bull; v{s.version}
                    </div>
                  </td>
                  <td className="p-4">
                    <StatusBadge status={s.status.toLowerCase()} />
                  </td>
                  <td className="p-4">
                    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border font-mono">
                      <Globe className="w-3 h-3 text-muted-foreground" />
                      {s.visibility}
                    </span>
                  </td>
                  <td className="p-4 text-xs font-mono">{s.environment}</td>
                  <td className="p-4 text-sm font-medium">{s.capabilities_count}</td>
                  <td className="p-4 text-sm font-medium">{s.endpoints_count}</td>
                  <td className="p-4 text-right">
                    <Link
                      href={`/dashboard/services/${s.service_id}`}
                      className="text-xs px-2.5 py-1.5 border rounded hover:bg-muted"
                    >
                      Inspect
                    </Link>
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
