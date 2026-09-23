"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { 
  ArrowLeft, 
  CheckCircle2, 
  Copy, 
  Globe, 
  Layers, 
  Play, 
  RefreshCw, 
  Server, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Zap 
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import { PageHeader, StatusBadge } from "@/components/ui";

interface ServiceDetail {
  id: string;
  service_id: string;
  organization_id: string;
  agent_id: string;
  name: string;
  description?: string;
  version: string;
  status: string;
  visibility: string;
  environment: string;
  metadata_json: Record<string, any>;
  created_at: string;
  updated_at: string;
}

interface CapabilityItem {
  id: string;
  capability_id: string;
  name: string;
  version: string;
  description?: string;
  risk_classification: string;
  requires_approval: boolean;
  approval_threshold_amount?: number;
}

interface EndpointItem {
  id: string;
  endpoint_id: string;
  protocol: string;
  url: string;
  priority: number;
  weight: number;
  environment: string;
  health_status: string;
  verified_at?: string;
}

export default function ServiceDetailPage() {
  const params = useParams();
  const serviceId = params?.id as string;

  const [service, setService] = useState<ServiceDetail | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilityItem[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [verifyLoading, setVerifyLoading] = useState<string | null>(null);

  const fetchDetails = async () => {
    if (!serviceId) return;
    setLoading(true);
    try {
      const [svc, caps, eps] = await Promise.all([
        apiRequest<ServiceDetail>(`/api/v1/services/${serviceId}`),
        apiRequest<{ items: CapabilityItem[] }>(`/api/v1/services/${serviceId}/capabilities`),
        apiRequest<EndpointItem[]>(`/api/v1/services/${serviceId}/endpoints`),
      ]);
      setService(svc);
      setCapabilities(caps.items || []);
      setEndpoints(eps || []);
    } catch (err) {
      console.error("Failed to load service details", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetails();
  }, [serviceId]);

  if (loading || !service) {
    return (
      <div className="p-8 text-center text-muted-foreground">
        Loading service details...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Link href="/dashboard/services" className="hover:underline flex items-center gap-1">
          <ArrowLeft className="w-4 h-4" /> Back to Services
        </Link>
      </div>

      <PageHeader
        title={service.name}
        description={`Service ID: ${service.service_id} • Environment: ${service.environment}`}
        action={
          <div className="flex items-center gap-2">
            <StatusBadge value={service.status.toLowerCase()} />
            <button
              onClick={fetchDetails}
              className="inline-flex items-center gap-1 px-3 py-2 border rounded-md text-sm hover:bg-muted"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        }
      />

      {/* Metadata Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="border rounded-lg p-4 bg-card">
          <div className="text-xs text-muted-foreground font-medium">Visibility</div>
          <div className="text-sm font-semibold mt-1 flex items-center gap-1 font-mono">
            <Globe className="w-4 h-4 text-blue-500" />
            {service.visibility}
          </div>
        </div>
        <div className="border rounded-lg p-4 bg-card">
          <div className="text-xs text-muted-foreground font-medium">Owning Agent</div>
          <div className="text-sm font-semibold mt-1 font-mono text-muted-foreground truncate">
            {service.agent_id}
          </div>
        </div>
        <div className="border rounded-lg p-4 bg-card">
          <div className="text-xs text-muted-foreground font-medium">Version</div>
          <div className="text-sm font-semibold mt-1 font-mono">v{service.version}</div>
        </div>
        <div className="border rounded-lg p-4 bg-card">
          <div className="text-xs text-muted-foreground font-medium">Registered At</div>
          <div className="text-sm font-semibold mt-1 text-muted-foreground">
            {new Date(service.created_at).toLocaleDateString()}
          </div>
        </div>
      </div>

      {/* Capabilities Section */}
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-500" />
            Published Capabilities ({capabilities.length})
          </h2>
        </div>
        <div className="border rounded-lg bg-card overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
              <tr>
                <th className="p-3">Capability</th>
                <th className="p-3">Version</th>
                <th className="p-3">Risk Tier</th>
                <th className="p-3">Approval Required</th>
                <th className="p-3">Threshold</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {capabilities.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-6 text-center text-muted-foreground">
                    No capabilities registered on this service.
                  </td>
                </tr>
              ) : (
                capabilities.map((c) => (
                  <tr key={c.id} className="hover:bg-muted/20">
                    <td className="p-3 font-semibold font-mono">{c.name}</td>
                    <td className="p-3 text-xs font-mono">v{c.version}</td>
                    <td className="p-3">
                      <span className="text-xs font-mono px-2 py-0.5 rounded border">
                        {c.risk_classification}
                      </span>
                    </td>
                    <td className="p-3">
                      {c.requires_approval ? (
                        <span className="text-xs text-amber-600 font-semibold flex items-center gap-1">
                          <ShieldAlert className="w-3.5 h-3.5" /> YES
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">No</span>
                      )}
                    </td>
                    <td className="p-3 text-xs font-mono">
                      {c.approval_threshold_amount ? `$${c.approval_threshold_amount}` : "None"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Endpoints Section */}
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-500" />
            Service Endpoints & Failover Priority ({endpoints.length})
          </h2>
        </div>
        <div className="border rounded-lg bg-card overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/50 border-b font-medium text-muted-foreground">
              <tr>
                <th className="p-3">Priority / Weight</th>
                <th className="p-3">Protocol & Destination</th>
                <th className="p-3">Environment</th>
                <th className="p-3">Health Status</th>
                <th className="p-3">Cryptographic Verification</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {endpoints.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-6 text-center text-muted-foreground">
                    No endpoints registered for this service.
                  </td>
                </tr>
              ) : (
                endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-muted/20">
                    <td className="p-3 font-mono font-semibold">
                      Priority {ep.priority} &bull; W:{ep.weight}
                    </td>
                    <td className="p-3">
                      <div className="font-mono text-xs">{ep.url}</div>
                      <div className="text-xs text-muted-foreground font-mono">{ep.protocol} &bull; {ep.endpoint_id}</div>
                    </td>
                    <td className="p-3 text-xs font-mono">{ep.environment}</td>
                    <td className="p-3">
                      <StatusBadge value={ep.health_status.toLowerCase()} />
                    </td>
                    <td className="p-3">
                      {ep.verified_at ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-600 font-medium">
                          <ShieldCheck className="w-4 h-4" /> Verified
                        </span>
                      ) : (
                        <span className="text-xs text-amber-600 font-medium">
                          Unverified
                        </span>
                      )}
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
