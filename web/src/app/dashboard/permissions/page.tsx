"use client";

import { useState } from "react";

import { PermissionsTable } from "@/components/permissions-table";
import { EmptyState, ErrorState, LoadingState, PageHeader, PrimaryLink } from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import type { Agent, Permission } from "@/types";
import { useAuth } from "@/contexts/auth-context";

export default function PermissionsPage() {
  const { role = "owner" } = useAuth();
  const canManage = role === "owner" || role === "admin";
  const permissions = useApiQuery<Permission[]>("/permissions");
  const agents = useApiQuery<Agent[]>("/agents");
  const [revoking, setRevoking] = useState("");
  const [message, setMessage] = useState("");
  if (permissions.loading || agents.loading) return <LoadingState label="Loading permissions" />;
  if (permissions.error || agents.error) return <ErrorState message={permissions.error ?? agents.error ?? "Unable to load permissions."} retry={() => { permissions.reload(); agents.reload(); }} />;

  async function revoke(id: string) {
    if (!window.confirm("Revoke this permission now? The agent will lose this access immediately.")) return;
    setRevoking(id); setMessage("");
    try { await apiRequest(`/permissions/${id}/revoke`, { method: "POST" }); setMessage("Permission revoked successfully."); permissions.reload(); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to revoke permission."); }
    finally { setRevoking(""); }
  }

  return <div className="space-y-7"><PageHeader title="Permissions" description="Time-bound capabilities granted to your registered agents." action={canManage ? <PrimaryLink href="/dashboard/permissions/new">Create Permission</PrimaryLink> : undefined} />{message && <div role="status" className="rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-sm text-blue-800">{message}</div>}{permissions.data?.length ? <PermissionsTable permissions={permissions.data} agents={agents.data ?? []} onRevoke={canManage ? revoke : undefined} revoking={revoking} /> : <EmptyState title="No permissions found" description="Create a permission to define what an agent may do." />}</div>;
}
