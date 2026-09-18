"use client";

import { FormEvent, useState } from "react";

import { useAuth } from "@/contexts/auth-context";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";
import { ErrorState, LoadingState, PageHeader, StatusBadge, buttonClass, inputClass, secondaryButtonClass } from "@/components/ui";
import type { Invitation, Organization, OrganizationMember, OrganizationRole } from "@/types";

export default function TeamPage() {
  const auth = useAuth();
  return auth.organization ? <OrganizationTeam /> : <PersonalTeam />;
}

function PersonalTeam() {
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function create(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const organization = await apiRequest<Organization>("/organizations", {
        method: "POST", body: JSON.stringify({ name }),
      });
      window.localStorage.setItem("agenttrust_organization_id", organization.id);
      window.location.reload();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to create organization.");
    } finally { setBusy(false); }
  }

  return <div className="mx-auto max-w-2xl space-y-7">
    <PageHeader title="Team" description="Create an organization to work safely with other people." />
    <form onSubmit={create} className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="font-semibold text-slate-950">Create organization</h2>
      <p className="mt-1 text-sm text-slate-500">You will become its owner.</p>
      {error && <p role="alert" className="mt-4 rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
      <label className="mt-5 block text-sm font-medium text-slate-700">Organization name
        <input className={`${inputClass} mt-2`} value={name} onChange={(event) => setName(event.target.value)} maxLength={200} required placeholder="SkyTravel" />
      </label>
      <button className={`${buttonClass} mt-5`} disabled={busy}>{busy ? "Creating…" : "Create organization"}</button>
    </form>
  </div>;
}

function OrganizationTeam() {
  const { user, organization, role } = useAuth();
  const members = useApiQuery<OrganizationMember[]>(`/organizations/${organization!.id}/members`);
  const [showInvite, setShowInvite] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const canManage = role === "owner" || role === "admin";

  if (members.loading) return <LoadingState label="Loading team" />;
  if (members.error) return <ErrorState message={members.error} retry={members.reload} />;

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(""); setMessage("");
    const data = new FormData(event.currentTarget);
    try {
      const result = await apiRequest<Invitation>(`/organizations/${organization!.id}/invitations`, {
        method: "POST",
        body: JSON.stringify({ email: String(data.get("email")), role: String(data.get("role")) }),
      });
      setShowInvite(false);
      setMessage(result.invitation_url ? `Invitation created. Development link: ${result.invitation_url}` : "Invitation sent.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to invite member."); }
  }

  async function changeRole(member: OrganizationMember, nextRole: OrganizationRole) {
    setError("");
    try {
      await apiRequest(`/organizations/${organization!.id}/members/${member.id}`, {
        method: "PATCH", body: JSON.stringify({ role: nextRole }),
      });
      setMessage("Member role updated."); members.reload();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to update role."); }
  }

  async function remove(member: OrganizationMember) {
    if (!window.confirm(`Remove ${member.full_name} from this organization?`)) return;
    setError("");
    try {
      await apiRequest(`/organizations/${organization!.id}/members/${member.id}`, { method: "DELETE" });
      setMessage("Member removed."); members.reload();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to remove member."); }
  }

  return <div className="space-y-7">
    <PageHeader title="Team" description={`${organization!.name} members and roles.`} action={canManage ? <button className={buttonClass} onClick={() => setShowInvite(true)}>Invite Member</button> : undefined} />
    {message && <p role="status" className="break-all rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">{message}</p>}
    {error && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</p>}
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm"><table className="w-full min-w-[850px] text-left text-sm">
      <thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr>{["Name", "Email", "Role", "Status", "Joined", "Actions"].map((label) => <th key={label} className="px-5 py-3">{label}</th>)}</tr></thead>
      <tbody className="divide-y divide-slate-100">{members.data?.map((member) => {
        const editable = canManage && member.role !== "owner" && member.user_id !== user.id && member.status === "active";
        return <tr key={member.id}><td className="px-5 py-4 font-medium">{member.full_name}</td><td className="px-5 py-4 text-slate-600">{member.email}</td><td className="px-5 py-4">{editable ? <select aria-label={`Role for ${member.full_name}`} className={inputClass} value={member.role} onChange={(event) => changeRole(member, event.target.value as OrganizationRole)}><option value="admin">Admin</option><option value="developer">Developer</option><option value="viewer">Viewer</option></select> : <span className="capitalize">{member.role}</span>}</td><td className="px-5 py-4"><StatusBadge value={member.status} /></td><td className="px-5 py-4 text-slate-500">{formatDate(member.joined_at)}</td><td className="px-5 py-4">{editable && <button className="font-semibold text-red-600" onClick={() => remove(member)}>Remove</button>}</td></tr>;
      })}</tbody>
    </table></div>
    {showInvite && <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4"><form onSubmit={invite} className="w-full max-w-md space-y-5 rounded-xl bg-white p-6 shadow-2xl"><h2 className="text-lg font-semibold">Invite Member</h2><label className="block text-sm font-medium">Email<input name="email" type="email" required className={`${inputClass} mt-2`} /></label><label className="block text-sm font-medium">Role<select name="role" className={`${inputClass} mt-2`} defaultValue="developer"><option value="admin">Admin</option><option value="developer">Developer</option><option value="viewer">Viewer</option></select></label><div className="flex justify-end gap-3"><button type="button" className={secondaryButtonClass} onClick={() => setShowInvite(false)}>Cancel</button><button className={buttonClass}>Create invitation</button></div></form></div>}
  </div>;
}
