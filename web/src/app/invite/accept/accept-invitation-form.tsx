"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { apiRequest } from "@/lib/api/client";
import { buttonClass } from "@/components/ui";
import type { OrganizationMember } from "@/types";

export function AcceptInvitationForm({ token }: { token: string }) {
  const router = useRouter();
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function accept() {
    setBusy(true); setMessage("");
    try {
      const member = await apiRequest<OrganizationMember>("/invitations/accept", {
        method: "POST", body: JSON.stringify({ token }),
      });
      window.localStorage.setItem("agenttrust_organization_id", member.organization_id);
      router.push("/dashboard/team");
      router.refresh();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Unable to accept invitation. Sign in with the invited email and try again.");
    } finally { setBusy(false); }
  }

  return <main className="grid min-h-screen place-items-center bg-slate-50 p-5"><div className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm"><h1 className="text-2xl font-semibold text-slate-950">Join organization</h1><p className="mt-3 text-sm leading-6 text-slate-600">Sign in or register with the invited email, then accept this invitation.</p>{message && <p role="alert" className="mt-5 rounded-lg bg-red-50 p-3 text-sm text-red-700">{message}</p>}<button disabled={busy || token.length < 32} onClick={accept} className={`${buttonClass} mt-6 w-full`}>{busy ? "Accepting…" : "Accept invitation"}</button><Link href={`/login?next=${encodeURIComponent(`/invite/accept?token=${token}`)}`} className="mt-4 inline-block text-sm font-semibold text-blue-700">Sign in first</Link></div></main>;
}
