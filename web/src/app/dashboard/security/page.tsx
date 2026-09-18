"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { PageHeader, buttonClass, inputClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";

type MFAStatus = { enabled: boolean; pending: boolean; recovery_codes_remaining: number };
type Setup = { secret: string; otpauth_uri: string; qr_svg_data_url: string };
type Session = { id: string; user_agent_summary: string; device_type: string; auth_method: string; last_active_at: string; expires_at: string; current: boolean };

export default function SecurityPage() {
  const { organization, role, logout } = useAuth();
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [setup, setSetup] = useState<Setup | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [verifyPassword, setVerifyPassword] = useState("");
  const [verifyCode, setVerifyCode] = useState("");
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordCode, setPasswordCode] = useState("");
  const [message, setMessage] = useState("");

  async function reload() {
    const [mfa, active] = await Promise.all([
      apiRequest<MFAStatus>("/security/mfa"), apiRequest<Session[]>("/security/sessions"),
    ]);
    setStatus(mfa); setSessions(active);
  }
  useEffect(() => {
    let active = true;
    Promise.all([apiRequest<MFAStatus>("/security/mfa"), apiRequest<Session[]>("/security/sessions")])
      .then(([mfa, sessions]) => { if (active) { setStatus(mfa); setSessions(sessions); } })
      .catch((reason: Error) => { if (active) setMessage(reason.message); });
    return () => { active = false; };
  }, []);

  async function run(action: () => Promise<unknown>, success: string) {
    setMessage("");
    try { await action(); await reload(); setMessage(success); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Action failed."); }
  }

  async function beginSetup() {
    setMessage("");
    try { setSetup(await apiRequest<Setup>("/security/mfa/setup", { method: "POST" })); }
    catch (reason) { setMessage(reason instanceof Error ? reason.message : "Unable to start MFA setup."); }
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await run(async () => {
      const result = await apiRequest<{ recovery_codes: string[] }>("/security/mfa/confirm", { method: "POST", body: JSON.stringify({ code }) });
      setRecoveryCodes(result.recovery_codes); setSetup(null); setCode("");
    }, "Two-factor authentication is enabled. Save your recovery codes now.");
  }

  async function regenerate() {
    await run(async () => {
      const result = await apiRequest<{ recovery_codes: string[] }>("/security/mfa/recovery-codes", { method: "POST", body: JSON.stringify({ code }) });
      setRecoveryCodes(result.recovery_codes); setCode("");
    }, "Old recovery codes are invalid. Save the new codes now.");
  }

  return <div className="mx-auto max-w-4xl space-y-6">
    <PageHeader title="Security" description="Protect your account and review active sessions." />
    {message && <p role="status" className="rounded-lg border border-slate-200 bg-white p-3 text-sm text-slate-700">{message}</p>}
    <section className="space-y-3 rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h2 className="text-lg font-semibold">Verify your identity</h2><p className="text-sm text-slate-500">Required before sensitive account changes. Verification lasts five minutes.</p>
      <input className={inputClass} type="password" value={verifyPassword} onChange={(event) => setVerifyPassword(event.target.value)} placeholder="Password" autoComplete="current-password" />
      {status?.enabled && <input className={inputClass} value={verifyCode} onChange={(event) => setVerifyCode(event.target.value)} placeholder="Authenticator or recovery code" autoComplete="one-time-code" />}
      <button className={buttonClass} disabled={!verifyPassword} onClick={() => void run(async () => { await apiRequest("/security/step-up", { method: "POST", body: JSON.stringify({ password: verifyPassword, code: verifyCode || null }) }); setVerifyPassword(""); setVerifyCode(""); }, "Identity verified for five minutes.")}>Verify identity</button>
    </section>
    <section className="space-y-3 rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h2 className="text-lg font-semibold">Password</h2><p className="text-sm text-slate-500">Changing your password signs out your other devices.</p>
      <input className={inputClass} type="password" value={oldPassword} onChange={(event) => setOldPassword(event.target.value)} placeholder="Current password" autoComplete="current-password" />
      <input className={inputClass} type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} placeholder="New password (15 characters or more)" autoComplete="new-password" />
      {status?.enabled && <input className={inputClass} value={passwordCode} onChange={(event) => setPasswordCode(event.target.value)} placeholder="Authenticator or recovery code" autoComplete="one-time-code" />}
      <button className={buttonClass} disabled={!oldPassword || newPassword.length < 15} onClick={() => void run(async () => { await apiRequest<void>("/security/password", { method: "POST", body: JSON.stringify({ current_password: oldPassword, new_password: newPassword, code: passwordCode || null }) }); setOldPassword(""); setNewPassword(""); setPasswordCode(""); }, "Password changed. Other sessions have been signed out.")}>Change password</button>
    </section>
    <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div><h2 className="text-lg font-semibold">Two-factor authentication</h2><p className="text-sm text-slate-500">{status?.enabled ? "Enabled" : "Not enabled"}. Use an authenticator app; SMS is not used.</p></div>
      {!status?.enabled && !setup && <button className={buttonClass} onClick={() => void beginSetup()}>Set up authenticator</button>}
      {setup && <form onSubmit={confirm} className="space-y-3">
        <p className="text-sm">Scan this QR code with your authenticator. Then enter its current six-digit code.</p>
        {/* The SVG is generated by the backend and contains only the one-time provisioning URI. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={setup.qr_svg_data_url} alt="Authenticator setup QR code" className="size-48" />
        <p className="break-all text-xs text-slate-500">Manual key: <code>{setup.secret}</code></p>
        <input className={inputClass} value={code} onChange={(event) => setCode(event.target.value)} placeholder="123456" autoComplete="one-time-code" required />
        <button className={buttonClass}>Verify and enable</button>
      </form>}
      {status?.enabled && <div className="space-y-3">
        <p className="text-sm text-slate-600">{status.recovery_codes_remaining} unused recovery codes remain.</p>
        <input className={inputClass} value={code} onChange={(event) => setCode(event.target.value)} placeholder="Current code or recovery code" autoComplete="one-time-code" />
        <div className="flex flex-wrap gap-2"><button className={buttonClass} onClick={() => void regenerate()} disabled={!code}>Regenerate recovery codes</button>
          <button className="rounded-lg border border-red-300 px-4 py-2 text-sm text-red-700" disabled={!code || !password}
            onClick={() => void run(async () => { await apiRequest<void>("/security/mfa/disable", { method: "POST", body: JSON.stringify({ code, password }) }); setCode(""); setPassword(""); }, "Two-factor authentication disabled.")}>Disable MFA</button></div>
        <input className={inputClass} type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password required to disable MFA" autoComplete="current-password" />
      </div>}
      {recoveryCodes && <div className="rounded-lg border border-amber-300 bg-amber-50 p-4"><p className="font-semibold">Save these codes now. They will not be shown again.</p><ul className="mt-3 grid grid-cols-2 gap-2 font-mono text-sm">{recoveryCodes.map((value) => <li key={value}>{value}</li>)}</ul><button className="mt-4 text-sm text-blue-700" onClick={() => setRecoveryCodes(null)}>I saved them</button></div>}
    </section>
    <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Active sessions</h2><button className="text-sm text-blue-700" onClick={() => void run(() => apiRequest("/security/sessions/revoke-others", { method: "POST" }), "Other sessions signed out.")}>Log out other sessions</button></div>
      <ul className="divide-y divide-slate-100">{sessions.map((item) => <li key={item.id} className="flex items-center justify-between gap-4 py-3 text-sm"><div><p className="font-medium">{item.user_agent_summary} {item.current && "(this device)"}</p><p className="text-slate-500">Last active {formatDate(item.last_active_at)} · {item.auth_method}</p></div><button className="text-red-700" onClick={() => void run(async () => { await apiRequest<void>(`/security/sessions/${item.id}/revoke`, { method: "POST" }); if (item.current) await logout(); }, "Session signed out.")}>Revoke</button></li>)}</ul>
    </section>
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h2 className="text-lg font-semibold">Security events</h2><p className="mt-1 text-sm text-slate-500">Review sign-ins, MFA changes, and session changes.</p><Link className="mt-3 inline-block text-sm font-medium text-blue-700" href="/dashboard/security/events">View security history</Link></section>
    {organization && role === "owner" && <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"><h2 className="text-lg font-semibold">Organization security</h2><p className="mt-1 text-sm text-slate-500">Configure MFA, SSO, and approval rules for {organization.name}.</p><Link className="mt-3 inline-block text-sm font-medium text-blue-700" href="/dashboard/security/organization">Manage organization security</Link></section>}
  </div>;
}
