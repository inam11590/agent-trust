"use client";

import { FormEvent, useEffect, useState } from "react";

import { PageHeader, buttonClass, inputClass } from "@/components/ui";
import { useAuth } from "@/contexts/auth-context";
import { apiRequest } from "@/lib/api/client";

type Policy = { require_mfa: boolean; require_sso: boolean; session_timeout_minutes: number; max_session_lifetime_minutes: number;
  allowed_email_domains: string[]; require_manual_approval_above_amount: string | null; approval_threshold_currency: string; block_critical_risk: boolean; require_approval_for_high_risk: boolean };
type Connection = { id: string; name: string; issuer: string; status: string; verified_at: string | null };

export default function OrganizationSecurityPage() {
  const { organization, role } = useAuth();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [message, setMessage] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [discoveryUrl, setDiscoveryUrl] = useState("");
  const [domains, setDomains] = useState("");

  async function reload(id: string) {
    const [p, c] = await Promise.all([
      apiRequest<Policy>(`/organizations/${id}/security-policy`),
      apiRequest<Connection[]>(`/organizations/${id}/sso/connections`),
    ]);
    setPolicy(p); setConnections(c);
  }
  useEffect(() => {
    if (!organization || role !== "owner") return;
    let active = true;
    Promise.all([apiRequest<Policy>(`/organizations/${organization.id}/security-policy`),
      apiRequest<Connection[]>(`/organizations/${organization.id}/sso/connections`)])
      .then(([p, c]) => { if (active) { setPolicy(p); setConnections(c); } })
      .catch((error: Error) => { if (active) setMessage(error.message); });
    return () => { active = false; };
  }, [organization, role]);
  if (!organization || role !== "owner") return <p>Only an organization owner can manage these settings.</p>;
  const id = organization.id;
  async function run(action: () => Promise<unknown>, success: string) {
    setMessage("");
    try { await action(); await reload(id); setMessage(success); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Unable to save security settings."); }
  }
  async function createConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await run(async () => {
      await apiRequest(`/organizations/${id}/sso/connections`, { method: "POST", body: JSON.stringify({
        name, issuer, client_id: clientId, client_secret: clientSecret, discovery_url: discoveryUrl,
        allowed_domains: domains.split(",").map((item) => item.trim()).filter(Boolean),
      }) });
      setClientSecret("");
    }, "SSO connection saved as draft. Test it before enabling it.");
  }
  return <div className="mx-auto max-w-4xl space-y-6"><PageHeader title="Organization security" description={`Owner controls for ${organization.name}.`} />
    {message && <p role="status" className="rounded-lg border border-slate-200 bg-white p-3 text-sm">{message}</p>}
    <section className="space-y-3 rounded-xl border border-slate-200 bg-white p-6"><h2 className="text-lg font-semibold">Verify your identity</h2><p className="text-sm text-slate-500">Required before changing policy or SSO settings. Verification lasts five minutes.</p>
      <input className={inputClass} type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" />
      <input className={inputClass} value={code} onChange={(event) => setCode(event.target.value)} placeholder="Authenticator code if MFA is enabled" />
      <button className={buttonClass} onClick={() => void run(() => apiRequest("/security/step-up", { method: "POST", body: JSON.stringify({ password, code: code || null }) }), "Identity verified for five minutes.")}>Verify identity</button>
    </section>
    {policy && <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-6"><h2 className="text-lg font-semibold">Security policy</h2>
      <label className="flex gap-3 text-sm"><input type="checkbox" checked={policy.require_mfa} onChange={(event) => setPolicy({ ...policy, require_mfa: event.target.checked })} />Require MFA for organization work</label>
      <label className="flex gap-3 text-sm"><input type="checkbox" checked={policy.require_sso} onChange={(event) => setPolicy({ ...policy, require_sso: event.target.checked })} />Require SSO for members; owner retains recovery access</label>
      <label className="block text-sm">Session inactivity (minutes)<input className={inputClass} type="number" min="5" max="60" value={policy.session_timeout_minutes} onChange={(event) => setPolicy({ ...policy, session_timeout_minutes: Number(event.target.value) })} /></label>
      <label className="block text-sm">Maximum session lifetime (minutes)<input className={inputClass} type="number" min="15" max="1440" value={policy.max_session_lifetime_minutes} onChange={(event) => setPolicy({ ...policy, max_session_lifetime_minutes: Number(event.target.value) })} /></label>
      <label className="block text-sm">Approved email domains (comma separated)<input className={inputClass} value={policy.allowed_email_domains.join(", ")} onChange={(event) => setPolicy({ ...policy, allowed_email_domains: event.target.value.split(",").map((value) => value.trim()).filter(Boolean) })} /></label>
      <label className="block text-sm">Manual approval for purchases above<input className={inputClass} type="number" min="0" step="0.01" value={policy.require_manual_approval_above_amount ?? ""} onChange={(event) => setPolicy({ ...policy, require_manual_approval_above_amount: event.target.value || null })} /></label>
      <label className="block text-sm">Threshold currency (three-letter code)<input className={inputClass} maxLength={3} pattern="[A-Z]{3}" value={policy.approval_threshold_currency} onChange={(event) => setPolicy({ ...policy, approval_threshold_currency: event.target.value.toUpperCase() })} /></label>
      <label className="flex gap-3 text-sm"><input type="checkbox" checked={policy.block_critical_risk} onChange={(event) => setPolicy({ ...policy, block_critical_risk: event.target.checked })} />Block critical risk</label>
      <label className="flex gap-3 text-sm"><input type="checkbox" checked={policy.require_approval_for_high_risk} onChange={(event) => setPolicy({ ...policy, require_approval_for_high_risk: event.target.checked })} />Require approval for high risk</label>
      <button className={buttonClass} onClick={() => void run(() => apiRequest(`/organizations/${id}/security-policy`, { method: "PUT", body: JSON.stringify(policy) }), "Security policy saved.")}>Save policy</button>
    </section>}
    <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-6"><h2 className="text-lg font-semibold">Single Sign-On (OIDC)</h2><p className="text-sm text-slate-500">Only existing organization members can sign in. The client secret is never shown again after saving.</p>
      <ul className="divide-y divide-slate-100">{connections.map((item) => <li key={item.id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm"><div><p className="font-medium">{item.name} · {item.status}</p><p className="text-slate-500">{item.issuer}</p></div><div className="flex gap-3"><button className="text-blue-700" onClick={() => void run(() => apiRequest(`/organizations/${id}/sso/connections/${item.id}/test`, { method: "POST" }), "Provider discovery verified.")}>Test</button><button className="text-blue-700" onClick={() => void run(() => apiRequest(`/organizations/${id}/sso/connections/${item.id}/${item.status === "active" ? "disable" : "enable"}`, { method: "POST" }), "SSO setting updated.")}>{item.status === "active" ? "Disable" : "Enable"}</button></div></li>)}</ul>
      <form onSubmit={createConnection} className="grid gap-3"><h3 className="font-medium">Add OIDC connection</h3>
        <input className={inputClass} value={name} onChange={(event) => setName(event.target.value)} placeholder="Connection name" required />
        <input className={inputClass} value={issuer} onChange={(event) => setIssuer(event.target.value)} placeholder="Issuer URL (HTTPS)" required />
        <input className={inputClass} value={discoveryUrl} onChange={(event) => setDiscoveryUrl(event.target.value)} placeholder="Discovery URL (HTTPS)" required />
        <input className={inputClass} value={clientId} onChange={(event) => setClientId(event.target.value)} placeholder="Client ID" required />
        <input className={inputClass} type="password" value={clientSecret} onChange={(event) => setClientSecret(event.target.value)} placeholder="Client secret" required />
        <input className={inputClass} value={domains} onChange={(event) => setDomains(event.target.value)} placeholder="Allowed domains, comma separated" />
        <button className={buttonClass}>Save draft connection</button>
      </form>
    </section>
  </div>;
}
