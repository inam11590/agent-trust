"use client";

import { FormEvent, useState } from "react";

import { apiRequest } from "@/lib/api/client";
import { useApiQuery } from "@/hooks/use-api-query";
import { formatDate } from "@/lib/format";
import { buttonClass, inputClass, secondaryButtonClass, textareaClass } from "@/components/ui";

type SigningKey = { id: string; key_id: string; algorithm: string; fingerprint: string;
  status: string; created_at: string; last_used_at: string | null; expires_at: string | null };

export function SigningKeys({ agentId }: { agentId: string }) {
  const path = `/agents/${encodeURIComponent(agentId)}/signing-keys`;
  const keys = useApiQuery<SigningKey[]>(path);
  const [publicKey, setPublicKey] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [rotateFrom, setRotateFrom] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    const value = publicKey.trim();
    if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) {
      setMessage("Paste a base64-encoded 32-byte Ed25519 public key.");
      return;
    }
    setBusy(true);
    try {
      await apiRequest(rotateFrom ? `${path}/${encodeURIComponent(rotateFrom)}/rotate` : path,
        { method: "POST", body: JSON.stringify({ algorithm: "Ed25519", public_key: value,
          expires_at: expiresAt ? new Date(expiresAt).toISOString() : null }) });
      setPublicKey(""); setExpiresAt(""); setRotateFrom(null);
      setMessage("Public key saved. Keep its matching private key in your own secure storage.");
      keys.reload();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not save signing key."); }
    finally { setBusy(false); }
  }

  async function revoke(keyId: string) {
    if (!window.confirm("Revoke this key now? Requests signed with it will stop working.")) return;
    setBusy(true); setMessage("");
    try {
      await apiRequest(`${path}/${encodeURIComponent(keyId)}/revoke`, { method: "POST" });
      setMessage("Signing key revoked."); keys.reload();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not revoke signing key."); }
    finally { setBusy(false); }
  }

  return <section className="space-y-4 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
    <div><h2 className="text-lg font-semibold text-slate-950">Signing keys</h2>
      <p className="mt-1 text-sm text-slate-500">Public keys prove which agent sent a developer API request. Never paste your private key here.</p></div>
    {message && <p role="status" className="rounded-lg bg-slate-50 p-3 text-sm">{message}</p>}
    {keys.error && <p role="alert" className="text-sm text-red-600">{keys.error}</p>}
    {keys.loading ? <p className="text-sm text-slate-500">Loading signing keys…</p> :
      <div className="overflow-x-auto"><table className="w-full min-w-[680px] text-left text-sm">
        <thead className="border-b text-xs uppercase text-slate-500"><tr><th className="py-2">Key ID</th><th>Algorithm</th><th>Fingerprint</th><th>Status</th><th>Created</th><th>Last used</th><th>Expires</th><th>Actions</th></tr></thead>
        <tbody className="divide-y">{(keys.data ?? []).map((key) => <tr key={key.id}>
          <td className="py-3 font-mono text-xs">{key.key_id}</td><td>{key.algorithm}</td>
          <td className="font-mono text-xs" title={`SHA256: ${key.fingerprint}`}>SHA256: {key.fingerprint.slice(0, 12)}…</td>
          <td>{key.status}</td><td>{formatDate(key.created_at, true)}</td>
          <td>{key.last_used_at ? formatDate(key.last_used_at, true) : "Never"}</td>
          <td>{key.expires_at ? formatDate(key.expires_at, true) : "No expiry"}</td>
          <td className="space-x-2">{["ACTIVE", "ROTATING"].includes(key.status) && <>
            <button className="text-blue-700" onClick={() => { setRotateFrom(key.key_id); setMessage(`Paste the new public key to rotate ${key.key_id}.`); }}>Rotate</button>
            <button className="text-red-700" disabled={busy} onClick={() => void revoke(key.key_id)}>Revoke</button>
          </>}</td></tr>)}</tbody></table>
        {!keys.data?.length && <p className="py-4 text-sm text-slate-500">No signing keys registered.</p>}</div>}
    <form onSubmit={save} className="space-y-3 border-t pt-4">
      <h3 className="font-medium">{rotateFrom ? `Rotate ${rotateFrom}` : "Add public key"}</h3>
      <label className="block text-sm">Ed25519 public key (base64, 32 bytes)
        <textarea className={textareaClass} value={publicKey} onChange={(event) => setPublicKey(event.target.value)} required rows={2} maxLength={200} />
      </label>
      <label className="block text-sm">Optional expiry
        <input className={inputClass} type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
      </label>
      <div className="flex gap-2"><button className={buttonClass} disabled={busy}>{busy ? "Saving…" : rotateFrom ? "Rotate key" : "Add public key"}</button>
        {rotateFrom && <button type="button" className={secondaryButtonClass} onClick={() => setRotateFrom(null)}>Cancel rotation</button>}</div>
    </form>
  </section>;
}
