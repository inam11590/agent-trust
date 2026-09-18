"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { Field, buttonClass, inputClass } from "@/components/ui";
import { authRequest } from "@/lib/api/client";

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [challenge, setChallenge] = useState<string | null>(null);

  function finishLogin() {
    const requested = new URLSearchParams(window.location.search).get("next");
    const destination = requested?.startsWith("/") && !requested.startsWith("//")
      ? requested : "/dashboard";
    router.push(destination);
    router.refresh();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    setLoading(true);
    setError("");
    const form = new FormData(formElement);
    try {
      const result = await authRequest<{ status?: string; challenge_token?: string }>("login", {
        email: String(form.get("email")),
        password: String(form.get("password")),
      });
      formElement.reset();
      if (result.status === "MFA_REQUIRED" && result.challenge_token) {
        setChallenge(result.challenge_token);
      } else {
        finishLogin();
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to sign in.");
    } finally {
      setLoading(false);
    }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!challenge) return;
    setLoading(true); setError("");
    const form = event.currentTarget;
    try {
      await authRequest("mfa/verify", { challenge_token: challenge, code: String(new FormData(form).get("code")) });
      setChallenge(null);
      form.reset();
      finishLogin();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to verify the code.");
    } finally { setLoading(false); }
  }

  return (
    <>
      <p className="text-sm font-semibold text-[#3157d5]">Welcome back</p>
      <h2 className="mt-2 text-3xl font-semibold tracking-[-0.035em] text-slate-950">Sign in to AgentTrust</h2>
      <p className="mt-3 text-sm leading-6 text-slate-500">Manage agents, permissions, and authorization history.</p>
      {challenge ? <form onSubmit={verify} className="mt-8 space-y-5">
        <p className="text-sm text-slate-600">Enter the current code from your authenticator app, or a one-time recovery code.</p>
        {error && <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
        <Field label="Authenticator or recovery code"><input className={inputClass} name="code" autoComplete="one-time-code" required maxLength={64} /></Field>
        <button className={`${buttonClass} w-full`} disabled={loading}>{loading ? "Verifying…" : "Verify and sign in"}</button>
        <button type="button" className="text-sm text-blue-700" onClick={() => { setChallenge(null); setError(""); }}>Start again</button>
      </form> : <form onSubmit={submit} className="mt-8 space-y-5">
        {error && <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
        <Field label="Email address"><input className={inputClass} name="email" type="email" autoComplete="email" required placeholder="you@company.com" /></Field>
        <Field label="Password"><input className={inputClass} name="password" type="password" autoComplete="current-password" required placeholder="Enter your password" /></Field>
        <button className={`${buttonClass} w-full`} disabled={loading}>{loading ? "Signing in…" : "Sign in"}</button>
      </form>
      }
      {!challenge && <form action="/api/auth/sso/start" method="GET" className="mt-5 space-y-2 border-t border-slate-200 pt-5">
        <Field label="Company ID for SSO"><input className={inputClass} name="organization_id" placeholder="Organization UUID" required /></Field>
        <button className="w-full rounded-lg border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700">Continue with Company SSO</button>
      </form>}
      <p className="mt-6 text-center text-sm text-slate-500">New to AgentTrust? <Link className="font-semibold text-[#3157d5] hover:underline" href="/register">Create an account</Link></p>
    </>
  );
}
