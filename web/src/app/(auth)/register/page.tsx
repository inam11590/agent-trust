"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { Field, buttonClass, inputClass } from "@/components/ui";
import { authRequest } from "@/lib/api/client";
import type { User } from "@/types";

export default function RegisterPage() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const password = String(form.get("password"));
    if (password !== String(form.get("confirm_password"))) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await authRequest<User>("register", {
        full_name: String(form.get("full_name")),
        email: String(form.get("email")),
        password,
      });
      formElement.reset();
      router.push("/login?registered=1");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to create your account.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <p className="text-sm font-semibold text-[#3157d5]">Create your workspace</p>
      <h2 className="mt-2 text-3xl font-semibold tracking-[-0.035em] text-slate-950">Start with AgentTrust</h2>
      <p className="mt-3 text-sm leading-6 text-slate-500">Set clear controls before your AI agents take action.</p>
      <form onSubmit={submit} className="mt-8 space-y-4">
        {error && <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>}
        <Field label="Full name"><input className={inputClass} name="full_name" autoComplete="name" required placeholder="Inam" /></Field>
        <Field label="Email address"><input className={inputClass} name="email" type="email" autoComplete="email" required placeholder="you@company.com" /></Field>
        <Field label="Password" hint="Use at least 15 characters."><input className={inputClass} name="password" type="password" minLength={15} maxLength={128} autoComplete="new-password" required /></Field>
        <Field label="Confirm password"><input className={inputClass} name="confirm_password" type="password" minLength={15} maxLength={128} autoComplete="new-password" required /></Field>
        <button className={`${buttonClass} mt-2 w-full`} disabled={loading}>{loading ? "Creating account…" : "Create account"}</button>
      </form>
      <p className="mt-6 text-center text-sm text-slate-500">Already have an account? <Link className="font-semibold text-[#3157d5] hover:underline" href="/login">Sign in</Link></p>
    </>
  );
}
