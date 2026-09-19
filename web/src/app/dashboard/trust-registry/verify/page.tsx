"use client";

import { useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  Copy,
  FileCode,
  KeyRound,
  ShieldCheck,
  Terminal,
  XCircle,
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import type { CredentialVerificationResult } from "@/types";

const SAMPLE_CREDENTIAL = {
  credential_version: "ATC/1.0",
  credential_id: "cred_sample_test",
  credential_type: "AgentIdentityCredential",
  issuer: "iss_sample_hotelcorp",
  subject: {
    organization_id: "HotelCorp",
    agent_id: "agt_hotel_booking",
  },
  environment: "sandbox",
  issued_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 86400000 * 30).toISOString(),
  claims: {
    organization_membership: true,
    agent_identifier: "agt_hotel_booking",
  },
  proof: {
    type: "ATC-SIG/1",
    algorithm: "Ed25519",
    key_id: "iss_key_sample",
    signature: "base64-signature-placeholder",
  },
};

export default function CredentialVerifierPage() {
  const [jsonInput, setJsonInput] = useState("");
  const [environment, setEnvironment] = useState<"production" | "sandbox">("production");
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<CredentialVerificationResult | null>(null);
  const [errorDetails, setErrorDetails] = useState<{ message: string; code: string } | null>(null);

  const handleVerify = async () => {
    if (!jsonInput.trim()) {
      alert("Please paste an ATC/1.0 credential JSON object.");
      return;
    }
    let parsed: any;
    try {
      parsed = JSON.parse(jsonInput);
    } catch {
      alert("Invalid JSON format. Please paste valid JSON.");
      return;
    }

    setVerifying(true);
    setResult(null);
    setErrorDetails(null);

    try {
      const res = await apiRequest<CredentialVerificationResult>("/v1/credentials/verify", {
        method: "POST",
        body: JSON.stringify({
          credential: parsed,
          expected_environment: environment,
        }),
      });
      setResult(res);
    } catch (err: any) {
      setErrorDetails({
        message: err?.message || "Verification failed.",
        code: err?.details?.code || err?.code || "CREDENTIAL_INVALID",
      });
    } finally {
      setVerifying(false);
    }
  };

  const loadSample = () => {
    setJsonInput(JSON.stringify(SAMPLE_CREDENTIAL, null, 2));
    setEnvironment("sandbox");
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Link href="/dashboard/trust-registry" className="hover:text-white transition flex items-center gap-1">
          <ChevronLeft size={16} /> Trust Registry
        </Link>
        <span>/</span>
        <span className="text-white">Credential Verifier</span>
      </div>

      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Verifiable Credential Diagnostic Tool</h1>
        <p className="mt-1 text-sm text-slate-400">
          Cryptographically verify ATC/1.0 credentials against Trust Registry public keys, expiration, and status revocation.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: Input Form */}
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCode size={16} className="text-blue-400" />
              <h2 className="font-semibold text-white">Credential JSON Wire Format</h2>
            </div>
            <button
              onClick={loadSample}
              className="text-xs font-medium text-blue-400 hover:underline"
            >
              Load Sample
            </button>
          </div>

          <textarea
            value={jsonInput}
            onChange={(e) => setJsonInput(e.target.value)}
            rows={16}
            placeholder={`Paste ATC/1.0 JSON credential here...\n{\n  "credential_version": "ATC/1.0",\n  "credential_id": "cred_...",\n  "proof": { ... }\n}`}
            className="w-full rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-200 placeholder-slate-600 focus:border-blue-500 focus:outline-none"
          />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span>Expected Context:</span>
              <select
                value={environment}
                onChange={(e: any) => setEnvironment(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-white focus:outline-none"
              >
                <option value="production">Production</option>
                <option value="sandbox">Sandbox</option>
              </select>
            </div>

            <button
              onClick={handleVerify}
              disabled={verifying}
              className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500 transition disabled:opacity-50"
            >
              <ShieldCheck size={16} />
              {verifying ? "Verifying Proof..." : "Verify Credential"}
            </button>
          </div>
        </div>

        {/* Right Column: Diagnostic Verification Results */}
        <div className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Terminal size={16} className="text-slate-400" />
            <h2 className="font-semibold text-white">Verification Engine Diagnostics</h2>
          </div>

          {result ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4">
                <div className="flex items-center gap-3">
                  <CheckCircle2 size={24} className="text-emerald-400" />
                  <div>
                    <h3 className="font-bold text-emerald-300">OVERALL: VERIFIED</h3>
                    <p className="text-xs text-emerald-200/80">
                      Signature, issuer authority, expiration, and revocation checks passed.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800">
                  <span className="text-slate-400">Credential Signature</span>
                  <span className="font-semibold text-emerald-400 flex items-center gap-1"><CheckCircle2 size={12} /> PASS</span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800">
                  <span className="text-slate-400">Issuer Status</span>
                  <span className="font-semibold text-emerald-400 flex items-center gap-1"><CheckCircle2 size={12} /> ACTIVE</span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800">
                  <span className="text-slate-400">Subject Binding</span>
                  <span className="font-semibold text-emerald-400 flex items-center gap-1"><CheckCircle2 size={12} /> VALID</span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800">
                  <span className="text-slate-400">Temporal Expiration</span>
                  <span className="font-semibold text-emerald-400 flex items-center gap-1"><CheckCircle2 size={12} /> VALID</span>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2.5 border border-slate-800">
                  <span className="text-slate-400">Revocation Status</span>
                  <span className="font-semibold text-emerald-400 flex items-center gap-1"><CheckCircle2 size={12} /> CLEAR</span>
                </div>
              </div>

              <div className="rounded-lg bg-slate-950 p-3 text-xs border border-slate-800 space-y-1">
                <p><span className="text-slate-500">ID:</span> <span className="font-mono text-blue-400">{result.credential_id}</span></p>
                <p><span className="text-slate-500">Issuer:</span> <span className="font-mono text-slate-300">{result.issuer}</span></p>
                <p><span className="text-slate-500">Subject:</span> <span className="font-mono text-slate-300">{result.subject_agent_id}</span></p>
                <p><span className="text-slate-500">Type:</span> <span className="text-slate-300">{result.credential_type}</span></p>
                <p><span className="text-slate-500">Expires:</span> <span className="text-slate-300">{new Date(result.expires_at).toLocaleString()}</span></p>
              </div>
            </div>
          ) : errorDetails ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-4">
                <div className="flex items-center gap-3">
                  <XCircle size={24} className="text-red-400" />
                  <div>
                    <h3 className="font-bold text-red-300">OVERALL: INVALID</h3>
                    <p className="text-xs text-red-200/80 font-mono mt-0.5">{errorDetails.code}</p>
                  </div>
                </div>
              </div>
              <div className="rounded-lg bg-slate-950 p-3 text-xs border border-slate-800 text-red-300">
                {errorDetails.message}
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-sm text-slate-500">
              Paste a credential JSON on the left and click &quot;Verify Credential&quot; to inspect cryptographic validity, issuer status, and revocation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
