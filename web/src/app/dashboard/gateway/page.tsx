"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { 
  CheckCircle2, 
  Copy, 
  ExternalLink, 
  Key, 
  Layers, 
  Play, 
  Radio, 
  RefreshCw, 
  Send, 
  Shield, 
  ShieldCheck, 
  Waypoints 
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";
import { PageHeader, StatusBadge } from "@/components/ui";
import { GatewayIdentity, ATPMessageRecord } from "@/types";

export default function GatewayOverviewPage() {
  const [identity, setIdentity] = useState<GatewayIdentity | null>(null);
  const [health, setHealth] = useState<{ status: string; gateway: string; protocol: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  // Dispatch Playground state
  const [mockTarget, setMockTarget] = useState("atp://org_hotelcorp/agt_hotel");
  const [capability, setCapability] = useState("hotel.reserve@1.0");
  const [payloadText, setPayloadText] = useState(
    JSON.stringify({ hotel_id: "hotel_grand_hyatt", amount: 450, currency: "USD" }, null, 2)
  );
  const [dispatchLoading, setDispatchLoading] = useState(false);
  const [dispatchResult, setDispatchResult] = useState<any>(null);
  const [dispatchError, setDispatchError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [h, id] = await Promise.all([
        apiRequest<{ status: string; gateway: string; protocol: string }>("/atp/health"),
        apiRequest<GatewayIdentity>("/atp/gateway-identity"),
      ]);
      setHealth(h);
      setIdentity(id);
    } catch (err) {
      console.error("Failed to load gateway data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const copyKey = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleTestDispatch = async () => {
    setDispatchLoading(true);
    setDispatchResult(null);
    setDispatchError(null);
    try {
      let parsed = {};
      try {
        parsed = JSON.parse(payloadText);
      } catch (e) {
        setDispatchError("Invalid JSON in payload");
        setDispatchLoading(false);
        return;
      }

      // Quick test using mock sandbox agent directly via gateway
      const res = await apiRequest<any>("/atp/messages", {
        method: "POST",
        body: JSON.stringify({
          protocol: "ATP/1.0",
          message_id: `msg_sandbox_${Date.now()}`,
          message_type: "request",
          source: {
            address: "atp://org_sandbox/agt_tester",
          },
          target: {
            address: mockTarget,
          },
          capability: capability,
          timestamp: new Date().toISOString(),
          nonce: `nonce_${Math.random().toString(16).slice(2)}`,
          payload: parsed,
          signature: {
            version: "ATP-SIG/1",
            key_id: "key_sandbox_mock",
            value: "mock_signature_for_sandbox",
          },
        }),
      });
      setDispatchResult(res);
    } catch (err: any) {
      setDispatchError(err.message || "Failed to dispatch message");
    } finally {
      setDispatchLoading(false);
    }
  };

  return (
    <div className="space-y-8 p-6 lg:p-8">
      <PageHeader
        title="AgentTrust Protocol Gateway"
        description="Autonomous agent-to-agent communication router, Ed25519 identity verification, and SSRF boundary enforcement."
        action={
          <div className="flex gap-3">
            <Link
              href="/dashboard/gateway/messages"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50"
            >
              <Radio size={16} /> Messages Feed
            </Link>
            <Link
              href="/dashboard/gateway/endpoints"
              className="inline-flex items-center gap-2 rounded-lg bg-[#3157d5] px-3.5 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#2949b7]"
            >
              <Layers size={16} /> Endpoints & SSRF
            </Link>
          </div>
        }
      />

      {/* Gateway Status Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Gateway Status</span>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-semibold text-emerald-700">
              <span className="size-1.5 rounded-full bg-emerald-500 animate-pulse" />
              {health?.status ?? "OPERATIONAL"}
            </span>
          </div>
          <p className="mt-3 text-2xl font-bold text-slate-900">ATP/1.0</p>
          <p className="mt-1 text-xs text-slate-500">Active Specification Profile</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Signing Profile</span>
            <ShieldCheck size={18} className="text-blue-600" />
          </div>
          <p className="mt-3 text-2xl font-bold text-slate-900">ATP-SIG/1</p>
          <p className="mt-1 text-xs text-slate-500">Ed25519 Canonical Cryptography</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Attestation TTL</span>
            <Shield size={18} className="text-purple-600" />
          </div>
          <p className="mt-3 text-2xl font-bold text-slate-900">{identity?.attestation_ttl_seconds ?? 60}s</p>
          <p className="mt-1 text-xs text-slate-500">X-ATP-Gateway-Attestation Token</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">SSRF Enforcement</span>
            <CheckCircle2 size={18} className="text-emerald-600" />
          </div>
          <p className="mt-3 text-2xl font-bold text-slate-900">Strict Pinning</p>
          <p className="mt-1 text-xs text-slate-500">RFC 1918 & Cloud Metadata Deny</p>
        </div>
      </div>

      {/* Gateway Cryptographic Identity Box */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <div>
            <h2 className="text-base font-semibold text-slate-900">Gateway Public Attestation Identity</h2>
            <p className="text-sm text-slate-500">
              Receiving agent endpoints must verify the <code>X-ATP-Gateway-Attestation</code> token against this public key.
            </p>
          </div>
          <button
            onClick={fetchData}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh Key
          </button>
        </div>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg bg-slate-50 p-4 border border-slate-100">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-600">Key Identifier (kid)</span>
              <span className="rounded bg-slate-200/60 px-2 py-0.5 text-xs font-mono font-medium text-slate-800">
                {identity?.key_id ?? "gateway_key_primary"}
              </span>
            </div>
            <div className="mt-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-slate-600">Base64 Raw Ed25519 Public Key</span>
                <button
                  onClick={() => copyKey(identity?.public_key_base64 || "")}
                  className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
                >
                  <Copy size={12} /> {copied ? "Copied!" : "Copy"}
                </button>
              </div>
              <pre className="overflow-x-auto rounded bg-white p-2.5 text-xs font-mono text-slate-800 border border-slate-200">
                {identity?.public_key_base64 ?? "Loading key..."}
              </pre>
            </div>
          </div>

          <div className="rounded-lg bg-slate-50 p-4 border border-slate-100">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-semibold text-slate-600">PEM SubjectPublicKeyInfo</span>
              <button
                onClick={() => copyKey(identity?.public_key_pem || "")}
                className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
              >
                <Copy size={12} /> Copy PEM
              </button>
            </div>
            <pre className="h-28 overflow-y-auto rounded bg-white p-2.5 text-[11px] font-mono leading-relaxed text-slate-700 border border-slate-200">
              {identity?.public_key_pem ?? "Loading PEM..."}
            </pre>
          </div>
        </div>
      </div>

      {/* Interactive Gateway Sandbox Dispatcher */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs">
        <div className="border-b border-slate-200 pb-4">
          <h2 className="text-base font-semibold text-slate-900">Sandbox Protocol Dispatcher</h2>
          <p className="text-sm text-slate-500">
            Test routing ATP/1.0 messages to simulated or registered agents through the Gateway pipeline.
          </p>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wide">
                Target Agent ATP Address
              </label>
              <select
                value={mockTarget}
                onChange={(e) => {
                  setMockTarget(e.target.value);
                  if (e.target.value.includes("hotel")) {
                    setCapability("hotel.reserve@1.0");
                    setPayloadText(JSON.stringify({ hotel_id: "hotel_grand_hyatt", amount: 450, currency: "USD" }, null, 2));
                  } else if (e.target.value.includes("payment")) {
                    setCapability("payment.charge@1.0");
                    setPayloadText(JSON.stringify({ amount: 100, currency: "USD", description: "API Sandbox Charge" }, null, 2));
                  } else if (e.target.value.includes("calendar")) {
                    setCapability("calendar.event.create@1.0");
                    setPayloadText(JSON.stringify({ title: "Autonomous Sync", start: "2026-10-01T14:00:00Z" }, null, 2));
                  }
                }}
                className="mt-1 block w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-800 shadow-xs focus:border-blue-500 focus:outline-none"
              >
                <option value="atp://org_hotelcorp/agt_hotel">atp://org_hotelcorp/agt_hotel (Grand Hyatt Concierge)</option>
                <option value="atp://org_payco/agt_payment">atp://org_payco/agt_payment (PayCo Autonomous Clearing)</option>
                <option value="atp://org_workplace/agt_calendar">atp://org_workplace/agt_calendar (Workplace Schedule Assistant)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wide">
                Requested Capability
              </label>
              <input
                type="text"
                value={capability}
                onChange={(e) => setCapability(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-800 shadow-xs focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wide">
                JSON Payload
              </label>
              <textarea
                rows={6}
                value={payloadText}
                onChange={(e) => setPayloadText(e.target.value)}
                className="mt-1 block w-full rounded-lg border border-slate-200 bg-slate-900 font-mono text-xs text-emerald-400 p-3 focus:border-blue-500 focus:outline-none"
              />
            </div>

            <button
              onClick={handleTestDispatch}
              disabled={dispatchLoading}
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-[#3157d5] px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-[#2949b7] disabled:opacity-50"
            >
              <Play size={16} /> {dispatchLoading ? "Dispatching..." : "Execute Through Gateway"}
            </button>
            {dispatchError && (
              <p className="text-xs text-red-600 font-medium">{dispatchError}</p>
            )}
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wide mb-1">
              Gateway Delivery Response
            </label>
            <div className="h-[340px] overflow-y-auto rounded-lg bg-slate-950 p-4 border border-slate-800 font-mono text-xs text-slate-300">
              {dispatchResult ? (
                <pre className="whitespace-pre-wrap">{JSON.stringify(dispatchResult, null, 2)}</pre>
              ) : (
                <div className="flex h-full flex-col items-center justify-center text-slate-600">
                  <Waypoints size={36} className="mb-2 opacity-50" />
                  <p>Awaiting message dispatch</p>
                  <p className="text-[10px]">Response envelope and attestation ID will appear here</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
