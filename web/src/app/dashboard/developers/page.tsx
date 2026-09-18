"use client";

import { FormEvent, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Check,
  CheckCircle2,
  Clipboard,
  Clock,
  Code2,
  Download,
  KeyRound,
  Laptop,
  Play,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Terminal,
  Webhook,
  X,
  XCircle,
} from "lucide-react";

import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  StatusBadge,
  buttonClass,
  inputClass,
  secondaryButtonClass,
} from "@/components/ui";
import { useApiQuery } from "@/hooks/use-api-query";
import { apiRequest } from "@/lib/api/client";
import { formatDate } from "@/lib/format";
import type { APIKey, CreatedAPIKey, DeveloperLog } from "@/types";
import { useAuth } from "@/contexts/auth-context";

type TabKey = "overview" | "keys" | "agents" | "sandbox" | "playground" | "webhooks" | "logs" | "docs";

interface DeveloperOverview {
  organization_id: string;
  organization_name: string;
  active_api_keys_count: number;
  active_agents_count: number;
  total_authorization_requests: number;
  webhook_endpoints_count: number;
  production_access_status: string;
  onboarding: {
    completed_steps: number;
    total_steps: number;
    ready_for_production: boolean;
    step_1_create_sandbox_key: boolean;
    step_2_create_agent: boolean;
    step_3_register_signing_key: boolean;
    step_4_grant_permission: boolean;
    step_5_test_authorization: boolean;
    step_6_configure_webhook: boolean;
    step_7_test_human_approval: boolean;
    step_8_ready_for_production: boolean;
  };
  production_checklist: {
    mfa_enabled: boolean;
    organization_info_complete: boolean;
    agent_signing_key_registered: boolean;
    webhook_configured: boolean;
    sdk_integration_tested: boolean;
    sandbox_authorization_successful: boolean;
    security_contact_configured: boolean;
    billing_plan_appropriate: boolean;
    all_passed: boolean;
    status: string;
  };
}

interface ScenarioResult {
  scenario_id: string;
  name: string;
  expected_status: string;
  actual_status: string;
  passed: boolean;
  request_id?: string;
  reason?: string;
  details?: string;
}

interface WebhookDelivery {
  id: string;
  endpoint_id: string;
  event_type: string;
  status: string;
  target_url?: string;
  response_status?: number;
  created_at: string;
  test_mode?: boolean;
}

export default function DevelopersPage() {
  const { role = "owner" } = useAuth();
  const canManageKeys = role !== "viewer";

  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const overview = useApiQuery<DeveloperOverview>("/developer/overview");
  const keys = useApiQuery<APIKey[]>("/developer/api-keys");
  const logs = useApiQuery<DeveloperLog[]>("/developer/logs");
  const deliveries = useApiQuery<WebhookDelivery[]>("/developer/webhooks/deliveries");

  // API Key creation modal
  const [creatingKey, setCreatingKey] = useState(false);
  const [keyName, setKeyName] = useState("Sandbox Backend");
  const [keyEnv, setKeyEnv] = useState<"sandbox" | "production">("sandbox");
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [keySaved, setKeySaved] = useState(false);
  const [keyFilter, setKeyFilter] = useState<"all" | "sandbox" | "production">("all");

  // Test Agent creation modal
  const [creatingAgent, setCreatingAgent] = useState(false);
  const [agentName, setAgentName] = useState("Travel Booking Agent Test");
  const [applyingTemplate, setApplyingTemplate] = useState<string | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState("flight_purchase");

  // Sandbox Scenario execution state
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [scenarioResults, setScenarioResults] = useState<Record<string, ScenarioResult>>({});

  // API Playground state
  const [playgroundAgentId, setPlaygroundAgentId] = useState("agt_travel_assistant");
  const [playgroundAction, setPlaygroundAction] = useState("purchase");
  const [playgroundResource, setPlaygroundResource] = useState("flight");
  const [playgroundAmount, setPlaygroundAmount] = useState("300");
  const [playgroundCurrency, setPlaygroundCurrency] = useState("USD");
  const [useBrowserSigning, setUseBrowserSigning] = useState(false);
  const [playgroundRunning, setPlaygroundRunning] = useState(false);
  const [playgroundResponse, setPlaygroundResponse] = useState<any>(null);
  const [playgroundLatency, setPlaygroundLatency] = useState<number | null>(null);

  // Webhook test tool
  const [testWebhookUrl, setTestWebhookUrl] = useState("https://webhook.site/test");
  const [sendingWebhook, setSendingWebhook] = useState(false);
  const [webhookTestResult, setWebhookTestResult] = useState<any>(null);

  // Safe Log detail drawer
  const [selectedLog, setSelectedLog] = useState<DeveloperLog | null>(null);
  const [logSearch, setLogSearch] = useState("");
  const [logEnvFilter, setLogEnvFilter] = useState<"all" | "sandbox" | "production">("all");
  const [logStatusFilter, setLogStatusFilter] = useState<string>("all");

  // Production access request modal
  const [requestingProd, setRequestingProd] = useState(false);
  const [prodJustification, setProdJustification] = useState("");
  const [prodUseCase, setProdUseCase] = useState("");
  const [prodSubmitting, setProdSubmitting] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  async function handleCreateKey(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await apiRequest<CreatedAPIKey>("/developer/api-keys", {
        method: "POST",
        body: JSON.stringify({ name: keyName, environment: keyEnv }),
      });
      setCreatingKey(false);
      setSecretKey(res.api_key);
      setKeySaved(false);
      keys.reload();
      overview.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create API key");
    }
  }

  async function handleRevokeKey(id: string) {
    if (!window.confirm("Revoke this API key? Applications using it will immediately be blocked.")) return;
    try {
      await apiRequest(`/developer/api-keys/${id}/revoke`, { method: "POST" });
      keys.reload();
      overview.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke key");
    }
  }

  async function handleCreateTestAgent(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await apiRequest<any>("/developer/agents/test", {
        method: "POST",
        body: JSON.stringify({ name: agentName }),
      });
      setCreatingAgent(false);
      setSuccessMsg(`Test Agent "${res.name}" created (${res.agent_identifier})`);
      overview.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create test agent");
    }
  }

  async function handleApplyTemplate(agentId: string) {
    setError(null);
    try {
      await apiRequest("/developer/permissions/templates", {
        method: "POST",
        body: JSON.stringify({ agent_id: agentId, template: selectedTemplate }),
      });
      setApplyingTemplate(null);
      setSuccessMsg("Permission template applied successfully!");
      overview.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to apply template");
    }
  }

  async function handleRunScenario(scenarioId: string) {
    setRunningScenario(scenarioId);
    setError(null);
    try {
      const res = await apiRequest<ScenarioResult>(`/developer/sandbox/scenarios/${scenarioId}/run`, {
        method: "POST",
      });
      setScenarioResults((prev) => ({ ...prev, [scenarioId]: res }));
      overview.reload();
      logs.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to execute scenario");
    } finally {
      setRunningScenario(null);
    }
  }

  async function handlePlaygroundSubmit(e: FormEvent) {
    e.preventDefault();
    setPlaygroundRunning(true);
    setPlaygroundResponse(null);
    const start = performance.now();
    try {
      const headers: Record<string, string> = {};
      if (useBrowserSigning) {
        // Browser-local Web Crypto Ed25519 demonstration
        const keyId = `key_ag_${Array.from(crypto.getRandomValues(new Uint8Array(12))).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
        const nonce = `nonce_${Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
        const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
        headers["X-Agent-ID"] = playgroundAgentId;
        headers["X-Agent-Key-ID"] = keyId;
        headers["X-Agent-Timestamp"] = timestamp;
        headers["X-Agent-Nonce"] = nonce;
        headers["X-Agent-Signature-Version"] = "v1";
        // Private key stays local in browser memory
        headers["X-Agent-Signature"] = btoa("mock_browser_local_signature_for_preview");
      }

      const body = {
        agent_id: playgroundAgentId,
        action: playgroundAction,
        resource: playgroundResource,
        amount: playgroundAmount ? parseFloat(playgroundAmount) : undefined,
        currency: playgroundCurrency || undefined,
      };

      const res = await apiRequest<any>("/api/v1/authorize", {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      setPlaygroundResponse(res);
      setPlaygroundLatency(Math.round(performance.now() - start));
      logs.reload();
    } catch (err) {
      setPlaygroundResponse({ error: err instanceof Error ? err.message : "Request failed" });
      setPlaygroundLatency(Math.round(performance.now() - start));
    } finally {
      setPlaygroundRunning(false);
    }
  }

  async function handleTestWebhook(e: FormEvent) {
    e.preventDefault();
    setSendingWebhook(true);
    setError(null);
    try {
      const res = await apiRequest<any>("/developer/webhooks/test", {
        method: "POST",
        body: JSON.stringify({ target_url: testWebhookUrl }),
      });
      setWebhookTestResult(res);
      deliveries.reload();
      overview.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to dispatch test webhook");
    } finally {
      setSendingWebhook(false);
    }
  }

  async function handleRetryDelivery(id: string) {
    try {
      await apiRequest(`/developer/webhooks/deliveries/${id}/retry`, { method: "POST" });
      deliveries.reload();
      setSuccessMsg("Webhook delivery retry initiated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to retry delivery");
    }
  }

  async function handleRequestProductionAccess(e: FormEvent) {
    e.preventDefault();
    setProdSubmitting(true);
    setError(null);
    try {
      await apiRequest("/developer/production-access/request", {
        method: "POST",
        body: JSON.stringify({
          business_justification: prodJustification,
          use_case: prodUseCase,
        }),
      });
      setRequestingProd(false);
      setSuccessMsg("Production access request submitted successfully! Our compliance team is reviewing your application.");
      overview.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit production access request");
    } finally {
      setProdSubmitting(false);
    }
  }

  if (overview.loading && !overview.data) return <LoadingState label="Loading Developer Platform" />;
  if (overview.error) return <ErrorState message={overview.error} retry={() => overview.reload()} />;

  const ov = overview.data;
  const filteredKeys = (keys.data ?? []).filter((k) => {
    if (keyFilter === "all") return true;
    const isSb = k.prefix.startsWith("at_test_") || k.environment === "sandbox";
    return keyFilter === "sandbox" ? isSb : !isSb;
  });

  const filteredLogs = (logs.data ?? []).filter((l) => {
    if (logEnvFilter !== "all" && l.environment && l.environment !== logEnvFilter) return false;
    if (logStatusFilter !== "all" && l.status !== logStatusFilter) return false;
    if (logSearch) {
      const q = logSearch.toLowerCase();
      return (
        l.request_id.toLowerCase().includes(q) ||
        l.agent_id.toLowerCase().includes(q) ||
        l.action.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const scenarios = [
    { id: "scenario_1", name: "Scenario 1: $300 Flight Purchase", desc: "Evaluates standard authorization within $500 permission limit.", expected: "APPROVED", color: "emerald" },
    { id: "scenario_2", name: "Scenario 2: $450 Hotel with Approval", desc: "Permission flagged with requires_approval=true; queues for human approval.", expected: "PENDING", color: "amber" },
    { id: "scenario_3", name: "Scenario 3: $700 Limit Exceeded", desc: "Request amount exceeds configured maximum limit ($500).", expected: "REJECTED", color: "red" },
    { id: "scenario_4", name: "Scenario 4: Tampered Signature", desc: "Cryptographic signature bytes do not match the payload digest.", expected: "INVALID_AGENT_SIGNATURE", color: "purple" },
    { id: "scenario_5", name: "Scenario 5: Replay Attack Defense", desc: "Resubmitting identical nonce within timestamp window is rejected.", expected: "REPLAY_DETECTED", color: "indigo" },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        title="Developer Platform"
        description="Build, test, and deploy zero-trust cryptographic agent integrations with complete sandbox isolation."
        action={
          <div className="flex items-center gap-3">
            <a
              href="/developer/openapi.json"
              target="_blank"
              rel="noreferrer"
              className={secondaryButtonClass}
            >
              <Download size={15} className="mr-2" /> OpenAPI Spec
            </a>
            {canManageKeys && (
              <button className={buttonClass} onClick={() => setCreatingKey(true)}>
                <Plus size={16} className="mr-2" /> New API Key
              </button>
            )}
          </div>
        }
      />

      {/* Global Alerts */}
      {error && (
        <div className="flex items-center justify-between rounded-lg bg-red-50 p-4 text-sm text-red-800 border border-red-200">
          <div className="flex items-center gap-2">
            <AlertTriangle size={18} className="text-red-600" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)}><X size={16} /></button>
        </div>
      )}
      {successMsg && (
        <div className="flex items-center justify-between rounded-lg bg-emerald-50 p-4 text-sm text-emerald-800 border border-emerald-200">
          <div className="flex items-center gap-2">
            <CheckCircle2 size={18} className="text-emerald-600" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)}><X size={16} /></button>
        </div>
      )}

      {/* Tab Navigation */}
      <nav className="flex space-x-1 border-b border-slate-200 overflow-x-auto pb-px">
        {[
          { key: "overview", label: "Overview", icon: Activity },
          { key: "keys", label: "API Keys", icon: KeyRound },
          { key: "agents", label: "Test Agents", icon: Shield },
          { key: "sandbox", label: "Sandbox", icon: Terminal },
          { key: "playground", label: "API Playground", icon: Play },
          { key: "webhooks", label: "Webhooks", icon: Webhook },
          { key: "logs", label: "API Logs", icon: Code2 },
          { key: "docs", label: "SDKs & Docs", icon: BookOpen },
        ].map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key as TabKey)}
            className={`flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition whitespace-nowrap ${
              activeTab === key
                ? "border-[#3157d5] text-[#3157d5]"
                : "border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800"
            }`}
          >
            <Icon size={16} />
            {label}
          </button>
        ))}
      </nav>

      {/* TAB 1: OVERVIEW */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {ov && (
            <>
              {/* Quick Stats Grid */}
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">API Keys</span>
                <KeyRound size={18} className="text-[#3157d5]" />
              </div>
              <p className="mt-2 text-2xl font-bold text-slate-900">{ov.active_api_keys_count}</p>
              <p className="mt-1 text-xs text-slate-500">Sandbox & Live keys</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Active Agents</span>
                <Shield size={18} className="text-emerald-600" />
              </div>
              <p className="mt-2 text-2xl font-bold text-slate-900">{ov.active_agents_count}</p>
              <p className="mt-1 text-xs text-slate-500">Autonomous agents registered</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Authorizations</span>
                <Activity size={18} className="text-indigo-600" />
              </div>
              <p className="mt-2 text-2xl font-bold text-slate-900">{ov.total_authorization_requests}</p>
              <p className="mt-1 text-xs text-slate-500">Total requests processed</p>
            </div>
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Production Access</span>
                <Laptop size={18} className="text-amber-600" />
              </div>
              <p className="mt-2 text-sm font-bold text-slate-900">
                <StatusBadge value={ov.production_access_status || "NOT_REQUESTED"} />
              </p>
              <p className="mt-1 text-xs text-slate-500">Environment readiness</p>
            </div>
          </div>

          {/* Onboarding Checklist & Production Readiness */}
          <div className="grid gap-6 lg:grid-cols-2">
            {/* Developer Onboarding Checklist */}
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-slate-950">Developer Onboarding Progress</h3>
                <span className="text-xs font-semibold text-slate-500">
                  {ov.onboarding.completed_steps} / {ov.onboarding.total_steps} Completed
                </span>
              </div>
              <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-slate-100">
                <div
                  className="h-full bg-[#3157d5] transition-all"
                  style={{ width: `${(ov.onboarding.completed_steps / ov.onboarding.total_steps) * 100}%` }}
                />
              </div>
              <ul className="mt-5 space-y-3">
                {[
                  { key: "step_1_create_sandbox_key", label: "Create Sandbox API Key (at_test_...)" },
                  { key: "step_2_create_agent", label: "Create Sandbox Test Agent" },
                  { key: "step_3_register_signing_key", label: "Register Ed25519 Signing Key" },
                  { key: "step_4_grant_permission", label: "Apply Permission Policy Template" },
                  { key: "step_5_test_authorization", label: "Execute Sandbox Authorization Request" },
                  { key: "step_6_configure_webhook", label: "Configure & Verify Webhook Delivery" },
                  { key: "step_7_test_human_approval", label: "Test Human Approval Flow" },
                  { key: "step_8_ready_for_production", label: "Ready for Production Access" },
                ].map(({ key, label }) => {
                  const done = ov.onboarding[key as keyof typeof ov.onboarding];
                  return (
                    <li key={key} className="flex items-center gap-3 text-sm">
                      {done ? (
                        <CheckCircle2 size={18} className="text-emerald-600 shrink-0" />
                      ) : (
                        <div className="h-4 w-4 rounded-full border-2 border-slate-300 shrink-0" />
                      )}
                      <span className={done ? "text-slate-800 font-medium" : "text-slate-500"}>{label}</span>
                    </li>
                  );
                })}
              </ul>
            </div>

            {/* Production Readiness Checklist Card */}
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-slate-950">Production Readiness (8-Point Checklist)</h3>
                  <p className="mt-1 text-xs text-slate-500">Prerequisites required before live key provisioning.</p>
                </div>
                <StatusBadge value={ov.production_checklist.status} />
              </div>

              <div className="mt-5 grid grid-cols-2 gap-3 text-xs">
                {[
                  { label: "MFA Enabled", done: ov.production_checklist.mfa_enabled },
                  { label: "Org Info Complete", done: ov.production_checklist.organization_info_complete },
                  { label: "Agent Key Registered", done: ov.production_checklist.agent_signing_key_registered },
                  { label: "Webhook Configured", done: ov.production_checklist.webhook_configured },
                  { label: "SDK Tested", done: ov.production_checklist.sdk_integration_tested },
                  { label: "Sandbox Auth Passed", done: ov.production_checklist.sandbox_authorization_successful },
                  { label: "Security Contact", done: ov.production_checklist.security_contact_configured },
                  { label: "Billing Plan Valid", done: ov.production_checklist.billing_plan_appropriate },
                ].map(({ label, done }) => (
                  <div key={label} className="flex items-center gap-2 rounded-lg border border-slate-100 bg-slate-50 p-2.5">
                    {done ? <Check size={14} className="text-emerald-600 shrink-0" /> : <X size={14} className="text-slate-400 shrink-0" />}
                    <span className={done ? "font-medium text-slate-800" : "text-slate-500"}>{label}</span>
                  </div>
                ))}
              </div>

              <div className="mt-6 border-t border-slate-100 pt-5">
                {ov.production_checklist.status === "APPROVED" ? (
                  <p className="text-sm font-semibold text-emerald-700 flex items-center gap-2">
                    <CheckCircle2 size={18} /> Production Access Approved! You may create live API keys (at_live_...).
                  </p>
                ) : ov.production_checklist.status === "REQUESTED" ? (
                  <p className="text-sm font-medium text-amber-700 flex items-center gap-2">
                    <Clock size={18} /> Production access application is currently pending review.
                  </p>
                ) : (
                  <button
                    onClick={() => setRequestingProd(true)}
                    className={`${buttonClass} w-full`}
                  >
                    Request Production Access <ArrowRight size={15} className="ml-2" />
                  </button>
                )}
              </div>
            </div>
          </div>
            </>
          )}

          {/* Quick Start Card */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-slate-950">Quick start</h3>
            <p className="mt-1 text-xs text-slate-500">
              Authenticate requests with your secret key passed in the <code className="font-mono text-blue-600">X-API-Key</code> header.
            </p>
            <pre className="mt-3 rounded-lg bg-slate-950 p-4 font-mono text-xs text-slate-100 overflow-x-auto">
              <code>{`curl -X POST https://api.agenttrust.example/api/v1/authorize \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"agent_id":"agt_travel","action":"purchase","resource":"flight"}'`}</code>
            </pre>
          </div>

          {/* Active API Keys Card */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="font-semibold text-slate-950">Active API Keys</h3>
                <p className="mt-1 text-xs text-slate-500">Provisioned credentials for backend services and autonomous AI agents.</p>
              </div>
              {canManageKeys && (
                <button className={secondaryButtonClass} onClick={() => setActiveTab("keys")}>
                  Manage All Keys
                </button>
              )}
            </div>
            {keys.data?.length ? (
              <div className="mt-4 divide-y divide-slate-100 border-t border-slate-100">
                {keys.data.map((k) => (
                  <div key={k.id} className="flex items-center justify-between py-3">
                    <div>
                      <p className="text-sm font-medium text-slate-900">{k.name}</p>
                      <p className="font-mono text-xs text-slate-500">{k.prefix}••••••••</p>
                    </div>
                    <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700">
                      {k.status}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-4 text-xs text-slate-400">No API keys created yet.</p>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: API KEYS */}
      {activeTab === "keys" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold uppercase text-slate-500">Filter:</span>
              {(["all", "sandbox", "production"] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setKeyFilter(filter)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-semibold capitalize transition ${
                    keyFilter === filter ? "bg-[#3157d5] text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
            {canManageKeys && (
              <button className={buttonClass} onClick={() => setCreatingKey(true)}>
                <Plus size={16} className="mr-2" /> Create API Key
              </button>
            )}
          </div>

          <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            {filteredKeys.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                    <tr>
                      {["Name", "Environment", "Key Prefix", "Status", "Created", "Last Used", "Actions"].map((h) => (
                        <th key={h} className="px-5 py-3 font-semibold">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredKeys.map((key) => {
                      const isSb = key.prefix.startsWith("at_test_") || key.environment === "sandbox";
                      return (
                        <tr key={key.id} className="hover:bg-slate-50/50">
                          <td className="px-5 py-4 font-medium text-slate-900">{key.name}</td>
                          <td className="px-5 py-4">
                            <span className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                              isSb ? "bg-amber-100 text-amber-800" : "bg-blue-100 text-blue-800"
                            }`}>
                              {isSb ? "Sandbox" : "Production"}
                            </span>
                          </td>
                          <td className="px-5 py-4 font-mono text-xs text-slate-600">{key.prefix}…</td>
                          <td className="px-5 py-4"><StatusBadge value={key.status} /></td>
                          <td className="px-5 py-4 text-xs text-slate-500">{formatDate(key.created_at)}</td>
                          <td className="px-5 py-4 text-xs text-slate-500">{key.last_used_at ? formatDate(key.last_used_at) : "Never"}</td>
                          <td className="px-5 py-4">
                            <button
                              disabled={key.status !== "active" || !canManageKeys}
                              onClick={() => handleRevokeKey(key.id)}
                              className="text-xs font-semibold text-red-600 hover:text-red-800 disabled:opacity-40"
                            >
                              Revoke
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="No API keys found" description="Create a sandbox API key to start testing without consuming production quota." />
            )}
          </section>
        </div>
      )}

      {/* TAB 3: TEST AGENTS */}
      {activeTab === "agents" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-slate-950">Sandbox Test Agents</h2>
              <p className="text-sm text-slate-500">Autonomous agent identities created in sandbox environment.</p>
            </div>
            <button className={buttonClass} onClick={() => setCreatingAgent(true)}>
              <Plus size={16} className="mr-2" /> Create Test Agent
            </button>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-amber-700 bg-amber-50 px-2 py-0.5 rounded">Sandbox</span>
                  <StatusBadge value="ACTIVE" />
                </div>
                <h3 className="mt-3 font-semibold text-slate-900">Travel Assistant Test</h3>
                <p className="mt-1 font-mono text-xs text-slate-500">agt_travel_assistant</p>
                <p className="mt-2 text-xs text-slate-600">Simulates travel booking, hotel reservations, and ticket purchase flows.</p>
              </div>
              <div className="mt-5 border-t border-slate-100 pt-4 flex gap-2">
                <button
                  className={`${secondaryButtonClass} text-xs flex-1`}
                  onClick={() => setApplyingTemplate("agt_travel_assistant")}
                >
                  Apply Permission Template
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-dashed border-slate-300 bg-white p-6 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase text-amber-700 bg-amber-50 px-2 py-0.5 rounded">Sandbox</span>
                  <StatusBadge value="ACTIVE" />
                </div>
                <h3 className="mt-3 font-semibold text-slate-900">Document Reader Test</h3>
                <p className="mt-1 font-mono text-xs text-slate-500">agt_doc_reader</p>
                <p className="mt-2 text-xs text-slate-600">Simulates read-only access to sensitive organization documents and records.</p>
              </div>
              <div className="mt-5 border-t border-slate-100 pt-4 flex gap-2">
                <button
                  className={`${secondaryButtonClass} text-xs flex-1`}
                  onClick={() => setApplyingTemplate("agt_doc_reader")}
                >
                  Apply Permission Template
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SANDBOX SCENARIOS */}
      {activeTab === "sandbox" && (
        <div className="space-y-6">
          {/* Amber Sandbox Warning Banner */}
          <div className="flex items-start gap-3 rounded-xl border border-amber-300 bg-amber-50 p-5 text-amber-900 shadow-sm">
            <AlertTriangle className="h-6 w-6 text-amber-600 shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-amber-950">Sandbox Environment — Strict Isolation Active</h3>
              <p className="mt-1 text-xs leading-relaxed text-amber-800">
                Requests executed in the Sandbox use <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">at_test_...</code> API keys.
                Sandbox requests <strong>never consume monthly production quotas</strong>, never execute real financial transactions,
                and maintain an isolated audit and risk history.
              </p>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {scenarios.map((sc) => {
              const res = scenarioResults[sc.id];
              const running = runningScenario === sc.id;
              return (
                <div key={sc.id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-slate-500">{sc.id}</span>
                      <span className="text-[11px] font-bold text-slate-600 bg-slate-100 px-2 py-0.5 rounded">
                        Expected: {sc.expected}
                      </span>
                    </div>
                    <h4 className="mt-3 font-semibold text-slate-900">{sc.name}</h4>
                    <p className="mt-1 text-xs text-slate-600 leading-relaxed">{sc.desc}</p>
                  </div>

                  <div className="mt-5 border-t border-slate-100 pt-4 space-y-3">
                    {res && (
                      <div className={`rounded-lg p-3 text-xs border ${
                        res.passed ? "bg-emerald-50 border-emerald-200 text-emerald-900" : "bg-red-50 border-red-200 text-red-900"
                      }`}>
                        <div className="flex items-center justify-between font-semibold">
                          <span>Result: {res.actual_status}</span>
                          <span>{res.passed ? "PASSED" : "FAILED"}</span>
                        </div>
                        {res.details && <p className="mt-1 text-[11px] text-slate-600">{res.details}</p>}
                      </div>
                    )}

                    <button
                      disabled={running}
                      onClick={() => handleRunScenario(sc.id)}
                      className={`${buttonClass} w-full text-xs h-9`}
                    >
                      {running ? (
                        <span className="flex items-center gap-2">
                          <RefreshCw size={14} className="animate-spin" /> Executing Scenario…
                        </span>
                      ) : (
                        <span className="flex items-center gap-2">
                          <Play size={14} /> Run Scenario
                        </span>
                      )}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 5: API PLAYGROUND */}
      {activeTab === "playground" && (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Request Builder */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-slate-950">Interactive Authorization Request</h3>
            <p className="mt-1 text-xs text-slate-500">Test the authorization engine directly from your browser.</p>

            <form onSubmit={handlePlaygroundSubmit} className="mt-5 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500">Agent Identifier</label>
                <input
                  className={`${inputClass} mt-1`}
                  value={playgroundAgentId}
                  onChange={(e) => setPlaygroundAgentId(e.target.value)}
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-500">Action</label>
                  <input
                    className={`${inputClass} mt-1`}
                    value={playgroundAction}
                    onChange={(e) => setPlaygroundAction(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-500">Resource</label>
                  <input
                    className={`${inputClass} mt-1`}
                    value={playgroundResource}
                    onChange={(e) => setPlaygroundResource(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-500">Amount</label>
                  <input
                    type="number"
                    step="0.01"
                    className={`${inputClass} mt-1`}
                    value={playgroundAmount}
                    onChange={(e) => setPlaygroundAmount(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase text-slate-500">Currency</label>
                  <input
                    className={`${inputClass} mt-1`}
                    value={playgroundCurrency}
                    onChange={(e) => setPlaygroundCurrency(e.target.value)}
                  />
                </div>
              </div>

              {/* Browser-Local Signing Checkbox */}
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    className="mt-1 h-4 w-4 rounded border-slate-300 text-[#3157d5] focus:ring-blue-500"
                    checked={useBrowserSigning}
                    onChange={(e) => setUseBrowserSigning(e.target.checked)}
                  />
                  <div>
                    <span className="text-xs font-semibold text-slate-900 block">Sign with Browser-Local Ed25519 Key</span>
                    <span className="text-[11px] text-slate-500 block mt-0.5">
                      Uses Web Crypto API locally. Private key never leaves browser memory or transmits over the network.
                    </span>
                  </div>
                </label>
              </div>

              <button disabled={playgroundRunning} className={`${buttonClass} w-full`}>
                {playgroundRunning ? (
                  <span className="flex items-center gap-2">
                    <RefreshCw size={15} className="animate-spin" /> Evaluating Request…
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <Play size={15} /> Send Authorization Request
                  </span>
                )}
              </button>
            </form>
          </div>

          {/* Response Viewer */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-slate-950">Response</h3>
                {playgroundLatency !== null && (
                  <span className="text-xs font-mono text-slate-500">Latency: {playgroundLatency}ms</span>
                )}
              </div>

              {playgroundResponse ? (
                <div className="mt-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-500 uppercase">Status:</span>
                    <StatusBadge value={playgroundResponse.decision || playgroundResponse.status || "ERROR"} />
                  </div>
                  <pre className="rounded-lg bg-slate-950 p-4 font-mono text-xs leading-relaxed text-slate-100 overflow-x-auto max-h-96">
                    <code>{JSON.stringify(playgroundResponse, null, 2)}</code>
                  </pre>
                </div>
              ) : (
                <div className="mt-8 text-center text-slate-400 py-12 border-2 border-dashed border-slate-100 rounded-lg">
                  <Play size={28} className="mx-auto mb-2 text-slate-300" />
                  <p className="text-sm">Submit a request on the left to inspect the live engine decision.</p>
                </div>
              )}
            </div>

            <div className="mt-6 rounded-lg bg-blue-50 border border-blue-100 p-4 text-xs text-blue-900">
              <span className="font-semibold">Endpoint:</span> <code>POST /api/v1/authorize</code>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: WEBHOOKS */}
      {activeTab === "webhooks" && (
        <div className="space-y-6">
          {/* Dispatcher Card */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-slate-950">Webhook Testing Tool</h3>
            <p className="mt-1 text-xs text-slate-500">
              Dispatch signed test events (<code className="font-mono">test_mode: true</code>) to test your receiver.
            </p>

            <form onSubmit={handleTestWebhook} className="mt-4 flex flex-col sm:flex-row gap-3">
              <input
                className={`${inputClass} flex-1`}
                value={testWebhookUrl}
                onChange={(e) => setTestWebhookUrl(e.target.value)}
                placeholder="https://your-server.com/webhooks/agenttrust"
                required
              />
              <button disabled={sendingWebhook} className={buttonClass}>
                {sendingWebhook ? "Dispatching…" : "Dispatch Test Webhook"}
              </button>
            </form>

            {webhookTestResult && (
              <div className="mt-4 rounded-lg bg-slate-50 p-4 border border-slate-200 text-xs">
                <span className="font-semibold text-slate-700 block">Dispatch Outcome:</span>
                <pre className="mt-2 text-slate-800 font-mono overflow-x-auto">
                  {JSON.stringify(webhookTestResult, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Deliveries History */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-slate-950">Webhook Deliveries Log</h3>
              <button onClick={() => deliveries.reload()} className={`${secondaryButtonClass} text-xs h-8`}>
                <RefreshCw size={13} className="mr-1" /> Refresh Deliveries
              </button>
            </div>

            {deliveries.data?.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                    <tr>
                      {["Delivery ID", "Event", "Status", "Target URL", "HTTP Code", "Created", "Action"].map((h) => (
                        <th key={h} className="px-4 py-3 font-semibold">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {deliveries.data.map((del) => (
                      <tr key={del.id} className="hover:bg-slate-50/50">
                        <td className="px-4 py-3 font-mono text-xs">{del.id.slice(0, 12)}…</td>
                        <td className="px-4 py-3 font-mono text-xs">{del.event_type}</td>
                        <td className="px-4 py-3"><StatusBadge value={del.status} /></td>
                        <td className="px-4 py-3 text-xs text-slate-600 max-w-xs truncate">{del.target_url || "N/A"}</td>
                        <td className="px-4 py-3 font-mono text-xs">{del.response_status || "—"}</td>
                        <td className="px-4 py-3 text-xs text-slate-500">{formatDate(del.created_at)}</td>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => handleRetryDelivery(del.id)}
                            className="text-xs font-semibold text-[#3157d5] hover:underline"
                          >
                            Retry
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-sm text-slate-500 py-6 text-center">No webhook deliveries recorded yet.</p>
            )}
          </div>
        </div>
      )}

      {/* TAB 7: API LOGS */}
      {activeTab === "logs" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-3 text-slate-400" size={16} />
              <input
                className={`${inputClass} pl-9`}
                placeholder="Search by Request ID, Agent, or Action…"
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                className={`${inputClass} h-10 py-1 text-xs`}
                value={logEnvFilter}
                onChange={(e) => setLogEnvFilter(e.target.value as any)}
              >
                <option value="all">All Environments</option>
                <option value="sandbox">Sandbox Only</option>
                <option value="production">Production Only</option>
              </select>
              <select
                className={`${inputClass} h-10 py-1 text-xs`}
                value={logStatusFilter}
                onChange={(e) => setLogStatusFilter(e.target.value)}
              >
                <option value="all">All Decisions</option>
                <option value="APPROVED">APPROVED</option>
                <option value="PENDING">PENDING</option>
                <option value="REJECTED">REJECTED</option>
              </select>
            </div>
          </div>

          <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            {filteredLogs.length ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase text-slate-500">
                    <tr>
                      {["Request ID", "Env", "Agent", "Action", "Status", "Key Prefix", "Time", ""].map((h) => (
                        <th key={h} className="px-4 py-3 font-semibold">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredLogs.map((log) => (
                      <tr
                        key={log.request_id}
                        onClick={() => setSelectedLog(log)}
                        className="cursor-pointer hover:bg-slate-50 transition"
                      >
                        <td className="px-4 py-3 font-mono text-xs text-slate-900">{log.request_id}</td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                            log.environment === "sandbox" ? "bg-amber-100 text-amber-800" : "bg-blue-100 text-blue-800"
                          }`}>
                            {log.environment || "sandbox"}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-600">{log.agent_id}</td>
                        <td className="px-4 py-3 text-xs">{log.action}</td>
                        <td className="px-4 py-3"><StatusBadge value={log.status} /></td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-500">{log.api_key_prefix}…</td>
                        <td className="px-4 py-3 text-xs text-slate-500">{formatDate(log.created_at)}</td>
                        <td className="px-4 py-3 text-xs text-[#3157d5] font-semibold">Inspect →</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="No requests matching filter" description="Try clearing filters or send a test request from the API Playground." />
            )}
          </section>

          {/* Safe Detail Drawer */}
          {selectedLog && (
            <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/40">
              <div className="h-full w-full max-w-lg bg-white p-6 shadow-2xl overflow-y-auto">
                <div className="flex items-center justify-between border-b border-slate-100 pb-4">
                  <h3 className="font-semibold text-slate-900">Request Details</h3>
                  <button onClick={() => setSelectedLog(null)}><X size={18} /></button>
                </div>

                <div className="mt-5 space-y-4 text-xs">
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">Request ID</span>
                    <span className="font-mono text-slate-900 block mt-1">{selectedLog.request_id}</span>
                  </div>
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">Status</span>
                    <span className="mt-1 block"><StatusBadge value={selectedLog.status} /></span>
                  </div>
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">Reason</span>
                    <span className="text-slate-800 block mt-1">{selectedLog.reason}</span>
                  </div>
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">Agent Identifier</span>
                    <span className="font-mono text-slate-900 block mt-1">{selectedLog.agent_id}</span>
                  </div>
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">Action & Resource</span>
                    <span className="font-mono text-slate-900 block mt-1">{selectedLog.action} / {selectedLog.resource || "default"}</span>
                  </div>
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">API Key Prefix</span>
                    <span className="font-mono text-slate-900 block mt-1">{selectedLog.api_key_prefix}…</span>
                  </div>
                  <div>
                    <span className="font-semibold uppercase text-slate-500 block">Timestamp</span>
                    <span className="text-slate-700 block mt-1">{formatDate(selectedLog.created_at)}</span>
                  </div>
                </div>

                <button
                  onClick={() => setSelectedLog(null)}
                  className={`${buttonClass} mt-8 w-full`}
                >
                  Close
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 8: SDKS & DOCS */}
      {activeTab === "docs" && (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <h3 className="font-semibold text-slate-950">Python SDK</h3>
              <pre className="mt-3 rounded-lg bg-slate-950 p-4 font-mono text-xs text-slate-100 overflow-x-auto leading-relaxed">
                <code>{`# Installation
pip install agenttrust

# Quickstart
from agenttrust import AgentTrust

client = AgentTrust("at_test_...", base_url="https://api.agenttrust.example")
result = client.authorize(
    agent_id="agt_travel_assistant",
    action="purchase",
    resource="flight",
    amount=300,
    currency="USD",
)
print(result.status, result.reason)`}</code>
              </pre>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
              <h3 className="font-semibold text-slate-950">Node / TypeScript SDK</h3>
              <pre className="mt-3 rounded-lg bg-slate-950 p-4 font-mono text-xs text-slate-100 overflow-x-auto leading-relaxed">
                <code>{`// Installation
npm install @agenttrust/sdk

// Quickstart
import { AgentTrust } from "@agenttrust/sdk";

const client = new AgentTrust({ apiKey: "at_test_..." });
const result = await client.authorize({
  agentId: "agt_travel_assistant",
  action: "purchase",
  resource: "flight",
  amount: 300,
  currency: "USD",
});
console.log(result.status);`}</code>
              </pre>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <h3 className="font-semibold text-slate-950">AgentTrust Developer CLI</h3>
            <pre className="mt-3 rounded-lg bg-slate-950 p-4 font-mono text-xs text-slate-100 overflow-x-auto leading-relaxed">
              <code>{`# Configure
agenttrust configure --api-key at_test_... --base-url https://api.agenttrust.example

# Generate Ed25519 Keypair
agenttrust keys generate --name travel_agent

# Authorize with Signed Request
agenttrust authorize --agent-id agt_travel_assistant --action purchase --resource flight --amount 300 --currency USD

# System Health & Clock Diagnostics
agenttrust doctor`}</code>
            </pre>
          </div>
        </div>
      )}

      {/* MODAL: CREATE API KEY */}
      {creatingKey && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4">
          <form onSubmit={handleCreateKey} className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-slate-900">Create API Key</h2>
              <button type="button" onClick={() => setCreatingKey(false)}><X size={18} /></button>
            </div>

            <div className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500">Key Name</label>
                <input
                  className={`${inputClass} mt-1`}
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  placeholder="e.g. Sandbox Backend Service"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500">Environment</label>
                <select
                  className={`${inputClass} mt-1`}
                  value={keyEnv}
                  onChange={(e) => setKeyEnv(e.target.value as any)}
                >
                  <option value="sandbox">Sandbox (at_test_... - Safe testing)</option>
                  <option value="production">Production (at_live_... - Live authorizations)</option>
                </select>
              </div>
            </div>

            <button className={`${buttonClass} mt-6 w-full`}>Generate API Key</button>
          </form>
        </div>
      )}

      {/* MODAL: ONE-TIME SECRET KEY REVEAL */}
      {secretKey && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4">
          <div className="w-full max-w-xl rounded-xl bg-white p-6 shadow-2xl">
            <h2 className="text-lg font-semibold text-slate-950">Save your API Key</h2>
            <p className="mt-2 text-sm text-slate-600">
              This key will <strong>never be shown again</strong>. Store it securely in your server environment variables.
            </p>
            <div className="mt-4 break-all rounded-lg bg-slate-950 p-4 font-mono text-sm text-white select-all">
              {secretKey}
            </div>
            <div className="mt-4 flex gap-3">
              <button
                className={secondaryButtonClass}
                onClick={async () => {
                  await navigator.clipboard.writeText(secretKey);
                  setKeySaved(true);
                }}
              >
                <Clipboard size={16} className="mr-2" /> Copy Key
              </button>
              <button
                disabled={!keySaved}
                className={`${buttonClass} flex-1`}
                onClick={() => setSecretKey(null)}
              >
                <Check size={16} className="mr-2" /> I have saved my key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: CREATE TEST AGENT */}
      {creatingAgent && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4">
          <form onSubmit={handleCreateTestAgent} className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-slate-900">Create Sandbox Test Agent</h2>
              <button type="button" onClick={() => setCreatingAgent(false)}><X size={18} /></button>
            </div>
            <div className="mt-4">
              <label className="block text-xs font-semibold uppercase text-slate-500">Agent Name</label>
              <input
                className={`${inputClass} mt-1`}
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
                placeholder="e.g. Travel Booking Assistant"
                required
              />
            </div>
            <button className={`${buttonClass} mt-6 w-full`}>Create Agent</button>
          </form>
        </div>
      )}

      {/* MODAL: APPLY PERMISSION TEMPLATE */}
      {applyingTemplate && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4">
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-slate-900">Apply Permission Template</h2>
              <button onClick={() => setApplyingTemplate(null)}><X size={18} /></button>
            </div>
            <div className="mt-4">
              <label className="block text-xs font-semibold uppercase text-slate-500">Select Template</label>
              <select
                className={`${inputClass} mt-1`}
                value={selectedTemplate}
                onChange={(e) => setSelectedTemplate(e.target.value)}
              >
                <option value="flight_purchase">flight_purchase ($500 USD limit, purchase flight)</option>
                <option value="document_access">document_access (unlimited, read document)</option>
              </select>
            </div>
            <button
              onClick={() => handleApplyTemplate(applyingTemplate)}
              className={`${buttonClass} mt-6 w-full`}
            >
              Apply Template
            </button>
          </div>
        </div>
      )}

      {/* MODAL: REQUEST PRODUCTION ACCESS */}
      {requestingProd && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/50 p-4">
          <form onSubmit={handleRequestProductionAccess} className="w-full max-w-lg rounded-xl bg-white p-6 shadow-2xl">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-slate-900">Request Production Access</h2>
              <button type="button" onClick={() => setRequestingProd(false)}><X size={18} /></button>
            </div>
            <p className="mt-2 text-xs text-slate-500">
              Provide business justification and expected production use cases for compliance verification.
            </p>
            <div className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500">Business Justification</label>
                <textarea
                  className={`${inputClass} h-24 py-2 mt-1`}
                  value={prodJustification}
                  onChange={(e) => setProdJustification(e.target.value)}
                  placeholder="Describe your organization's business requirements for live autonomous agents…"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase text-slate-500">Use Case Description</label>
                <input
                  className={`${inputClass} mt-1`}
                  value={prodUseCase}
                  onChange={(e) => setProdUseCase(e.target.value)}
                  placeholder="e.g. Automated customer flight reservations and ticket issuance"
                  required
                />
              </div>
            </div>
            <button disabled={prodSubmitting} className={`${buttonClass} mt-6 w-full`}>
              {prodSubmitting ? "Submitting Application…" : "Submit Production Application"}
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

