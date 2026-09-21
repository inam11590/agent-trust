"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Braces,
  CheckCircle2,
  Clock,
  Code2,
  Copy,
  ExternalLink,
  Eye,
  FileCode,
  FileDiff,
  Flame,
  GitBranch,
  History,
  Layers,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";

interface PolicyDetails {
  id: string;
  name: string;
  description?: string;
  category: string;
  tags: string[];
  active_version?: number;
  total_versions: number;
  status: string;
  created_at: string;
  updated_at: string;
}

interface PolicyVersionItem {
  id: string;
  policy_id: string;
  version_number: number;
  status: string;
  content_hash: string;
  yaml_source: string;
  compiled_ast: any;
  change_description?: string;
  is_active: boolean;
  published_at?: string;
  created_at: string;
}

interface SimulationResponse {
  decision: string;
  explanation: string;
  matched_rules: any[];
  unmatched_rules: string[];
  default_effect_applied: boolean;
  trace: any[];
  evaluation_time_ms: number;
}

interface DiffResponse {
  old_version: number;
  new_version: number;
  added_rules: any[];
  removed_rules: any[];
  modified_rules: any[];
  default_effect_changed: boolean;
  old_default_effect?: string;
  new_default_effect?: string;
  has_security_sensitive_changes: boolean;
  markdown_summary: string;
}

interface TestCaseItem {
  id: string;
  name: string;
  description?: string;
  context: any;
  expected_decision: string;
}

interface TestRunSummary {
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  all_passed: boolean;
  results: {
    test_id: string;
    test_name: string;
    expected_decision: string;
    actual_decision: string;
    passed: boolean;
    explanation: string;
    duration_ms: number;
  }[];
}

export default function PolicyWorkbenchPage({ params }: { params: Promise<{ id: string }> }) {
  const { id: policyId } = use(params);

  const [policy, setPolicy] = useState<PolicyDetails | null>(null);
  const [versions, setVersions] = useState<PolicyVersionItem[]>([]);
  const [selectedVersionNum, setSelectedVersionNum] = useState<number>(1);
  const [activeTab, setActiveTab] = useState<"editor" | "simulate" | "diff" | "publish">("editor");

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Version Draft State
  const [isDrafting, setIsDrafting] = useState(false);
  const [draftYaml, setDraftYaml] = useState("");
  const [draftDescription, setDraftDescription] = useState("");
  const [savingDraft, setSavingDraft] = useState(false);

  // Simulation State
  const [simContext, setSimContext] = useState(
    JSON.stringify(
      {
        action: "purchase_flight",
        resource: "flight_booking",
        agent: { id: "agt_demo_travel", type: "travel_agent" },
        input: { amount: 350, currency: "USD" },
        risk: { score: 25, level: "LOW" },
      },
      null,
      2
    )
  );
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<SimulationResponse | null>(null);

  // Test Runner State
  const [testCases, setTestCases] = useState<TestCaseItem[]>([]);
  const [runningTests, setRunningTests] = useState(false);
  const [testSummary, setTestSummary] = useState<TestRunSummary | null>(null);

  // Diff State
  const [diffBaseVer, setDiffBaseVer] = useState<number>(1);
  const [diffTargetVer, setDiffTargetVer] = useState<number>(1);
  const [diffResult, setDiffResult] = useState<DiffResponse | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  // Rollback / Publish State
  const [rollbackReason, setRollbackReason] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);

  const fetchPolicyData = async () => {
    setLoading(true);
    setError(null);
    try {
      const p = await apiRequest<PolicyDetails>(`/v1/policies/${policyId}`);
      setPolicy(p);

      const vers = await apiRequest<PolicyVersionItem[]>(`/v1/policies/${policyId}/versions`);
      setVersions(vers || []);

      if (vers && vers.length > 0) {
        const initialVer = p.active_version || vers[0].version_number;
        setSelectedVersionNum(initialVer);
        setDiffTargetVer(initialVer);
        setDiffBaseVer(vers[vers.length - 1].version_number);
      }

      // Fetch test cases
      try {
        const tests = await apiRequest<TestCaseItem[]>(`/v1/policies/${policyId}/tests`);
        setTestCases(tests || []);
      } catch (e) {
        // test cases optional
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load policy.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicyData();
  }, [policyId]);

  const currentVersion = versions.find((v) => v.version_number === selectedVersionNum) || versions[0];

  const handleSimulate = async () => {
    setSimulating(true);
    setError(null);
    try {
      let parsedCtx: any = {};
      try {
        parsedCtx = JSON.parse(simContext);
      } catch (e) {
        throw new Error("Simulation context must be valid JSON.");
      }

      const res = await apiRequest<SimulationResponse>("/v1/policies/simulate", {
        method: "POST",
        body: JSON.stringify({
          policy_id: policyId,
          version_number: selectedVersionNum,
          context: parsedCtx,
        }),
      });
      setSimResult(res);
    } catch (err: any) {
      setError(err?.message || "Simulation failed.");
    } finally {
      setSimulating(false);
    }
  };

  const handleRunTests = async () => {
    setRunningTests(true);
    setError(null);
    try {
      const res = await apiRequest<TestRunSummary>(
        `/v1/policies/${policyId}/tests/run?version_number=${selectedVersionNum}`,
        { method: "POST" }
      );
      setTestSummary(res);
    } catch (err: any) {
      setError(err?.message || "Test execution failed.");
    } finally {
      setRunningTests(false);
    }
  };

  const handleCreateDraftVersion = async () => {
    if (!draftYaml.trim()) {
      setError("YAML source cannot be empty.");
      return;
    }
    setSavingDraft(true);
    setError(null);
    try {
      const newVer = await apiRequest<PolicyVersionItem>(`/v1/policies/${policyId}/versions`, {
        method: "POST",
        body: JSON.stringify({
          yaml_source: draftYaml,
          change_description: draftDescription || "Draft update",
        }),
      });
      setSuccessMsg(`Version v${newVer.version_number} created successfully.`);
      setIsDrafting(false);
      await fetchPolicyData();
      setSelectedVersionNum(newVer.version_number);
    } catch (err: any) {
      setError(err?.message || "Failed to create new version.");
    } finally {
      setSavingDraft(false);
    }
  };

  const handleFetchDiff = async () => {
    setLoadingDiff(true);
    setError(null);
    try {
      const res = await apiRequest<DiffResponse>(
        `/v1/policies/${policyId}/diff?v1=${diffBaseVer}&v2=${diffTargetVer}`
      );
      setDiffResult(res);
    } catch (err: any) {
      setError(err?.message || "Diff generation failed.");
    } finally {
      setLoadingDiff(false);
    }
  };

  const handlePublish = async (verNum: number) => {
    if (!confirm(`Are you sure you want to publish v${verNum}? This will activate it across all Edge Gateways.`)) {
      return;
    }
    setPublishing(true);
    setError(null);
    try {
      await apiRequest(`/v1/policies/${policyId}/publish`, {
        method: "POST",
        body: JSON.stringify({
          version_number: verNum,
          sync_gateways: true,
        }),
      });
      setSuccessMsg(`Policy v${verNum} successfully published and synchronized!`);
      await fetchPolicyData();
    } catch (err: any) {
      setError(err?.message || "Publishing failed.");
    } finally {
      setPublishing(false);
    }
  };

  const handleRollback = async () => {
    if (!rollbackReason.trim()) {
      setError("Please provide an audit reason for the rollback.");
      return;
    }
    setRollingBack(true);
    setError(null);
    try {
      await apiRequest(`/v1/policies/${policyId}/rollback`, {
        method: "POST",
        body: JSON.stringify({
          target_version: selectedVersionNum,
          reason: rollbackReason.trim(),
          sync_gateways: true,
        }),
      });
      setSuccessMsg(`Successfully rolled back to v${selectedVersionNum}. Monotonic snapshot pushed.`);
      setRollbackReason("");
      await fetchPolicyData();
    } catch (err: any) {
      setError(err?.message || "Rollback failed.");
    } finally {
      setRollingBack(false);
    }
  };

  if (loading && !policy) {
    return (
      <div className="py-24 text-center text-slate-400">
        <RefreshCw size={28} className="mx-auto mb-3 animate-spin text-blue-500" />
        Loading Policy Workbench...
      </div>
    );
  }

  if (!policy) {
    return (
      <div className="space-y-4">
        <Link href="/dashboard/policies" className="inline-flex items-center gap-1.5 text-sm text-slate-500">
          <ArrowLeft size={16} /> Back to Policies
        </Link>
        <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-red-700">
          Policy not found or access denied.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb */}
      <div className="flex items-center justify-between">
        <Link
          href="/dashboard/policies"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-500 hover:text-slate-900 transition"
        >
          <ArrowLeft size={16} />
          Back to Policies
        </Link>
        <div className="flex items-center gap-2">
          {policy.status === "ACTIVE" && policy.active_version ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 border border-emerald-200">
              <CheckCircle2 size={13} /> Active (v{policy.active_version})
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-700 border border-amber-200">
              <Clock size={13} /> Draft Mode
            </span>
          )}
        </div>
      </div>

      {/* Header Banner */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900">{policy.name}</h1>
              <span className="rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold text-slate-700">
                {policy.category}
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-500">{policy.description || "No description provided."}</p>
            <div className="mt-3 flex items-center gap-4 text-xs font-mono text-slate-400">
              <span>ID: {policy.id}</span>
              {currentVersion?.content_hash && (
                <span className="truncate max-w-sm">Hash: {currentVersion.content_hash}</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                setDraftYaml(currentVersion?.yaml_source || "");
                setIsDrafting(true);
              }}
              className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
            >
              <Plus size={15} />
              New Draft Version
            </button>
            <button
              onClick={() => handlePublish(selectedVersionNum)}
              disabled={publishing || currentVersion?.is_active}
              className="flex items-center gap-2 rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-600 disabled:opacity-50"
            >
              <Send size={15} />
              {currentVersion?.is_active ? "Currently Active" : `Publish v${selectedVersionNum}`}
            </button>
          </div>
        </div>

        {/* Tab navigation */}
        <div className="mt-6 flex border-b border-slate-200 space-x-8">
          <button
            onClick={() => setActiveTab("editor")}
            className={`pb-3 text-sm font-semibold transition border-b-2 flex items-center gap-2 ${
              activeTab === "editor"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Code2 size={16} />
            Editor &amp; AST
          </button>
          <button
            onClick={() => setActiveTab("simulate")}
            className={`pb-3 text-sm font-semibold transition border-b-2 flex items-center gap-2 ${
              activeTab === "simulate"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Play size={16} />
            Simulator &amp; Tests
          </button>
          <button
            onClick={() => {
              setActiveTab("diff");
              handleFetchDiff();
            }}
            className={`pb-3 text-sm font-semibold transition border-b-2 flex items-center gap-2 ${
              activeTab === "diff"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <FileDiff size={16} />
            Impact &amp; Diff
          </button>
          <button
            onClick={() => setActiveTab("publish")}
            className={`pb-3 text-sm font-semibold transition border-b-2 flex items-center gap-2 ${
              activeTab === "publish"
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <RotateCcw size={16} />
            Publish &amp; Rollback
          </button>
        </div>
      </div>

      {successMsg && (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800 flex items-center gap-2">
          <CheckCircle2 size={16} className="shrink-0 text-emerald-600" />
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="ml-auto text-xs font-semibold text-emerald-600 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 flex items-center gap-2">
          <AlertCircle size={16} className="shrink-0" />
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-auto text-xs font-semibold text-red-600 hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* TAB 1: EDITOR & AST */}
      {activeTab === "editor" && (
        <div className="space-y-6">
          {/* Version Selector Bar */}
          <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white p-4">
            <div className="flex items-center gap-3">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Inspecting Version:</span>
              <select
                value={selectedVersionNum}
                onChange={(e) => setSelectedVersionNum(Number(e.target.value))}
                className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-semibold text-slate-800 focus:border-blue-500 focus:outline-none"
              >
                {versions.map((v) => (
                  <option key={v.id} value={v.version_number}>
                    Version v{v.version_number} {v.is_active ? "(Active)" : `(${v.status})`}
                  </option>
                ))}
              </select>
              {currentVersion?.change_description && (
                <span className="text-xs text-slate-500 italic max-w-md truncate">
                  &ldquo;{currentVersion.change_description}&rdquo;
                </span>
              )}
            </div>
            <div className="text-xs text-slate-400">
              Created: {currentVersion ? new Date(currentVersion.created_at).toLocaleString() : ""}
            </div>
          </div>

          {/* New Version Drafting Modal / Drawer */}
          {isDrafting && (
            <div className="rounded-xl border border-blue-200 bg-blue-50/50 p-5 space-y-4 shadow-sm">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <GitBranch size={16} className="text-blue-600" />
                  Author New Version (v{versions.length + 1})
                </h3>
                <button
                  onClick={() => setIsDrafting(false)}
                  className="text-xs font-semibold text-slate-500 hover:text-slate-800"
                >
                  Cancel
                </button>
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
                  Change Rationale / Description
                </label>
                <input
                  type="text"
                  value={draftDescription}
                  onChange={(e) => setDraftDescription(e.target.value)}
                  placeholder="e.g. Lower autonomous threshold from $500 to $250"
                  className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm bg-white"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
                  APL/1.0 YAML Definition
                </label>
                <textarea
                  rows={12}
                  value={draftYaml}
                  onChange={(e) => setDraftYaml(e.target.value)}
                  className="w-full font-mono text-xs p-3 rounded-lg border border-slate-300 bg-slate-950 text-slate-100"
                  spellCheck={false}
                />
              </div>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => setIsDrafting(false)}
                  className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateDraftVersion}
                  disabled={savingDraft}
                  className="rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-semibold text-white hover:bg-blue-600 disabled:opacity-50"
                >
                  {savingDraft ? "Saving..." : "Commit Version"}
                </button>
              </div>
            </div>
          )}

          {/* Two-column View: Raw YAML and Normalized AST Rule Visualizer */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Left: Raw Code */}
            <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
              <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                  Immutable Source (v{currentVersion?.version_number})
                </span>
                <span className="text-xs font-mono text-slate-400">YAML SafeLoader</span>
              </div>
              <pre className="p-4 font-mono text-xs text-slate-100 bg-slate-950 overflow-x-auto max-h-[500px]">
                {currentVersion?.yaml_source || "# No source available"}
              </pre>
            </div>

            {/* Right: Parsed Rule Cards */}
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h3 className="text-sm font-bold text-slate-900">Compiled Rule Hierarchy</h3>
                <span className="text-xs text-slate-500">
                  Default Effect: <strong className="text-slate-800">{currentVersion?.compiled_ast?.default_effect || "DENY"}</strong>
                </span>
              </div>
              <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
                {currentVersion?.compiled_ast?.rules?.map((rule: any, idx: number) => {
                  const effect = (rule.effect || "DENY").toUpperCase();
                  const badgeColor =
                    effect === "ALLOW"
                      ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                      : effect === "REQUIRE_APPROVAL"
                      ? "bg-amber-50 text-amber-700 border-amber-200"
                      : "bg-red-50 text-red-700 border-red-200";

                  return (
                    <div key={rule.id || idx} className="rounded-lg border border-slate-200 p-4 space-y-2 bg-slate-50/50">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm font-bold text-slate-800">{rule.id}</span>
                        <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold border ${badgeColor}`}>
                          {effect}
                        </span>
                      </div>
                      {rule.description && <p className="text-xs text-slate-500">{rule.description}</p>}
                      <div className="rounded bg-white p-2 text-xs font-mono text-slate-700 border border-slate-100 overflow-x-auto">
                        <pre>{JSON.stringify(rule.when || rule.conditions || {}, null, 2)}</pre>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: SIMULATOR & TESTS */}
      {activeTab === "simulate" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Context Input */}
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Play size={16} className="text-blue-600" />
                  Simulation Context (JSON)
                </h3>
                <span className="text-xs text-slate-400">Zero side-effects</span>
              </div>
              <textarea
                rows={12}
                value={simContext}
                onChange={(e) => setSimContext(e.target.value)}
                className="w-full font-mono text-xs p-3 rounded-lg border border-slate-300 bg-slate-950 text-slate-100"
                spellCheck={false}
              />
              <button
                onClick={handleSimulate}
                disabled={simulating}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-[#4168e8] py-2.5 text-sm font-semibold text-white hover:bg-blue-600 disabled:opacity-50"
              >
                <Play size={15} />
                {simulating ? "Evaluating..." : `Simulate Against v${selectedVersionNum}`}
              </button>
            </div>

            {/* Simulation Result */}
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
              <h3 className="text-sm font-bold text-slate-900">Simulation Outcome</h3>
              {simResult ? (
                <div className="space-y-4">
                  <div
                    className={`rounded-lg border p-4 flex items-center justify-between ${
                      simResult.decision === "ALLOW"
                        ? "border-emerald-200 bg-emerald-50"
                        : simResult.decision === "REQUIRE_APPROVAL"
                        ? "border-amber-200 bg-amber-50"
                        : "border-red-200 bg-red-50"
                    }`}
                  >
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">Decision</p>
                      <p
                        className={`text-xl font-bold ${
                          simResult.decision === "ALLOW"
                            ? "text-emerald-700"
                            : simResult.decision === "REQUIRE_APPROVAL"
                            ? "text-amber-700"
                            : "text-red-700"
                        }`}
                      >
                        {simResult.decision}
                      </p>
                    </div>
                    <span className="text-xs text-slate-500 font-mono">
                      {simResult.evaluation_time_ms} ms
                    </span>
                  </div>

                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">Explanation</p>
                    <p className="text-sm text-slate-800 bg-slate-50 p-3 rounded-lg border border-slate-200">
                      {simResult.explanation}
                    </p>
                  </div>

                  {simResult.trace && simResult.trace.length > 0 && (
                    <div className="space-y-2">
                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">Rule Trace Tree</p>
                      <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                        {simResult.trace.map((tr: any, idx: number) => (
                          <div
                            key={idx}
                            className={`rounded-lg border p-3 text-xs font-mono space-y-1 ${
                              tr.matched ? "border-emerald-200 bg-emerald-50/40" : "border-slate-200 bg-slate-50"
                            }`}
                          >
                            <div className="flex items-center justify-between font-bold">
                              <span>Rule: {tr.rule_id}</span>
                              <span className={tr.matched ? "text-emerald-700" : "text-slate-400"}>
                                {tr.matched ? "MATCHED" : "SKIPPED"}
                              </span>
                            </div>
                            {tr.condition_traces?.map((ct: any, cidx: number) => (
                              <div key={cidx} className="text-slate-600 text-[11px] pl-2 border-l-2 border-slate-300">
                                {ct.field} {ct.operator} {JSON.stringify(ct.expected)} (Actual: {JSON.stringify(ct.actual)}) →{" "}
                                <strong className={ct.matched ? "text-emerald-600" : "text-red-500"}>
                                  {ct.matched ? "TRUE" : "FALSE"}
                                </strong>
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-16 text-center text-slate-400 text-sm">
                  Click &ldquo;Simulate&rdquo; to test your policy context with deterministic traces.
                </div>
              )}
            </div>
          </div>

          {/* Test Cases Section */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900">Automated Test Suites</h3>
                <p className="text-xs text-slate-500">Run regression tests before publishing.</p>
              </div>
              <button
                onClick={handleRunTests}
                disabled={runningTests || testCases.length === 0}
                className="flex items-center gap-2 rounded-lg bg-slate-900 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
              >
                <Activity size={14} />
                {runningTests ? "Running Tests..." : `Run ${testCases.length} Test Cases`}
              </button>
            </div>

            {testSummary && (
              <div
                className={`rounded-lg border p-4 space-y-2 ${
                  testSummary.all_passed ? "border-emerald-200 bg-emerald-50" : "border-red-200 bg-red-50"
                }`}
              >
                <p className="text-sm font-bold text-slate-900">
                  {testSummary.all_passed ? "All Test Cases Passed!" : "Test Failures Detected"}
                </p>
                <p className="text-xs text-slate-600">
                  Passed: {testSummary.passed_tests} / {testSummary.total_tests} (Failed: {testSummary.failed_tests})
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: IMPACT & DIFF */}
      {activeTab === "diff" && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-4">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                    Base Version
                  </label>
                  <select
                    value={diffBaseVer}
                    onChange={(e) => setDiffBaseVer(Number(e.target.value))}
                    className="rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-semibold"
                  >
                    {versions.map((v) => (
                      <option key={v.id} value={v.version_number}>
                        v{v.version_number}
                      </option>
                    ))}
                  </select>
                </div>
                <span className="text-slate-400 text-sm font-bold mt-4">vs</span>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                    Target Version
                  </label>
                  <select
                    value={diffTargetVer}
                    onChange={(e) => setDiffTargetVer(Number(e.target.value))}
                    className="rounded-lg border border-slate-200 px-3 py-1.5 text-sm font-semibold"
                  >
                    {versions.map((v) => (
                      <option key={v.id} value={v.version_number}>
                        v{v.version_number}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <button
                onClick={handleFetchDiff}
                disabled={loadingDiff}
                className="flex items-center gap-2 rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-semibold text-white hover:bg-blue-600 disabled:opacity-50"
              >
                <RefreshCw size={14} className={loadingDiff ? "animate-spin" : ""} />
                Calculate Diff &amp; Security Impact
              </button>
            </div>

            {diffResult && (
              <div className="space-y-4 pt-4 border-t border-slate-100">
                {diffResult.has_security_sensitive_changes && (
                  <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800 flex items-center gap-2">
                    <AlertTriangle size={18} className="shrink-0 text-amber-600" />
                    <div>
                      <strong className="font-bold">SECURITY-SENSITIVE CHANGES DETECTED:</strong>
                      <p className="text-xs text-amber-700 mt-0.5">
                        This change elevates privileges, broadens access, or removes approval guardrails. Review carefully before publishing.
                      </p>
                    </div>
                  </div>
                )}

                <div className="rounded-lg border border-slate-200 bg-slate-900 text-slate-100 p-5 font-mono text-xs whitespace-pre-wrap">
                  {diffResult.markdown_summary}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: PUBLISH & ROLLBACK */}
      {activeTab === "publish" && (
        <div className="space-y-6 max-w-3xl">
          {/* Publishing Box */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Send size={18} className="text-blue-600" />
              Publish Version to Fleet Gateways
            </h3>
            <p className="text-sm text-slate-500">
              Publishing activates this version and immediately pushes a new monotonically ordered, cryptographically signed
              configuration snapshot to all Enterprise Gateways and Sidecars.
            </p>
            <div className="flex items-center justify-between rounded-lg bg-slate-50 p-4 border border-slate-200">
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Target Version:</span>
                <p className="text-lg font-bold text-slate-900">v{selectedVersionNum}</p>
              </div>
              <button
                onClick={() => handlePublish(selectedVersionNum)}
                disabled={publishing || currentVersion?.is_active}
                className="rounded-lg bg-[#4168e8] px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-600 disabled:opacity-50"
              >
                {currentVersion?.is_active ? "Already Active" : `Publish v${selectedVersionNum}`}
              </button>
            </div>
          </div>

          {/* Rollback Box */}
          <div className="rounded-xl border border-amber-200 bg-white p-6 shadow-sm space-y-4">
            <h3 className="text-base font-bold text-amber-900 flex items-center gap-2">
              <RotateCcw size={18} className="text-amber-600" />
              Emergency Rollback
            </h3>
            <p className="text-sm text-slate-500">
              Revert to a previously known good policy version. To enforce strict anti-rollback invariants, this action
              generates a <strong>new strictly incremented signed configuration snapshot</strong>.
            </p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
                  Audit Reason for Rollback *
                </label>
                <input
                  type="text"
                  value={rollbackReason}
                  onChange={(e) => setRollbackReason(e.target.value)}
                  placeholder="e.g. Incident #1042: Policy blocking authorized travel booking"
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-amber-500 focus:outline-none"
                />
              </div>
              <button
                onClick={handleRollback}
                disabled={rollingBack || !rollbackReason.trim()}
                className="flex items-center gap-2 rounded-lg bg-amber-600 px-4 py-2 text-sm font-semibold text-white hover:bg-amber-700 disabled:opacity-50"
              >
                <RotateCcw size={15} />
                {rollingBack ? "Executing Rollback..." : `Execute Rollback to v${selectedVersionNum}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
