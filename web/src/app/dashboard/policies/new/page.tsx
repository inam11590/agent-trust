"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Braces,
  CheckCircle2,
  FileCode,
  Info,
  Play,
  Save,
  Shield,
  Sparkles,
} from "lucide-react";

import { apiRequest } from "@/lib/api/client";

interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  yaml_source: string;
}

interface ValidationResponse {
  is_valid: boolean;
  content_hash?: string;
  errors: { message: string; path: string; severity: string }[];
  warnings: { message: string; path: string; severity: string }[];
  lint_issues: { code: string; message: string; rule_id?: string; severity: string }[];
}

export default function NewPolicyPage() {
  const router = useRouter();

  // Form State
  const [name, setName] = useState("");
  const [category, setCategory] = useState("Financial Controls");
  const [description, setDescription] = useState("");
  const [yamlSource, setYamlSource] = useState("");
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");

  // Validation & Saving State
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidationResponse | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch templates on mount
  useEffect(() => {
    async function loadTemplates() {
      try {
        const res = await apiRequest<PolicyTemplate[]>("/v1/policies/templates");
        if (res && res.length > 0) {
          setTemplates(res);
          setSelectedTemplate(res[0].id);
          setYamlSource(res[0].yaml_source);
          setName(res[0].name);
          setCategory(res[0].category || "General");
          setDescription(res[0].description || "");
        }
      } catch (e) {
        console.error("Failed to load templates:", e);
      }
    }
    loadTemplates();
  }, []);

  const handleTemplateSelect = (templateId: string) => {
    setSelectedTemplate(templateId);
    const t = templates.find((item) => item.id === templateId);
    if (t) {
      setYamlSource(t.yaml_source);
      if (!name) setName(t.name);
      setCategory(t.category);
      setDescription(t.description);
      setValidationResult(null);
    }
  };

  const handleValidate = async () => {
    setValidating(true);
    setError(null);
    try {
      const res = await apiRequest<ValidationResponse>("/v1/policies/validate", {
        method: "POST",
        body: JSON.stringify({
          yaml_source: yamlSource,
          source_format: "yaml",
        }),
      });
      setValidationResult(res);
    } catch (err: any) {
      setError(err?.message || "Validation failed.");
    } finally {
      setValidating(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError("Please provide a policy name.");
      return;
    }
    if (!yamlSource.trim()) {
      setError("Policy document source cannot be empty.");
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const res = await apiRequest<{ id: string }>("/v1/policies", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim(),
          category: category.trim(),
          initial_yaml_source: yamlSource,
        }),
      });
      router.push(`/dashboard/policies/${res.id}`);
    } catch (err: any) {
      setError(err?.message || "Failed to create policy.");
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Top Breadcrumb & Actions */}
      <div className="flex items-center justify-between">
        <Link
          href="/dashboard/policies"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-500 hover:text-slate-900 transition"
        >
          <ArrowLeft size={16} />
          Back to Policies
        </Link>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleValidate}
            disabled={validating}
            className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            <Play size={14} className="text-blue-600" />
            {validating ? "Validating..." : "Validate & Lint"}
          </button>
          <button
            type="button"
            onClick={handleCreate}
            disabled={saving}
            className="flex items-center gap-2 rounded-lg bg-[#4168e8] px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-600 transition disabled:opacity-50"
          >
            <Save size={15} />
            {saving ? "Creating..." : "Create Policy"}
          </button>
        </div>
      </div>

      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">Create New Policy</h1>
        <p className="text-sm text-slate-500">
          Author a new declarative APL/1.0 policy document from scratch or starting from a template.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 flex items-center gap-2">
          <AlertCircle size={16} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Template Chooser */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <Sparkles size={16} className="text-amber-500" />
            Quick-Start Template
          </label>
          <span className="text-xs text-slate-400">Pre-built industry standard guardrails</span>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
          {templates.map((tpl) => (
            <button
              key={tpl.id}
              type="button"
              onClick={() => handleTemplateSelect(tpl.id)}
              className={`rounded-lg border p-3 text-left transition ${
                selectedTemplate === tpl.id
                  ? "border-blue-500 bg-blue-50/50 ring-2 ring-blue-500/20"
                  : "border-slate-200 hover:border-slate-300 bg-white"
              }`}
            >
              <p className="text-sm font-semibold text-slate-900">{tpl.name}</p>
              <p className="mt-1 text-xs text-slate-500 line-clamp-2">{tpl.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Metadata Form */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
        <h2 className="text-sm font-semibold text-slate-900">Policy Metadata</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
              Policy Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Travel Flight Purchase Policy"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
              Category
            </label>
            <input
              type="text"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="e.g. Financial Controls, Risk, Compliance"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
            Description
          </label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Brief explanation of policy intent and operational boundaries"
            className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900 focus:border-blue-500 focus:outline-none"
          />
        </div>
      </div>

      {/* Code Editor */}
      <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-4 py-2.5">
          <div className="flex items-center gap-2">
            <FileCode size={16} className="text-slate-500" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-700">
              APL/1.0 Specification (YAML)
            </span>
          </div>
          <span className="text-xs text-slate-400 font-mono">Max size: 64 KB</span>
        </div>
        <textarea
          rows={18}
          value={yamlSource}
          onChange={(e) => {
            setYamlSource(e.target.value);
            setValidationResult(null);
          }}
          className="w-full font-mono text-xs text-slate-900 p-4 focus:outline-none bg-slate-950 text-slate-100 selection:bg-blue-600"
          spellCheck={false}
        />
      </div>

      {/* Validation Feedback Banner */}
      {validationResult && (
        <div
          className={`rounded-xl border p-5 space-y-3 ${
            validationResult.is_valid
              ? "border-emerald-200 bg-emerald-50/60"
              : "border-red-200 bg-red-50/60"
          }`}
        >
          <div className="flex items-center gap-2">
            {validationResult.is_valid ? (
              <CheckCircle2 size={18} className="text-emerald-600" />
            ) : (
              <AlertCircle size={18} className="text-red-600" />
            )}
            <h3 className="text-sm font-semibold text-slate-900">
              {validationResult.is_valid ? "Policy Syntax and Schema Valid" : "Validation Errors Detected"}
            </h3>
            {validationResult.content_hash && (
              <span className="ml-auto text-xs font-mono text-slate-500 truncate max-w-xs">
                {validationResult.content_hash}
              </span>
            )}
          </div>

          {validationResult.errors.length > 0 && (
            <div className="space-y-1">
              <p className="text-xs font-bold uppercase tracking-wider text-red-700">Errors (must fix):</p>
              <ul className="list-disc pl-5 text-xs text-red-600 space-y-0.5">
                {validationResult.errors.map((e, idx) => (
                  <li key={idx}>
                    <span className="font-mono font-semibold">[{e.path}]:</span> {e.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {validationResult.warnings.length > 0 && (
            <div className="space-y-1">
              <p className="text-xs font-bold uppercase tracking-wider text-amber-700">Warnings:</p>
              <ul className="list-disc pl-5 text-xs text-amber-600 space-y-0.5">
                {validationResult.warnings.map((w, idx) => (
                  <li key={idx}>
                    <span className="font-mono font-semibold">[{w.path}]:</span> {w.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {validationResult.lint_issues.length > 0 && (
            <div className="space-y-1">
              <p className="text-xs font-bold uppercase tracking-wider text-purple-700">Linter Findings:</p>
              <ul className="list-disc pl-5 text-xs text-purple-600 space-y-0.5">
                {validationResult.lint_issues.map((l, idx) => (
                  <li key={idx}>
                    <span className="font-mono font-semibold">[{l.code}]:</span> {l.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
