"""Deterministic AI Workload & Framework Classification Service (Step 29).

Analyzes safe metadata (dependency names, environment variable names, labels, image names)
without executing code, inspecting customer documents, or capturing secret values.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple


# Known Autonomous Agent Frameworks (High Signal)
AGENT_FRAMEWORKS = {
    "langchain": "LangChain agent ecosystem",
    "langchain-core": "LangChain core runtime",
    "langchain-community": "LangChain community tooling",
    "langgraph": "LangGraph multi-agent cyclical orchestration",
    "crewai": "CrewAI autonomous multi-agent framework",
    "crewai-tools": "CrewAI autonomous agent toolset",
    "autogen": "Microsoft AutoGen multi-agent conversation framework",
    "pyautogen": "Microsoft AutoGen Python engine",
    "autogen-agentchat": "AutoGen conversational agent protocol",
    "llamaindex": "LlamaIndex data agent framework",
    "llama-index": "LlamaIndex data agent framework",
    "semantic-kernel": "Microsoft Semantic Kernel AI agent SDK",
    "haystack": "deepset Haystack pipeline and agent framework",
    "haystack-ai": "deepset Haystack 2.x agent framework",
    "metagpt": "MetaGPT multi-agent collaborative software development",
    "camel-ai": "CAMEL communicative multi-agent framework",
    "agentops": "AgentOps agent monitoring and observability",
    "phidata": "Phidata autonomous assistant framework",
    "babyagi": "BabyAGI task-driven autonomous agent",
}

# Known AI Model Provider SDKs (Medium Signal)
MODEL_PROVIDERS = {
    "openai": "OpenAI Python API client",
    "anthropic": "Anthropic Claude API client",
    "cohere": "Cohere Language Model SDK",
    "mistralai": "Mistral AI API client",
    "google-generativeai": "Google Gemini / Generative AI SDK",
    "google-genai": "Google GenAI SDK",
    "boto3": "AWS SDK (potential Bedrock access)",
    "bedrock": "AWS Bedrock client",
    "azure-openai": "Azure OpenAI Service SDK",
    "azure-ai-generative": "Azure AI Generative SDK",
    "ollama": "Ollama local model inference client",
    "vllm": "vLLM high-throughput model inference engine",
    "groq": "Groq LPU inference client",
    "together": "Together AI model API client",
    "replicate": "Replicate cloud model deployment client",
    "transformers": "Hugging Face Transformers deep learning library",
}

# Safe Environment Variable Names (Recognized names only; NEVER collect values!)
SAFE_ENV_VAR_NAMES = {
    "OPENAI_API_KEY": ("OpenAI", "MODEL_PROVIDER_CONFIG"),
    "OPENAI_BASE_URL": ("OpenAI", "MODEL_PROVIDER_CONFIG"),
    "ANTHROPIC_API_KEY": ("Anthropic", "MODEL_PROVIDER_CONFIG"),
    "COHERE_API_KEY": ("Cohere", "MODEL_PROVIDER_CONFIG"),
    "MISTRAL_API_KEY": ("Mistral", "MODEL_PROVIDER_CONFIG"),
    "GOOGLE_API_KEY": ("Google Gemini", "MODEL_PROVIDER_CONFIG"),
    "GEMINI_API_KEY": ("Google Gemini", "MODEL_PROVIDER_CONFIG"),
    "AWS_BEDROCK_AGENT_ID": ("AWS Bedrock", "AGENT_DEPLOYMENT_CONFIG"),
    "BEDROCK_AGENT_ID": ("AWS Bedrock", "AGENT_DEPLOYMENT_CONFIG"),
    "AZURE_OPENAI_API_KEY": ("Azure OpenAI", "MODEL_PROVIDER_CONFIG"),
    "AZURE_OPENAI_ENDPOINT": ("Azure OpenAI", "MODEL_PROVIDER_CONFIG"),
    "GROQ_API_KEY": ("Groq", "MODEL_PROVIDER_CONFIG"),
    "LANGCHAIN_API_KEY": ("LangChain", "AGENT_FRAMEWORK_CONFIG"),
    "LANGCHAIN_TRACING_V2": ("LangChain", "AGENT_FRAMEWORK_CONFIG"),
    "AGENTOPS_API_KEY": ("AgentOps", "AGENT_OBSERVABILITY_CONFIG"),
    "AGENTTRUST_AGENT_ID": ("AgentTrust", "EXPLICIT_AGENTTRUST_IDENTITY"),
    "AGENTTRUST_API_KEY": ("AgentTrust", "EXPLICIT_AGENTTRUST_CONFIG"),
    "AGENTTRUST_GATEWAY_URL": ("AgentTrust", "EXPLICIT_AGENTTRUST_CONFIG"),
}

# Common Agent-like Naming Tokens
AGENT_NAMING_PATTERNS = [
    re.compile(r"(?:^|[-_])(agent|bot|assistant|copilot|worker|llm|triage|orchestrator)(?:[-_]|$)", re.IGNORECASE),
]


def classify_workload_evidence(
    raw_dependencies: Optional[List[str]] = None,
    env_var_names: Optional[List[str]] = None,
    labels: Optional[Dict[str, str]] = None,
    image_name: Optional[str] = None,
    resource_name: Optional[str] = None,
    telemetry_signals: Optional[List[str]] = None,
    environment: str = "unknown",
) -> Tuple[int, str, List[str], Dict[str, Any]]:
    """Compute transparent deterministic confidence score (0-100), level, and explanations.
    
    Returns:
        (confidence_score, confidence_level, explanation_reasons, structured_findings)
    """
    raw_dependencies = [d.lower().strip() for d in (raw_dependencies or [])]
    env_var_names = set(env_var_names or [])
    labels = labels or {}
    telemetry_signals = telemetry_signals or []

    score = 0
    reasons: List[str] = []
    findings: Dict[str, Any] = {
        "frameworks_detected": [],
        "providers_detected": [],
        "safe_env_vars_detected": [],
        "agenttrust_indicators": [],
        "naming_indicators": [],
    }

    # 1. AgentTrust Explicit Identity / Indicators (+40)
    agenttrust_id = None
    if "agenttrust.io/agent-id" in labels:
        agenttrust_id = labels["agenttrust.io/agent-id"]
    elif "AGENTTRUST_AGENT_ID" in env_var_names:
        agenttrust_id = "EXPLICIT_ENV_VAR"

    if agenttrust_id:
        score += 40
        reasons.append("Explicit AgentTrust Agent ID metadata or configuration detected (+40).")
        findings["agenttrust_indicators"].append("agent_id_metadata_present")

    # 2. Gateway / Sidecar Telemetry Observation (+30)
    if any("GATEWAY_OBSERVATION" in s or "SIDECAR_OBSERVATION" in s for s in telemetry_signals):
        score += 30
        reasons.append("Workload was observed communicating with AgentTrust Gateway/Sidecar (+30).")
        findings["agenttrust_indicators"].append("gateway_sidecar_traffic")

    # 3. Autonomous Agent Framework Dependencies (+30)
    detected_frameworks = []
    for dep in raw_dependencies:
        # Match base package name
        base_pkg = re.split(r"[><=~;]", dep)[0].strip()
        if base_pkg in AGENT_FRAMEWORKS:
            detected_frameworks.append(base_pkg)

    if detected_frameworks:
        score += 30
        distinct_fw = sorted(list(set(detected_frameworks)))
        reasons.append(f"Autonomous agent framework detected: {', '.join(distinct_fw)} (+30).")
        findings["frameworks_detected"] = distinct_fw

    # 4. Model Provider SDKs (+15)
    detected_providers = []
    for dep in raw_dependencies:
        base_pkg = re.split(r"[><=~;]", dep)[0].strip()
        if base_pkg in MODEL_PROVIDERS:
            detected_providers.append(base_pkg)

    if detected_providers:
        score += 15
        distinct_prov = sorted(list(set(detected_providers)))
        reasons.append(f"AI model provider SDK detected: {', '.join(distinct_prov)} (+15).")
        findings["providers_detected"] = distinct_prov

    # 5. Safe Environment Variable Names (+10)
    matched_env_names = []
    for var_name in env_var_names:
        clean_name = var_name.strip()
        if clean_name in SAFE_ENV_VAR_NAMES:
            matched_env_names.append(clean_name)

    if matched_env_names:
        score += 10
        reasons.append(f"Safe AI/model configuration variable names detected: {', '.join(sorted(matched_env_names))} (+10).")
        findings["safe_env_vars_detected"] = sorted(matched_env_names)

    # 6. Agent-like Naming or Label Metadata (+10)
    naming_matches = []
    target_strings = [resource_name or "", image_name or ""] + list(labels.values())
    for s in target_strings:
        for pat in AGENT_NAMING_PATTERNS:
            if pat.search(s):
                naming_matches.append(s)
                break

    if naming_matches:
        score += 10
        reasons.append(f"Agent-like naming or label token detected in resource/image metadata (+10).")
        findings["naming_indicators"] = list(set(naming_matches))[:3]

    # 7. Production Environment Context (+5)
    if environment.lower() in ("prod", "production"):
        score += 5
        reasons.append("Deployed in production environment (+5).")

    # Bounded between 0 and 100
    confidence_score = min(100, max(0, score))

    # Map to ConfidenceLevel
    if confidence_score >= 70:
        confidence_level = "HIGH"
    elif confidence_score >= 40:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"

    if not reasons:
        reasons.append("No definitive AI agent or model provider signals detected.")

    return confidence_score, confidence_level, reasons, findings
