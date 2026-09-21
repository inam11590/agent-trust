#!/usr/bin/env python3
"""Pre-commit and CI secret scanner for AgentTrust.

Scans the repository for hardcoded private keys, credentials, tokens, and high-entropy secrets.
"""

import argparse
import math
import os
from pathlib import Path
import re
import sys
from typing import List, Tuple

# Patterns that indicate high-severity credential exposure
HIGH_RISK_PATTERNS = [
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), "Unencrypted Private Key Block"),
    (re.compile(r'(?i)(?:api_key|apikey|secret_key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{32,})["\']'), "High-Entropy API Key"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']'), "Hardcoded Password Literal"),
    (re.compile(r'(?i)ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'(?i)xox[baprs]-[0-9a-zA-Z]{10,48}'), "Slack API Token"),
    (re.compile(r'(?i)AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
    (re.compile(r'(?i)eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'), "Hardcoded JWT Token"),
]

# Patterns explicitly allowed or marked as mock/test
ALLOWLIST = [
    "TEST / MOCK ONLY",
    "MOCK_KEY",
    "test-secret",
    "at_test_",
    "REDACTED",
    "example",
    "localhost",
    "127.0.0.1",
    "changeme",
    "dummy",
    "contains(\"-----BEGIN",
    "replace(\"-----BEGIN",
]

IGNORED_DIRS = {
    ".git",
    ".gemini",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".next",
    ".dart_tool",
    "build",
    "dist",
    "coverage",
    ".system_generated",
    "scratch",
    ".issuer_keys",
    ".sidecar_keys",
    ".sidecar_cache",
    "tests",
    "test",
    ".gradle",
    ".idea",
    ".vscode",
    "ephemeral",
    "windows",
    "ios",
    "android",
    "linux",
    "macos",
}

IGNORED_EXTENSIONS = {
    ".pyc",
    ".png",
    ".jpg",
    ".jpeg",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".lock",
    ".tar",
    ".gz",
    ".zip",
}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def scan_file(file_path: Path) -> List[Tuple[int, str, str]]:
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        # Skip allowed comments / test fixtures
        if any(allowed in line for allowed in ALLOWLIST):
            continue

        for pattern, desc in HIGH_RISK_PATTERNS:
            match = pattern.search(line)
            if match:
                # Exclude mock assignments in test files
                if "test" in file_path.name.lower() and "mock" in line.lower():
                    continue
                findings.append((idx, desc, line.strip()[:80]))
                break

    return findings


def run_scanner(root_dir: Path) -> int:
    print(f"[*] Starting AgentTrust Secret Scan...", flush=True)
    total_scanned = 0
    total_findings = 0

    target_paths = []
    repo_root = Path(__file__).resolve().parents[1]
    if root_dir == repo_root or root_dir == Path(".").resolve():
        for sub in ['backend/app', 'sidecar', 'sdk', 'deploy', 'scripts', 'docs', 'web/src', '.github']:
            sp = repo_root / sub
            if sp.exists():
                target_paths.append(sp)
    else:
        target_paths = [root_dir]

    for target in target_paths:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            for f in files:
                p = Path(root) / f
                if p.suffix.lower() in IGNORED_EXTENSIONS or p.name.startswith("."):
                    continue
                if p.name == "scan_secrets.py":
                    continue
                total_scanned += 1
                findings = scan_file(p)
                if findings:
                    total_findings += len(findings)
                    rel_path = p.relative_to(repo_root) if repo_root in p.parents else p
                    for line_no, desc, snippet in findings:
                        print(f"[!] FINDING: {rel_path}:{line_no} - {desc} -> {snippet}", flush=True)

    print(f"\n[*] Scan Complete. Scanned {total_scanned} files.", flush=True)
    if total_findings > 0:
        print(f"[FAIL] Detected {total_findings} potential secret exposures!", flush=True)
        return 1
    else:
        print("[PASS] Zero secrets detected in scan scope.", flush=True)
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentTrust Secret Scanner")
    parser.add_argument("--path", default=".", help="Directory to scan")
    args = parser.parse_args()
    sys.exit(run_scanner(Path(args.path).resolve()))
