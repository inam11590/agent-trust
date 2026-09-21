#!/usr/bin/env python3
"""Release Manifest and Artifact Verification Generator for AgentTrust.

Computes SHA-256 cryptographic digests of release artifacts, container definitions,
and supply chain manifests. Supports verification of existing manifests.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def generate_manifest(root_dir: Path) -> Dict[str, Any]:
    critical_artifacts = [
        "backend/Dockerfile",
        "sidecar/Dockerfile",
        "backend/requirements.txt",
        "web/package.json",
        "sdk/node/package.json",
        "sdk/python/pyproject.toml",
    ]

    artifacts = []
    for rel_path in critical_artifacts:
        p = root_dir / rel_path
        if p.exists():
            digest = sha256_file(p)
            artifacts.append({
                "path": rel_path,
                "sha256": digest,
                "size_bytes": p.stat().st_size,
            })

    manifest = {
        "manifest_version": "1.0",
        "platform": "AgentTrust",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "artifacts_count": len(artifacts),
        "artifacts": artifacts,
    }
    return manifest


def verify_manifest(manifest_path: Path, root_dir: Path) -> bool:
    if not manifest_path.exists():
        print(f"[!] Manifest not found: {manifest_path}")
        return False
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    all_ok = True
    for item in data.get("artifacts", []):
        p = root_dir / item["path"]
        if not p.exists():
            print(f"[FAIL] Missing artifact: {item['path']}")
            all_ok = False
            continue
        current_digest = sha256_file(p)
        if current_digest != item["sha256"]:
            print(f"[FAIL] Digest mismatch for {item['path']}! Expected {item['sha256']}, got {current_digest}")
            all_ok = False
        else:
            print(f"[OK] {item['path']} verified ({current_digest[:16]}...)")
    return all_ok


def main():
    parser = argparse.ArgumentParser(description="AgentTrust Release Manifest Tool")
    parser.add_argument("--output", default="release_manifest.json", help="Output path for manifest")
    parser.add_argument("--verify", help="Verify existing manifest file against filesystem")
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parents[1]

    if args.verify:
        ok = verify_manifest(Path(args.verify), root_dir)
        sys.exit(0 if ok else 1)
    else:
        manifest = generate_manifest(root_dir)
        out_p = Path(args.output)
        out_p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"[+] Release manifest generated with {manifest['artifacts_count']} artifacts -> {out_p}")


if __name__ == "__main__":
    main()
