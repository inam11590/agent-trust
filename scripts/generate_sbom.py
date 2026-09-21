#!/usr/bin/env python3
"""Software Bill of Materials (SBOM) Generator for AgentTrust.

Produces CycloneDX-compliant JSON SBOM by inspecting pinned Python and Node dependencies.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List


def parse_requirements_txt(req_path: Path) -> List[Dict[str, Any]]:
    components = []
    if not req_path.exists():
        return components

    lines = req_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # match pkg==1.2.3 or pkg>=1.2.3
        m = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:[=><~]=?|===?)([a-zA-Z0-9_\-\.]+)', line)
        if m:
            name, version = m.group(1), m.group(2)
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "scope": "required",
            })
    return components


def parse_package_json(pkg_path: Path) -> List[Dict[str, Any]]:
    components = []
    if not pkg_path.exists():
        return components
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
        deps = data.get("dependencies", {})
        for name, ver in deps.items():
            clean_ver = ver.lstrip("^~>=")
            components.append({
                "type": "library",
                "name": name,
                "version": clean_ver,
                "purl": f"pkg:npm/{name}@{clean_ver}",
                "scope": "required",
            })
    except Exception as e:
        print(f"[!] Warning: failed to parse {pkg_path}: {e}")
    return components


def generate_cyclonedx_sbom(root_dir: Path) -> Dict[str, Any]:
    components = []
    components.extend(parse_requirements_txt(root_dir / "backend" / "requirements.txt"))
    components.extend(parse_package_json(root_dir / "web" / "package.json"))
    components.extend(parse_package_json(root_dir / "sdk" / "node" / "package.json"))

    # De-duplicate components by purl
    seen = set()
    unique_components = []
    for c in components:
        if c["purl"] not in seen:
            seen.add(c["purl"])
            unique_components.append(c)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:agenttrust-sbom-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "AgentTrust",
                    "name": "agenttrust-sbom-generator",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": "AgentTrust",
                "version": "0.1.0",
                "description": "Cryptographic Trust & Identity Platform for Autonomous AI Agents",
            }
        },
        "components": unique_components,
    }
    return sbom


def main():
    parser = argparse.ArgumentParser(description="Generate CycloneDX SBOM for AgentTrust")
    parser.add_argument("--output", default="sbom.json", help="Output file path for SBOM JSON")
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parents[1]
    sbom_data = generate_cyclonedx_sbom(root_dir)

    out_path = Path(args.output)
    out_path.write_text(json.dumps(sbom_data, indent=2), encoding="utf-8")
    print(f"[+] SBOM generated successfully with {len(sbom_data['components'])} components -> {out_path}")


if __name__ == "__main__":
    main()
