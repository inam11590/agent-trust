"""Fail CI if a likely private-key file or PEM block enters source control."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "node_modules", ".next", ".dart_tool", "build", "dist", ".npm-cache", "__pycache__"}
BAD_NAMES = {"id_rsa", "id_ed25519"}
BAD_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
PRIVATE_HEADER = re.compile(rb"(?m)^-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


def main() -> int:
    found = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP for part in path.relative_to(ROOT).parts):
            continue
        if path.name in BAD_NAMES or path.suffix.lower() in BAD_SUFFIXES:
            found.append(str(path.relative_to(ROOT)))
            continue
        if path.suffix.lower() not in {".py", ".ts", ".tsx", ".js", ".java", ".md", ".txt", ".json", ".properties"}:
            continue
        try:
            if PRIVATE_HEADER.search(path.read_bytes()):
                found.append(str(path.relative_to(ROOT)))
        except OSError:
            continue
    if found:
        print("Possible private key files or blocks found (contents hidden):", *found, sep="\n")
        return 1
    print("No private key files or PEM blocks found in source files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
