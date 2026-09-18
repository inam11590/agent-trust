"""Local, bounded Ed25519 v1 verification microbenchmark (no network)."""

import base64
from pathlib import Path
from statistics import mean
from time import perf_counter_ns

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "docs" / "test-vectors" / "agent-signing-v1.properties"


def main() -> None:
    values = dict(line.split("=", 1) for line in VECTOR.read_text().splitlines()
                  if line and not line.startswith("#"))
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(values["public_raw_base64"]))
    canonical = base64.b64decode(values["canonical_base64"])
    signature = base64.b64decode(values["signature_base64"])
    samples = []
    errors = 0
    for _ in range(1000):
        start = perf_counter_ns()
        try:
            public.verify(signature, canonical)
        except Exception:
            errors += 1
        samples.append((perf_counter_ns() - start) / 1_000_000)
    ordered = sorted(samples)
    print(f"Ed25519 v1 signature verification, 1000 local operations: "
          f"mean={mean(samples):.4f} ms, p95={ordered[949]:.4f} ms, errors={errors}")


if __name__ == "__main__":
    main()
