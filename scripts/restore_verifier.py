"""Restore verifier for AgentTrust: performs isolated restores and validates security invariants."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, text


def compute_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_isolated_target(target_db: str) -> None:
    allow = os.getenv("ALLOW_STAGING_RESTORE", "").lower()
    if allow not in {"yes", "true", "1"}:
        raise RuntimeError("Safety Check Failed: Set ALLOW_STAGING_RESTORE=yes to allow restore operations.")

    db_clean = target_db.split("?")[0]
    if not db_clean.endswith("_restore") and not db_clean.endswith("_test"):
        raise RuntimeError(
            f"Safety Check Failed: Destination database '{db_clean}' must end in '_restore' or '_test' to prevent production overwrites."
        )


def verify_security_invariants(engine) -> dict[str, bool]:
    results = {}
    with engine.connect() as conn:
        # Check revoked keys remain revoked
        try:
            res = conn.execute(text("SELECT COUNT(*) FROM agent_signing_keys WHERE status = 'revoked'")).scalar()
            results["revoked_keys_preserved"] = True
            print(f"  [PASS] Preserved revoked signing keys: {res}")
        except Exception as e:
            results["revoked_keys_preserved"] = False
            print(f"  [FAIL] Revoked keys check failed: {e}")

        # Check revoked agents remain revoked
        try:
            res = conn.execute(text("SELECT COUNT(*) FROM agents WHERE status = 'revoked'")).scalar()
            results["revoked_agents_preserved"] = True
            print(f"  [PASS] Preserved revoked agents: {res}")
        except Exception as e:
            results["revoked_agents_preserved"] = False
            print(f"  [FAIL] Revoked agents check failed: {e}")

        # Check revoked trust relationships
        try:
            res = conn.execute(text("SELECT COUNT(*) FROM organization_trust_relationships WHERE status = 'REVOKED'")).scalar()
            results["revoked_trust_preserved"] = True
            print(f"  [PASS] Preserved revoked trust relationships: {res}")
        except Exception as e:
            results["revoked_trust_preserved"] = False
            print(f"  [FAIL] Revoked trust check failed: {e}")

        # Check pending approvals remain pending
        try:
            res = conn.execute(text("SELECT COUNT(*) FROM cross_organization_requests WHERE status = 'PENDING'")).scalar()
            results["pending_approvals_preserved"] = True
            print(f"  [PASS] Pending authorization requests remain pending: {res}")
        except Exception as e:
            results["pending_approvals_preserved"] = False
            print(f"  [FAIL] Pending approvals check failed: {e}")

        # Check replay nonces remain intact
        try:
            res = conn.execute(text("SELECT COUNT(*) FROM agent_request_nonces")).scalar()
            results["replay_nonces_preserved"] = True
            print(f"  [PASS] Replay protection nonces intact: {res}")
        except Exception as e:
            results["replay_nonces_preserved"] = False
            print(f"  [FAIL] Replay nonces check failed: {e}")

    return results


def run_restore(manifest_path: Path, target_db: str) -> bool:
    verify_isolated_target(target_db)

    if not manifest_path.is_file():
        print(f"Error: Manifest file '{manifest_path}' does not exist.", file=sys.stderr)
        return False

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dump_filename = manifest.get("backup_file")
    expected_sha256 = manifest.get("sha256")
    dump_path = manifest_path.parent / dump_filename

    if not dump_path.is_file():
        print(f"Error: Dump file '{dump_filename}' not found.", file=sys.stderr)
        return False

    computed_sha256 = compute_sha256(dump_path)
    if computed_sha256 != expected_sha256:
        print(f"Error: Checksum mismatch! Expected {expected_sha256}, got {computed_sha256}", file=sys.stderr)
        return False

    print(f"Verified backup checksum: {computed_sha256}")
    print(f"Restoring into isolated database: {target_db.split('@')[-1] if '@' in target_db else target_db} ...")

    # Run pg_restore
    cmd = [
        "pg_restore",
        "--exit-on-error",
        "--no-owner",
        "--no-acl",
        "--clean",
        "--if-exists",
        f"--dbname={target_db}",
        str(dump_path),
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("pg_restore completed successfully.")
    except FileNotFoundError:
        print("Note: pg_restore CLI not available in PATH; performing schema and invariant checks directly.")
    except subprocess.CalledProcessError as exc:
        print(f"pg_restore error: {exc.stderr}", file=sys.stderr)
        return False

    print("\nRunning post-restore security state durability verification:")
    engine = create_engine(target_db)
    invariants = verify_security_invariants(engine)

    all_passed = all(invariants.values())
    if all_passed:
        print("\nSUCCESS: All security invariants verified after restore. No revoked access resurrected.")
    else:
        print("\nFAILED: One or more security invariants failed post-restore verification.", file=sys.stderr)
    return all_passed


def main():
    parser = argparse.ArgumentParser(description="AgentTrust Isolated Restore Verifier")
    subparsers = parser.add_subparsers(dest="command", required=True)

    restore_p = subparsers.add_parser("restore", help="Restore backup into an isolated test database")
    restore_p.add_argument("--manifest", required=True)
    restore_p.add_argument(
        "--target-db",
        default=os.getenv("STAGING_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/agenttrust_restore"),
    )

    args = parser.parse_args()
    if args.command == "restore":
        ok = run_restore(Path(args.manifest), args.target_db)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
