"""AgentTrust Developer Command-Line Interface (CLI)."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agenttrust.client import AgentTrust, AgentTrustError
from agenttrust.signing import AgentSigner


CONFIG_DIR = Path.home() / ".agenttrust"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config() -> dict[str, str]:
    config: dict[str, str] = {}
    if CONFIG_FILE.is_file():
        try:
            config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    if "AGENTTRUST_API_KEY" in os.environ:
        config["api_key"] = os.environ["AGENTTRUST_API_KEY"]
    if "AGENTTRUST_BASE_URL" in os.environ:
        config["base_url"] = os.environ["AGENTTRUST_BASE_URL"]
    if "AGENTTRUST_ORG_ID" in os.environ:
        config["organization_id"] = os.environ["AGENTTRUST_ORG_ID"]
    return config


def save_config(config: dict[str, str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass


def get_client(args: argparse.Namespace) -> AgentTrust:
    config = load_config()
    api_key = getattr(args, "api_key", None) or config.get("api_key")
    base_url = getattr(args, "base_url", None) or config.get("base_url") or "http://localhost:8000"
    if not api_key:
        print("Error: No API key provided. Run 'agenttrust configure' or pass --api-key.", file=sys.stderr)
        sys.exit(1)
    try:
        return AgentTrust(api_key=api_key, base_url=base_url)
    except Exception as exc:
        print(f"Error initializing AgentTrust client: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_configure(args: argparse.Namespace) -> int:
    config = load_config()
    if args.api_key:
        config["api_key"] = args.api_key
    if args.base_url:
        config["base_url"] = args.base_url.rstrip("/")
    if args.org_id:
        config["organization_id"] = args.org_id

    save_config(config)
    print("AgentTrust CLI configuration updated successfully:")
    print(f"  Configuration file: {CONFIG_FILE}")
    masked_key = (config["api_key"][:12] + "..." + config["api_key"][-6:]) if config.get("api_key") else "(not set)"
    print(f"  API Key:            {masked_key}")
    print(f"  Base URL:           {config.get('base_url', 'http://localhost:8000')}")
    if config.get("organization_id"):
        print(f"  Organization ID:    {config['organization_id']}")
    return 0


def cmd_keys_generate(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = args.name or "agent_key"

    priv_path = out_dir / f"{name}_private.pem"
    pub_path = out_dir / f"{name}_public.pem"

    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    fingerprint = hashlib.sha256(raw_pub).hexdigest()
    key_id = f"key_ag_{secrets.token_hex(12)}"

    priv_path.write_bytes(priv_pem)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    pub_path.write_bytes(pub_pem)

    print("Generated Ed25519 keypair successfully:")
    print(f"  Key ID:          {key_id}")
    print(f"  Algorithm:       Ed25519")
    print(f"  Fingerprint:     {fingerprint}")
    print(f"  Private Key:     {priv_path.resolve()}")
    print(f"  Public Key:      {pub_path.resolve()}")
    print(f"  Base64 Public:   {base64.b64encode(raw_pub).decode('ascii')}")
    print("\n[CRITICAL SECURITY NOTICE]")
    print("  The private key is stored ONLY on your local machine.")
    print("  Never share, transmit, or commit your private key to version control.")
    print("  Register only your public key using: agenttrust keys register")
    return 0


def cmd_keys_register(args: argparse.Namespace) -> int:
    client = get_client(args)
    pub_path = Path(args.public_key_path)
    if not pub_path.is_file():
        print(f"Error: Public key file not found: {pub_path}", file=sys.stderr)
        return 1

    pub_bytes = pub_path.read_bytes()
    try:
        pub_key = serialization.load_pem_public_key(pub_bytes)
        if not isinstance(pub_key, Ed25519PublicKey):
            print("Error: Public key must be an Ed25519 key.", file=sys.stderr)
            return 1
        raw_pub = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception:
        raw_pub = pub_bytes

    b64_pub = base64.b64encode(raw_pub).decode("ascii")
    key_id = args.key_id or f"key_ag_{secrets.token_hex(12)}"

    payload = {
        "key_id": key_id,
        "algorithm": "Ed25519",
        "public_key": b64_pub,
    }

    try:
        res = client._request("POST", f"/api/v1/agents/{args.agent_id}/signing-keys", payload)
        print("Successfully registered agent signing key:")
        print(f"  Key ID:      {res.get('key_id', key_id)}")
        print(f"  Agent ID:    {args.agent_id}")
        print(f"  Fingerprint: {res.get('fingerprint', 'verified')}")
        print(f"  Status:      {res.get('status', 'active')}")
        return 0
    except AgentTrustError as err:
        print(f"Registration failed: {err}", file=sys.stderr)
        return 1


def cmd_agents_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client._request("GET", "/api/v1/agents")
        agents = res if isinstance(res, list) else res.get("items", [])
        if not agents:
            print("No agents found.")
            return 0
        print(f"{'AGENT ID':<36} {'NAME':<28} {'ENV':<10} {'STATUS':<10}")
        print("-" * 88)
        for ag in agents:
            aid = ag.get("agent_identifier") or ag.get("id") or ""
            name = ag.get("name", "")
            env = ag.get("environment", "production")
            status = ag.get("status", "active")
            print(f"{aid:<36} {name:<28} {env:<10} {status:<10}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to list agents: {err}", file=sys.stderr)
        return 1


def cmd_agents_create(args: argparse.Namespace) -> int:
    client = get_client(args)
    name = args.name
    env = args.environment or "sandbox"
    try:
        if env == "sandbox":
            res = client._request("POST", "/developer/agents/test", {"name": name})
        else:
            res = client._request("POST", "/api/v1/agents", {"name": name})
        print("Agent created successfully:")
        print(f"  ID:          {res.get('agent_identifier') or res.get('id')}")
        print(f"  Name:        {res.get('name')}")
        print(f"  Environment: {res.get('environment', env)}")
        print(f"  Status:      {res.get('status', 'active')}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to create agent: {err}", file=sys.stderr)
        return 1


def cmd_permissions_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client._request("GET", "/api/v1/permissions")
        perms = res if isinstance(res, list) else res.get("items", [])
        if args.agent_id:
            perms = [p for p in perms if p.get("agent_id") == args.agent_id or p.get("agent_identifier") == args.agent_id]
        if not perms:
            print("No permissions found.")
            return 0
        print(f"{'ID':<36} {'ACTION':<12} {'RESOURCE':<16} {'MAX AMOUNT':<14} {'STATUS':<10}")
        print("-" * 92)
        for p in perms:
            pid = str(p.get("id", ""))
            action = str(p.get("action", ""))
            res_name = str(p.get("resource", ""))
            amt = f"{p.get('maximum_amount')} {p.get('currency')}" if p.get("maximum_amount") else "N/A"
            status = str(p.get("status", "active"))
            print(f"{pid:<36} {action:<12} {res_name:<16} {amt:<14} {status:<10}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to list permissions: {err}", file=sys.stderr)
        return 1


def cmd_authorize(args: argparse.Namespace) -> int:
    client = get_client(args)
    signer = None
    if args.private_key_path:
        if not args.key_id:
            print("Error: --key-id is required when --private-key-path is specified.", file=sys.stderr)
            return 1
        try:
            signer = AgentSigner(args.agent_id, args.key_id, args.private_key_path)
        except Exception as exc:
            print(f"Error loading signing key: {exc}", file=sys.stderr)
            return 1

    try:
        result = client._authorize(
            agent_id=args.agent_id,
            action=args.action,
            resource=args.resource,
            amount=args.amount,
            currency=args.currency,
            delegation_id=getattr(args, "delegation_id", None),
            idempotency_key=args.idempotency_key,
            signer=signer,
        )
        print("Authorization Result:")
        print(f"  Decision:   {result.status}")
        print(f"  Request ID: {result.request_id}")
        print(f"  Reason:     {result.reason}")
        return 0 if result.status == "APPROVED" else 2
    except AgentTrustError as err:
        print(f"Authorization request failed: {err}", file=sys.stderr)
        return 1


def cmd_requests_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        result = client.get_request(args.request_id)
        print("Authorization Request:")
        print(f"  Request ID: {result.request_id}")
        print(f"  Status:     {result.status}")
        print(f"  Reason:     {result.reason}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to fetch request: {err}", file=sys.stderr)
        return 1


def cmd_trust_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        results = client.list_trust(status=getattr(args, "status", None), direction=getattr(args, "direction", None))
        print(f"Trust Relationships ({len(results)} found):")
        for t in results:
            print(f"  ID: {t.get('id')} | Status: {t.get('status')} | Source: {t.get('source_organization_id')} -> Target: {t.get('target_organization_id')}")
        return 0
    except Exception as err:
        print(f"Failed to list trust relationships: {err}", file=sys.stderr)
        return 1


def cmd_trust_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        t = client.get_trust(args.trust_id)
        print("Trust Relationship Details:")
        for k, v in t.items():
            print(f"  {k}: {v}")
        return 0
    except Exception as err:
        print(f"Failed to fetch trust relationship: {err}", file=sys.stderr)
        return 1


def cmd_trust_request(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        policy: dict[str, Any] = {}
        if getattr(args, "max_amount", None):
            policy["max_amount_per_request"] = args.max_amount
            policy["currency"] = getattr(args, "currency", "USD") or "USD"
        if getattr(args, "approval_stage", None):
            policy["approval_stage"] = args.approval_stage
        res = client.request_trust(target_org_id=args.target_org_id, proposed_policy=policy, notes=getattr(args, "notes", None))
        print(f"Trust requested successfully. Trust ID: {res.get('id', 'N/A')} (Status: {res.get('status', 'PENDING')})")
        return 0
    except Exception as err:
        print(f"Failed to request trust: {err}", file=sys.stderr)
        return 1


def cmd_trust_accept(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.accept_trust(args.trust_id)
        print(f"Trust relationship {args.trust_id} accepted. Status: {res.get('status', 'ACTIVE')}")
        return 0
    except Exception as err:
        print(f"Failed to accept trust: {err}", file=sys.stderr)
        return 1


def cmd_trust_reject(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.reject_trust(args.trust_id, reason=getattr(args, "reason", "Rejected via CLI") or "Rejected via CLI")
        print(f"Trust relationship {args.trust_id} rejected. Status: {res.get('status', 'REJECTED')}")
        return 0
    except Exception as err:
        print(f"Failed to reject trust: {err}", file=sys.stderr)
        return 1


def cmd_trust_revoke(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.revoke_trust(args.trust_id, reason=getattr(args, "reason", "Revoked via CLI") or "Revoked via CLI")
        print(f"Trust relationship {args.trust_id} revoked. Status: {res.get('status', 'REVOKED')}")
        return 0
    except Exception as err:
        print(f"Failed to revoke trust: {err}", file=sys.stderr)
        return 1


def cmd_trust_directory(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        results = client.search_profiles(query=getattr(args, "query", None), tag=getattr(args, "tag", None))
        print(f"Partner Directory ({len(results)} organizations):")
        for p in results:
            print(f"  Org ID: {p.get('organization_id')} | Name: {p.get('display_name')} | Verified: {p.get('is_verified')}")
        return 0
    except Exception as err:
        print(f"Failed to query partner directory: {err}", file=sys.stderr)
        return 1


def cmd_external_authorize(args: argparse.Namespace) -> int:
    client = get_client(args)
    signer = None
    if getattr(args, "private_key_path", None) and getattr(args, "key_id", None):
        signer = AgentSigner(args.source_agent_id, args.key_id, args.private_key_path)

    try:
        result = client.authorize_cross_org(
            source_agent_id=args.source_agent_id,
            target_org_id=args.target_org_id,
            target_agent_id=args.target_agent_id,
            action=args.action,
            resource=args.resource,
            amount=getattr(args, "amount", None),
            currency=getattr(args, "currency", None),
            idempotency_key=getattr(args, "idempotency_key", None),
            signer=signer,
            source_org_id=getattr(args, "source_org_id", None),
        )
        print("Cross-Organization Authorization Result:")
        print(f"  Request ID:        {result.request_id}")
        print(f"  Status:            {result.status}")
        print(f"  Reason:            {result.reason}")
        if result.pending_approvals:
            print(f"  Pending Approvals: {', '.join(result.pending_approvals)}")
        return 0 if result.status == "APPROVED" else 2
    except Exception as err:
        print(f"Cross-organization authorization failed: {err}", file=sys.stderr)
        return 1


def cmd_webhooks_test(args: argparse.Namespace) -> int:
    client = get_client(args)
    payload: dict[str, Any] = {}
    if args.url:
        payload["target_url"] = args.url
    if args.endpoint_id:
        payload["endpoint_id"] = args.endpoint_id

    try:
        res = client._request("POST", "/developer/webhooks/test", payload)
        print("Webhook test event dispatched:")
        print(f"  Delivery ID:    {res.get('delivery_id', 'N/A')}")
        print(f"  Status:         {res.get('status', 'N/A')}")
        print(f"  Target URL:     {res.get('target_url', 'N/A')}")
        print(f"  Response Code:  {res.get('response_status', 'N/A')}")
        return 0
    except AgentTrustError as err:
        print(f"Webhook test failed: {err}", file=sys.stderr)
        return 1


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = getattr(args, "base_url", None) or config.get("base_url") or "http://localhost:8000"
    api_key = getattr(args, "api_key", None) or config.get("api_key")

    print(f"AgentTrust Diagnostics (Doctor) - {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    api_reachable = False
    server_date_str = None
    try:
        req = Request(f"{base_url.rstrip('/')}/developer/openapi.json", headers={"Accept": "application/json"})
        with urlopen(req, timeout=5.0) as resp:
            if resp.status in (200, 401, 403, 404):
                api_reachable = True
                server_date_str = resp.headers.get("Date")
    except Exception:
        try:
            req = Request(f"{base_url.rstrip('/')}/api/v1/health", headers={"Accept": "application/json"})
            with urlopen(req, timeout=5.0) as resp:
                api_reachable = True
                server_date_str = resp.headers.get("Date")
        except Exception:
            api_reachable = False

    if api_reachable:
        print(f"  [OK] API Reachable:           {base_url}")
    else:
        print(f"  [FAIL] API Reachable:         Failed to connect to {base_url}")

    if server_date_str:
        try:
            from email.utils import parsedate_to_datetime
            server_dt = parsedate_to_datetime(server_date_str)
            local_dt = datetime.now(timezone.utc)
            drift = abs((local_dt - server_dt).total_seconds())
            if drift <= 5.0:
                print(f"  [OK] System Clock:            In sync (drift: {drift:.2f}s, window <= 5s)")
            else:
                print(f"  [FAIL] System Clock:          DRIFT DETECTED: {drift:.2f}s drift exceeds 5s window")
        except Exception:
            print("  [WARN] System Clock:          Unable to parse server Date header")
    else:
        print("  [WARN] System Clock:          No server Date header returned")

    try:
        test_priv = Ed25519PrivateKey.generate()
        test_pub = test_priv.public_key()
        msg = b"agenttrust-crypto-selftest"
        sig = test_priv.sign(msg)
        test_pub.verify(sig, msg)
        print("  [OK] Cryptographic Engine:    Ed25519 local signing operational")
    except Exception as exc:
        print(f"  [FAIL] Cryptographic Engine:  Ed25519 self-test failed: {exc}")

    if not api_key:
        print("  [FAIL] API Key:               Not configured. Run 'agenttrust configure'")
    else:
        env_type = "sandbox" if api_key.startswith("at_test_") else ("production" if api_key.startswith("at_live_") else "unknown")
        if env_type == "unknown":
            print("  [FAIL] API Key Format:        Invalid key prefix (must start with at_test_ or at_live_)")
        else:
            print(f"  [OK] API Key Format:          Valid ({env_type} key: {api_key[:12]}...{api_key[-4:]})")
            try:
                client = AgentTrust(api_key=api_key, base_url=base_url)
                overview = client._request("GET", "/developer/overview")
                print(f"  [OK] Authentication:          Authenticated successfully (Org: {overview.get('organization_name', 'Default')})")
            except Exception as auth_exc:
                print(f"  [FAIL] Authentication:        Failed ({auth_exc})")

    print("=" * 60)
    print("Diagnostics complete.")
    return 0


def cmd_delegations_create(args: argparse.Namespace) -> int:
    client = get_client(args)
    payload: dict[str, Any] = {
        "parent_agent_id": args.parent_agent_id,
        "child_agent_id": args.child_agent_id,
        "parent_permission_id": args.parent_permission_id,
        "action": args.action,
        "resource": args.resource,
        "requires_approval": args.requires_approval,
        "allow_delegation": not args.disallow_further_delegation,
    }
    if args.maximum_amount is not None:
        payload["maximum_amount"] = args.maximum_amount
        payload["currency"] = args.currency or "USD"
    if args.expires_at:
        payload["expires_at"] = args.expires_at

    try:
        res = client.create_delegation(payload)
        print("Agent Delegation Created Successfully:")
        print(f"  Delegation ID: {res.get('delegation_id')}")
        print(f"  Parent Agent:  {res.get('parent_agent_id')}")
        print(f"  Child Agent:   {res.get('child_agent_id')}")
        print(f"  Action:        {res.get('action')}")
        print(f"  Resource:      {res.get('resource')}")
        print(f"  Status:        {res.get('status')}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to create delegation: {err}", file=sys.stderr)
        return 1


def cmd_delegations_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        delegations = client.list_delegations(
            parent_agent_id=args.parent_agent_id,
            child_agent_id=args.child_agent_id,
        )
        print(f"Delegations ({len(delegations)}):")
        for d in delegations:
            print(f"  - [{d.get('delegation_id')}] Parent: {d.get('parent_agent_id')} -> Child: {d.get('child_agent_id')}")
            print(f"    Action: {d.get('action')} | Resource: {d.get('resource')} | Status: {d.get('status')}")
            if d.get("maximum_amount") is not None:
                print(f"    Max Amount: {d.get('maximum_amount')} {d.get('currency')}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to list delegations: {err}", file=sys.stderr)
        return 1


def cmd_delegations_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        if args.chain:
            res = client.get_delegation_chain(args.delegation_id)
            print(f"Delegation Chain for [{args.delegation_id}]:")
            print(f"  Valid:            {res.get('is_valid')}")
            print(f"  Effective Action: {res.get('effective_action')}")
            print(f"  Effective Res:    {res.get('effective_resource')}")
            print(f"  Effective Max:    {res.get('effective_maximum_amount')} {res.get('effective_currency')}")
            print("  Chain Nodes:")
            for node in res.get("chain", []):
                print(f"    Depth {node.get('depth')}: Agent {node.get('agent_name')} ({node.get('agent_id')}) -> Action: {node.get('action')} [Status: {node.get('status')}]")
        else:
            res = client.get_delegation(args.delegation_id)
            print(f"Delegation [{res.get('delegation_id')}]:")
            print(f"  Parent Agent: {res.get('parent_agent_id')}")
            print(f"  Child Agent:  {res.get('child_agent_id')}")
            print(f"  Action:       {res.get('action')}")
            print(f"  Resource:     {res.get('resource')}")
            print(f"  Status:       {res.get('status')}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to get delegation: {err}", file=sys.stderr)
        return 1


def cmd_delegations_revoke(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.revoke_delegation(args.delegation_id, reason=args.reason or "Revoked via CLI")
        print(f"Delegation [{res.get('delegation_id')}] revoked successfully.")
        print(f"  Status: {res.get('status')}")
        print(f"  Reason: {res.get('revocation_reason')}")
        return 0
    except AgentTrustError as err:
        print(f"Failed to revoke delegation: {err}", file=sys.stderr)
        return 1


def cmd_atp_send(args: argparse.Namespace) -> int:
    config = load_config()
    source_org_id = args.source_org_id or config.get("organization_id")
    if not source_org_id:
        print("Error: --source-org-id is required.", file=sys.stderr)
        return 1

    payload_data = {}
    if args.payload:
        if Path(args.payload).is_file():
            payload_data = json.loads(Path(args.payload).read_text(encoding="utf-8"))
        else:
            try:
                payload_data = json.loads(args.payload)
            except Exception:
                payload_data = {"text": args.payload}

    client = get_client(args)
    signed_agent = client.agent(
        agent_id=args.source_agent_id,
        key_id=args.key_id,
        private_key_path=args.private_key_path,
    )
    try:
        resp = signed_agent.send_atp_message(
            source_org_id=source_org_id,
            target_address=args.target_address,
            capability=args.capability,
            payload=payload_data,
        )
        print("ATP Message Dispatch Result:")
        print(json.dumps(resp, indent=2))
        return 0
    except Exception as exc:
        print(f"Failed to dispatch ATP message: {exc}", file=sys.stderr)
        return 1


def cmd_atp_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.get_atp_message(args.message_id)
        print(f"ATP Message [{args.message_id}]:")
        print(json.dumps(res, indent=2))
        return 0
    except Exception as exc:
        print(f"Failed to retrieve ATP message: {exc}", file=sys.stderr)
        return 1


def cmd_gateway_health(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = getattr(args, "base_url", None) or config.get("base_url") or "http://localhost:8000"
    try:
        req = Request(f"{base_url.rstrip('/')}/api/v1/atp/health", headers={"Accept": "application/json"})
        with urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read())
            print("AgentTrust Gateway Health:")
            print(json.dumps(data, indent=2))
            return 0
    except Exception as exc:
        print(f"Failed to query gateway health: {exc}", file=sys.stderr)
        return 1


def cmd_gateway_identity(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.get_gateway_identity()
        print("AgentTrust Gateway Identity:")
        print(json.dumps(res, indent=2))
        return 0
    except Exception as exc:
        print(f"Failed to retrieve gateway identity: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api-key", help="AgentTrust API key (at_test_... or at_live_...)")
    common.add_argument("--base-url", help="AgentTrust API Base URL")

    parser = argparse.ArgumentParser(
        prog="agenttrust",
        description="AgentTrust Developer CLI - manage agents, Ed25519 keys, permissions, and authorizations.",
        parents=[common],
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # configure
    p_config = subparsers.add_parser("configure", help="Configure default CLI credentials and base URL", parents=[common])
    p_config.add_argument("--org-id", help="Organization ID")
    p_config.set_defaults(func=cmd_configure)

    # keys
    p_keys = subparsers.add_parser("keys", help="Manage cryptographic Ed25519 signing keys", parents=[common])
    sub_keys = p_keys.add_subparsers(dest="subcommand", required=True)

    p_kg = sub_keys.add_parser("generate", help="Generate local Ed25519 keypair for agent signing", parents=[common])
    p_kg.add_argument("--output-dir", default="./keys", help="Directory to save PEM files (default: ./keys)")
    p_kg.add_argument("--name", default="agent_key", help="Key name prefix")
    p_kg.set_defaults(func=cmd_keys_generate)

    p_kr = sub_keys.add_parser("register", help="Register public signing key with AgentTrust", parents=[common])
    p_kr.add_argument("--agent-id", required=True, help="Agent identifier")
    p_kr.add_argument("--public-key-path", required=True, help="Path to public key PEM file")
    p_kr.add_argument("--key-id", help="Explicit key ID (e.g. key_ag_...)")
    p_kr.set_defaults(func=cmd_keys_register)

    # agents
    p_agents = subparsers.add_parser("agents", help="List and create agents", parents=[common])
    sub_agents = p_agents.add_subparsers(dest="subcommand", required=True)

    p_al = sub_agents.add_parser("list", help="List agents", parents=[common])
    p_al.set_defaults(func=cmd_agents_list)

    p_ac = sub_agents.add_parser("create", help="Create a new agent", parents=[common])
    p_ac.add_argument("--name", required=True, help="Agent name")
    p_ac.add_argument("--environment", choices=["sandbox", "production"], default="sandbox", help="Environment (sandbox or production)")
    p_ac.set_defaults(func=cmd_agents_create)

    # permissions
    p_perms = subparsers.add_parser("permissions", help="List permissions", parents=[common])
    sub_perms = p_perms.add_subparsers(dest="subcommand", required=True)
    p_pl = sub_perms.add_parser("list", help="List permissions", parents=[common])
    p_pl.add_argument("--agent-id", help="Filter permissions by agent ID")
    p_pl.set_defaults(func=cmd_permissions_list)

    # authorize
    p_auth = subparsers.add_parser("authorize", help="Request action authorization", parents=[common])
    p_auth.add_argument("--agent-id", required=True, help="Agent identifier")
    p_auth.add_argument("--action", required=True, help="Action to authorize (e.g. purchase)")
    p_auth.add_argument("--resource", required=True, help="Target resource (e.g. flight)")
    p_auth.add_argument("--amount", type=float, help="Transaction amount")
    p_auth.add_argument("--currency", help="Currency code (e.g. USD)")
    p_auth.add_argument("--key-id", help="Signing key ID")
    p_auth.add_argument("--private-key-path", help="Path to Ed25519 private key PEM file for local signing")
    p_auth.add_argument("--delegation-id", help="Delegation ID for delegated action authorization")
    p_auth.add_argument("--idempotency-key", help="Unique idempotency key")
    p_auth.set_defaults(func=cmd_authorize)

    # delegations
    p_delg = subparsers.add_parser("delegations", help="Manage agent-to-agent delegations", parents=[common])
    sub_delg = p_delg.add_subparsers(dest="subcommand", required=True)

    p_dc = sub_delg.add_parser("create", help="Create an agent-to-agent delegation", parents=[common])
    p_dc.add_argument("--parent-agent-id", required=True, help="Parent agent ID")
    p_dc.add_argument("--child-agent-id", required=True, help="Child agent ID")
    p_dc.add_argument("--parent-permission-id", required=True, help="Parent permission ID (root permission)")
    p_dc.add_argument("--action", required=True, help="Action delegated")
    p_dc.add_argument("--resource", required=True, help="Resource delegated")
    p_dc.add_argument("--maximum-amount", type=float, help="Maximum amount delegated")
    p_dc.add_argument("--currency", help="Currency code")
    p_dc.add_argument("--requires-approval", action="store_true", help="Require human approval")
    p_dc.add_argument("--disallow-further-delegation", action="store_true", help="Disallow further delegation by child")
    p_dc.add_argument("--expires-at", help="Delegation expiration ISO timestamp")
    p_dc.set_defaults(func=cmd_delegations_create)

    p_dl = sub_delg.add_parser("list", help="List agent delegations", parents=[common])
    p_dl.add_argument("--parent-agent-id", help="Filter by parent agent ID")
    p_dl.add_argument("--child-agent-id", help="Filter by child agent ID")
    p_dl.set_defaults(func=cmd_delegations_list)

    p_dg = sub_delg.add_parser("get", help="Get agent delegation or delegation chain", parents=[common])
    p_dg.add_argument("delegation_id", help="Delegation ID (delg_...)")
    p_dg.add_argument("--chain", action="store_true", help="Fetch and visualize full transitive delegation chain")
    p_dg.set_defaults(func=cmd_delegations_get)

    p_dr = sub_delg.add_parser("revoke", help="Revoke an agent delegation with cascade", parents=[common])
    p_dr.add_argument("delegation_id", help="Delegation ID to revoke")
    p_dr.add_argument("--reason", help="Revocation reason")
    p_dr.set_defaults(func=cmd_delegations_revoke)

    # requests
    p_reqs = subparsers.add_parser("requests", help="Inspect authorization requests", parents=[common])
    sub_reqs = p_reqs.add_subparsers(dest="subcommand", required=True)
    p_rg = sub_reqs.add_parser("get", help="Get status of authorization request", parents=[common])
    p_rg.add_argument("request_id", help="Request ID (req_...)")
    p_rg.set_defaults(func=cmd_requests_get)

    # webhooks
    p_wh = subparsers.add_parser("webhooks", help="Test webhooks", parents=[common])
    sub_wh = p_wh.add_subparsers(dest="subcommand", required=True)
    p_wt = sub_wh.add_parser("test", help="Send a test webhook event", parents=[common])
    p_wt.add_argument("--url", help="Direct webhook destination URL")
    p_wt.add_argument("--endpoint-id", help="Existing webhook endpoint ID")
    p_wt.set_defaults(func=cmd_webhooks_test)

    # trust (Step 20 cross-organization trust)
    p_trust = subparsers.add_parser("trust", help="Manage cross-organization trust relationships", parents=[common])
    sub_trust = p_trust.add_subparsers(dest="subcommand", required=True)

    p_tl = sub_trust.add_parser("list", help="List organization trust relationships", parents=[common])
    p_tl.add_argument("--status", choices=["pending", "active", "rejected", "revoked", "expired"], help="Filter by status")
    p_tl.add_argument("--direction", choices=["incoming", "outgoing"], help="Filter by direction")
    p_tl.set_defaults(func=cmd_trust_list)

    p_tg = sub_trust.add_parser("get", help="Get trust relationship details", parents=[common])
    p_tg.add_argument("trust_id", help="Trust relationship ID (trust_...)")
    p_tg.set_defaults(func=cmd_trust_get)

    p_trq = sub_trust.add_parser("request", help="Request cross-organization trust", parents=[common])
    p_trq.add_argument("--target-org-id", required=True, help="Target Organization UUID")
    p_trq.add_argument("--max-amount", type=float, help="Proposed max amount per request")
    p_trq.add_argument("--currency", default="USD", help="Currency code")
    p_trq.add_argument("--approval-stage", choices=["SOURCE", "TARGET", "BOTH"], default="BOTH", help="Approval stage required")
    p_trq.add_argument("--notes", help="Invitation notes")
    p_trq.set_defaults(func=cmd_trust_request)

    p_tac = sub_trust.add_parser("accept", help="Accept incoming trust request", parents=[common])
    p_tac.add_argument("trust_id", help="Trust relationship ID")
    p_tac.set_defaults(func=cmd_trust_accept)

    p_trj = sub_trust.add_parser("reject", help="Reject incoming trust request", parents=[common])
    p_trj.add_argument("trust_id", help="Trust relationship ID")
    p_trj.add_argument("--reason", help="Rejection reason")
    p_trj.set_defaults(func=cmd_trust_reject)

    p_trv = sub_trust.add_parser("revoke", help="Revoke active trust relationship", parents=[common])
    p_trv.add_argument("trust_id", help="Trust relationship ID")
    p_trv.add_argument("--reason", help="Revocation reason")
    p_trv.set_defaults(func=cmd_trust_revoke)

    p_td = sub_trust.add_parser("directory", help="Search partner organization directory", parents=[common])
    p_td.add_argument("--query", help="Search query string")
    p_td.add_argument("--tag", help="Search tag")
    p_td.set_defaults(func=cmd_trust_directory)

    # external (Step 20 cross-organization agent authorization)
    p_ext = subparsers.add_parser("external", help="Authorize external cross-organization actions", parents=[common])
    sub_ext = p_ext.add_subparsers(dest="subcommand", required=True)

    p_ea = sub_ext.add_parser("authorize", help="Request cross-organization action authorization", parents=[common])
    p_ea.add_argument("--source-agent-id", required=True, help="Source Agent UUID")
    p_ea.add_argument("--target-org-id", required=True, help="Target Organization UUID")
    p_ea.add_argument("--target-agent-id", required=True, help="Target Agent UUID")
    p_ea.add_argument("--action", required=True, help="Action name")
    p_ea.add_argument("--resource", required=True, help="Resource name")
    p_ea.add_argument("--amount", type=float, help="Transaction amount")
    p_ea.add_argument("--currency", help="Currency code")
    p_ea.add_argument("--key-id", help="Source agent signing key ID")
    p_ea.add_argument("--private-key-path", help="Path to Ed25519 private key PEM file for v2 local signing")
    p_ea.add_argument("--idempotency-key", help="Unique idempotency key")
    p_ea.add_argument("--source-org-id", help="Source Organization UUID")
    p_ea.set_defaults(func=cmd_external_authorize)

    # atp (Step 21 AgentTrust Protocol)
    p_atp = subparsers.add_parser("atp", help="AgentTrust Protocol (ATP/1.0) messaging and dispatch", parents=[common])
    sub_atp = p_atp.add_subparsers(dest="subcommand", required=True)

    p_atp_send = sub_atp.add_parser("send", help="Send ATP/1.0 signed message through Gateway", parents=[common])
    p_atp_send.add_argument("--source-org-id", required=True, help="Source Organization ID or Slug")
    p_atp_send.add_argument("--source-agent-id", required=True, help="Source Agent ID or Identifier")
    p_atp_send.add_argument("--target-address", required=True, help="Target Agent Address (e.g. atp://org/agt)")
    p_atp_send.add_argument("--capability", required=True, help="Requested capability (e.g. hotel.reserve@1.0)")
    p_atp_send.add_argument("--payload", help="JSON string or file path containing message payload")
    p_atp_send.add_argument("--key-id", required=True, help="Source agent signing key ID")
    p_atp_send.add_argument("--private-key-path", required=True, help="Path to Ed25519 private key PEM file")
    p_atp_send.set_defaults(func=cmd_atp_send)

    p_atp_get = sub_atp.add_parser("get", help="Retrieve ATP message delivery status and audit trace", parents=[common])
    p_atp_get.add_argument("message_id", help="ATP Message ID (e.g. msg_...)")
    p_atp_get.set_defaults(func=cmd_atp_get)

    # gateway (Step 21 AgentTrust Gateway commands)
    p_gw = subparsers.add_parser("gateway", help="AgentTrust Gateway health and identity commands", parents=[common])
    sub_gw = p_gw.add_subparsers(dest="subcommand", required=True)

    p_gw_health = sub_gw.add_parser("health", help="Check Gateway health and protocol readiness", parents=[common])
    p_gw_health.set_defaults(func=cmd_gateway_health)

    p_gw_id = sub_gw.add_parser("identity", help="Retrieve public Gateway Ed25519 identity key", parents=[common])
    p_gw_id.set_defaults(func=cmd_gateway_identity)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run connectivity, clock, and cryptographic diagnostics", parents=[common])
    p_doc.set_defaults(func=cmd_doctor)

    parsed = parser.parse_args(argv)
    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())
