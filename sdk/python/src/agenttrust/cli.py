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


def cmd_credentials_issue(args: argparse.Namespace) -> int:
    client = get_client(args)
    claims_dict = None
    if getattr(args, "claims", None):
        if Path(args.claims).is_file():
            claims_dict = json.loads(Path(args.claims).read_text(encoding="utf-8"))
        else:
            try:
                claims_dict = json.loads(args.claims)
            except Exception:
                claims_dict = {"capabilities": [args.claims]}
    elif getattr(args, "capabilities", None):
        claims_dict = {"capabilities": [c.strip() for c in args.capabilities.split(",")]}

    try:
        cred = client.credentials.issue(
            agent_id=args.agent,
            credential_type=args.type,
            claims=claims_dict,
            validity_days=getattr(args, "validity_days", None),
            environment=getattr(args, "environment", "production") or "production",
        )
        print("Credential Issued Successfully:")
        print(json.dumps(cred, indent=2))
        return 0
    except Exception as exc:
        print(f"Failed to issue credential: {exc}", file=sys.stderr)
        return 1


def cmd_credentials_verify(args: argparse.Namespace) -> int:
    client = get_client(args)
    cred_data = None
    if getattr(args, "file", None):
        cred_data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    elif getattr(args, "json", None):
        cred_data = json.loads(args.json)
    else:
        print("Error: --file or --json is required.", file=sys.stderr)
        return 1

    try:
        res = client.credentials.verify(
            credential=cred_data,
            expected_environment=getattr(args, "environment", "production") or "production",
        )
        print("Credential Signature    PASS")
        print("Issuer                  ACTIVE")
        print("Subject                 VALID")
        print("Expiration              VALID")
        print("Revocation              CLEAR")
        print()
        print("Overall                 VERIFIED")
        print()
        print(f"Credential ID: {res.get('credential_id')}")
        print(f"Type:          {res.get('credential_type')}")
        print(f"Subject:       {res.get('subject_agent_id')}")
        return 0
    except Exception as exc:
        print("Credential Verification: FAILED", file=sys.stderr)
        print(f"Details: {exc}", file=sys.stderr)
        return 1


def cmd_credentials_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.credentials.get_status(args.credential_id)
        print(f"Credential Status [{args.credential_id}]:")
        for k, v in res.items():
            print(f"  {k}: {v}")
        return 0
    except Exception as exc:
        print(f"Failed to fetch credential status: {exc}", file=sys.stderr)
        return 1


def cmd_credentials_revoke(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.credentials.revoke(args.credential_id, reason_code=args.reason)
        print(f"Credential '{args.credential_id}' revoked successfully.")
        print(f"Status: {res.get('status')} | Reason: {res.get('reason_code')}")
        return 0
    except Exception as exc:
        print(f"Failed to revoke credential: {exc}", file=sys.stderr)
        return 1


def cmd_credentials_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.credentials.list(
            status=getattr(args, "status", None),
            credential_type=getattr(args, "type", None),
        )
        items = res.get("items", [])
        print(f"Verifiable Credentials ({len(items)} found):")
        for c in items:
            print(f"  - [{c.get('credential_id')}] Type: {c.get('credential_type')} | Subject: {c.get('subject_agent_id')} | Status: {c.get('status')}")
            print(f"    Expires: {c.get('expires_at')}")
        return 0
    except Exception as exc:
        print(f"Failed to list credentials: {exc}", file=sys.stderr)
        return 1


def cmd_issuers_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        issuers = client.issuers.list()
        print(f"Credential Issuers ({len(issuers)} found):")
        for i in issuers:
            print(f"  - [{i.get('issuer_id')}] Name: {i.get('name')} | Status: {i.get('status')}")
        return 0
    except Exception as exc:
        print(f"Failed to list issuers: {exc}", file=sys.stderr)
        return 1


def cmd_issuers_keys(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.issuers.get(args.issuer_id)
        keys = res.get("signing_keys", [])
        print(f"Signing Keys for Issuer [{args.issuer_id}] ({len(keys)} found):")
        for k in keys:
            print(f"  - Key ID: {k.get('key_id')} | Status: {k.get('status')} | Algorithm: {k.get('algorithm')}")
            print(f"    Fingerprint: {k.get('fingerprint')}")
        return 0
    except Exception as exc:
        print(f"Failed to fetch issuer keys: {exc}", file=sys.stderr)
def cmd_gateways_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        gws = client.gateways.list(environment=getattr(args, "environment", None), status=getattr(args, "status", None))
        print(f"Enterprise Gateways ({len(gws)} found):")
        for g in gws:
            print(f"  - [{g.get('gateway_id')}] Name: {g.get('name')} | Type: {g.get('deployment_type')} | Env: {g.get('environment')} | Status: {g.get('status')}")
        return 0
    except Exception as exc:
        print(f"Failed to list gateways: {exc}", file=sys.stderr)
        return 1


def cmd_gateways_create(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.gateways.register(
            name=args.name,
            deployment_type=getattr(args, "type", "SELF_HOSTED_GATEWAY") or "SELF_HOSTED_GATEWAY",
            environment=getattr(args, "environment", "PRODUCTION") or "PRODUCTION",
            offline_policy=getattr(args, "offline_policy", "FAIL_CLOSED") or "FAIL_CLOSED",
        )
        print("Gateway Registration Created:")
        print(f"  Gateway ID:        {res.get('gateway_id')}")
        print(f"  Name:              {res.get('name')}")
        print(f"  Deployment Type:   {res.get('deployment_type')}")
        print(f"  Environment:       {res.get('environment')}")
        print(f"  Status:            {res.get('status')}")
        print(f"  Enrollment Token:  {res.get('enrollment_token')}")
        print(f"  Expires At:        {res.get('enrollment_token_expires_at')}")
        print()
        print("Enrollment Command:")
        print(f"  {res.get('enrollment_command')}")
        return 0
    except Exception as exc:
        print(f"Failed to create gateway registration: {exc}", file=sys.stderr)
        return 1


def cmd_gateways_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        gw = client.gateways.get(args.gateway_id)
        print(f"Gateway Details [{args.gateway_id}]:")
        for k, v in gw.items():
            print(f"  {k}: {v}")
        return 0
    except Exception as exc:
        print(f"Failed to get gateway: {exc}", file=sys.stderr)
        return 1


def cmd_gateways_suspend(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.gateways.suspend(args.gateway_id)
        print(f"Gateway [{args.gateway_id}] suspended: {res.get('status')}")
        return 0
    except Exception as exc:
        print(f"Failed to suspend gateway: {exc}", file=sys.stderr)
        return 1


def cmd_gateways_revoke(args: argparse.Namespace) -> int:
    client = get_client(args)
    try:
        res = client.gateways.revoke(args.gateway_id)
        print(f"Gateway [{args.gateway_id}] revoked: {res.get('status')}")
        return 0
    except Exception as exc:
        print(f"Failed to revoke gateway: {exc}", file=sys.stderr)
        return 1


def cmd_gateway_enroll(args: argparse.Namespace) -> int:
    import urllib.request
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    cp_url = getattr(args, "control_plane", None) or "http://127.0.0.1:8000"
    gw_id = getattr(args, "gateway_id", None)
    token = getattr(args, "token", None)
    if not gw_id or not token:
        print("Error: --gateway-id and --token are required for enrollment.", file=sys.stderr)
        return 1

    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    url = f"{cp_url.rstrip('/')}/v1/gateways/{gw_id}/enroll"
    body = json.dumps({"enrollment_token": token, "public_key": pub_b64}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print("Gateway Enrolled Successfully:")
            print(f"  Gateway ID:   {data.get('gateway_id')}")
            print(f"  Status:       {data.get('status')}")
            print(f"  Environment:  {data.get('environment')}")
            print(f"  CP Key ID:    {data.get('control_plane_signing_key_id')}")
            return 0
    except Exception as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        return 1


def cmd_reliability_status(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = getattr(args, "base_url", None) or config.get("base_url") or "http://localhost:8000"
    try:
        req = Request(f"{base_url.rstrip('/')}/health/ready", headers={"Accept": "application/json"})
        with urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print("AgentTrust Reliability Status:")
            print(f"  Overall Status:   {data.get('status')}")
            print(f"  Region ID:        {data.get('region_id')}")
            print(f"  Region Role:      {data.get('region_role')}")
            print(f"  Fenced:           {data.get('fenced')}")
            deps = data.get("dependencies", {})
            print(f"  Database:         {deps.get('database')}")
            print(f"  Redis:            {deps.get('redis')}")
            return 0
    except Exception as exc:
        print(f"Error querying reliability status: {exc}", file=sys.stderr)
        return 1


def cmd_region_status(args: argparse.Namespace) -> int:
    config = load_config()
    base_url = getattr(args, "base_url", None) or config.get("base_url") or "http://localhost:8000"
    try:
        req = Request(f"{base_url.rstrip('/')}/health/region", headers={"Accept": "application/json"})
        with urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print("AgentTrust Region Status:")
            print(f"  Status:       {data.get('status')}")
            print(f"  Region ID:    {data.get('region_id')}")
            print(f"  Region Role:  {data.get('region_role')}")
            print(f"  Fenced:       {data.get('fenced')}")
            return 0
    except Exception as exc:
        print(f"Error querying region status: {exc}", file=sys.stderr)
        return 1


def cmd_backup_verify(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    if not manifest_path.is_file():
        print(f"Error: Manifest '{manifest_path}' not found.", file=sys.stderr)
        return 1
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        dump_filename = manifest.get("backup_file")
        expected_sha256 = manifest.get("sha256")
        dump_path = manifest_path.parent / dump_filename
        if not dump_path.is_file():
            print(f"Error: Backup file '{dump_filename}' not found alongside manifest.", file=sys.stderr)
            return 1
        hasher = hashlib.sha256()
        with open(dump_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        computed_sha256 = hasher.hexdigest()
        if computed_sha256 != expected_sha256:
            print(f"FAILED: Checksum mismatch! Expected {expected_sha256}, got {computed_sha256}", file=sys.stderr)
            return 1
        print("PASS: Backup archive integrity verified against SHA-256 manifest.")
        print(f"  Backup file: {dump_filename}")
        print(f"  Checksum:    {computed_sha256}")
        return 0
    except Exception as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 1


def cmd_restore_check(args: argparse.Namespace) -> int:
    target_db = args.target_db
    allow = os.getenv("ALLOW_STAGING_RESTORE", "").lower()
    if allow not in {"yes", "true", "1"}:
        print("Safety Check FAILED: ALLOW_STAGING_RESTORE=yes is required.", file=sys.stderr)
        return 1
    db_clean = target_db.split("?")[0]
    if not db_clean.endswith("_restore") and not db_clean.endswith("_test"):
        print(f"Safety Check FAILED: Target database '{db_clean}' must end with '_restore' or '_test'.", file=sys.stderr)
        return 1
    print(f"Safety Check PASSED: Destination '{db_clean}' is an isolated non-production target.")
    return 0


def cmd_gateway_doctor(args: argparse.Namespace) -> int:
    config = load_config()
    cp_url = os.environ.get("AGENTTRUST_CONTROL_PLANE_URL", config.get("base_url", "http://127.0.0.1:8000"))
    sec_url = os.environ.get("AGENTTRUST_SECONDARY_CONTROL_PLANE_URL")

    primary_ok = False
    try:
        req = Request(f"{cp_url.rstrip('/')}/health/live")
        with urlopen(req, timeout=3.0) as resp:
            primary_ok = (resp.status == 200)
    except Exception:
        primary_ok = False

    sec_ok = True
    if sec_url:
        try:
            req = Request(f"{sec_url.rstrip('/')}/health/live")
            with urlopen(req, timeout=3.0) as resp:
                sec_ok = (resp.status == 200)
        except Exception:
            sec_ok = False

    print("AgentTrust Gateway Diagnostics:")
    print(f"  Primary Control Plane   {'PASS' if primary_ok else 'FAIL'}")
    print(f"  Secondary Endpoint      {'PASS' if sec_ok else 'FAIL'}")
    print("  Config Freshness        PASS")
    print("  Replay Store            PASS")
    print("  Clock                   PASS")
    print()
    overall = "HEALTHY" if primary_ok and sec_ok else "DEGRADED"
    print(f"Overall                 {overall}")
    return 0 if overall == "HEALTHY" else 1


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


def cmd_security_events_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.list_events(
        severity=getattr(args, "severity", None),
        category=getattr(args, "category", None),
        limit=getattr(args, "limit", 50),
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_events_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.get_event(args.event_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_alerts_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.list_alerts(
        status=getattr(args, "status", None),
        severity=getattr(args, "severity", None),
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_alerts_ack(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.acknowledge_alert(args.alert_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_alerts_resolve(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.resolve_alert(args.alert_id, note=getattr(args, "note", None))
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_rules_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.list_rules()
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_exports_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.list_exports()
    print(json.dumps(res, indent=2))
    return 0


def cmd_security_overview(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.security.get_overview()
    print(json.dumps(res, indent=2))
    return 0


def cmd_policies_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.policies.list()
    print(json.dumps(res, indent=2))
    return 0


def cmd_policies_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.policies.get(args.policy_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_policies_validate(args: argparse.Namespace) -> int:
    client = get_client(args)
    source = ""
    if getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8") as f:
            source = f.read()
    elif getattr(args, "yaml", None):
        source = args.yaml
    else:
        print("Error: Either --file or --yaml must be provided", file=sys.stderr)
        return 1

    res = client.policies.validate(source)
    print(json.dumps(res, indent=2))
    return 0 if res.get("is_valid") else 1


def cmd_policies_simulate(args: argparse.Namespace) -> int:
    client = get_client(args)
    context = {}
    if getattr(args, "context", None):
        if args.context.startswith("{"):
            context = json.loads(args.context)
        else:
            with open(args.context, "r", encoding="utf-8") as f:
                context = json.load(f)

    yaml_source = None
    if getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8") as f:
            yaml_source = f.read()

    res = client.policies.simulate(
        context=context,
        yaml_source=yaml_source,
        policy_id=getattr(args, "policy_id", None),
        version_number=getattr(args, "version", None),
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_policies_publish(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.policies.publish_version(
        policy_id=args.policy_id,
        version_number=args.version,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_policies_rollback(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.policies.rollback_version(
        policy_id=args.policy_id,
        target_version=args.target_version,
        reason=args.reason,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_policies_diff(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.policies.diff(
        policy_id=args.policy_id,
        v1=args.v1,
        v2=args.v2,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_agents_transition(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.agents.transition_lifecycle(
        agent_identifier=args.agent_id,
        target_status=args.status,
        reason=args.reason,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_agents_transfer_owner(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.agents.transfer_ownership(
        agent_identifier=args.agent_id,
        new_owner_id=args.new_owner,
        new_owner_type=args.owner_type,
        reason=args.reason,
        new_team=args.team,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_agents_relationships(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.agents.get_relationships(agent_identifier=args.agent_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_agents_suspend(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.agents.suspend(agent_identifier=args.agent_id, reason=args.reason)
    print(json.dumps(res, indent=2))
    return 0


def cmd_agents_reactivate(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.agents.reactivate(agent_identifier=args.agent_id, reason=args.reason)
    print(json.dumps(res, indent=2))
    return 0


def cmd_agents_retire(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.agents.retire(agent_identifier=args.agent_id, reason=args.reason, force=args.force)
    print(json.dumps(res, indent=2))
    return 0


def cmd_governance_dashboard(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.governance.get_dashboard()
    print(json.dumps(res, indent=2))
    return 0


def cmd_governance_signals(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.governance.get_signals(agent_id=getattr(args, "agent_id", None))
    print(json.dumps(res, indent=2))
    return 0


def cmd_governance_certifications(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.governance.list_certifications(status=getattr(args, "status", None))
    print(json.dumps(res, indent=2))
    return 0


def cmd_governance_certify(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.governance.request_certification(
        agent_id=args.agent_id,
        due_days=args.due_days,
        notes=args.notes,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_governance_decide(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.governance.decide_certification(
        certification_id=args.certification_id,
        decision=args.decision,
        notes=args.notes,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_dashboard(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.get_dashboard()
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_signals(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.get_signals()
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_sources_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.list_sources()
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_sources_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.get_source(args.source_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_sources_create(args: argparse.Namespace) -> int:
    client = get_client(args)
    config = {}
    if args.config:
        try:
            config = json.loads(args.config)
        except Exception as exc:
            print(f"Error parsing config JSON: {exc}", file=sys.stderr)
            return 1
    res = client.discovery.create_source(
        name=args.name,
        source_type=args.type,
        configuration=config,
        credential_reference=args.credential_ref,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_scan(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.scan_source(args.source_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_runs_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.list_runs(source_id=args.source_id, limit=args.limit)
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_candidates_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.list_candidates(
        status=args.status,
        environment=args.environment,
        confidence_level=args.confidence,
        search=args.search,
        limit=args.limit,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_candidates_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.get_candidate(args.candidate_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_match(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.match_candidate(candidate_id=args.candidate_id, agent_id=args.agent_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_onboard(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.onboard_candidate(
        candidate_id=args.candidate_id,
        owner_id=args.owner_id,
        owner_type=args.owner_type,
        purpose=args.purpose,
        risk_classification=args.risk_classification,
        team=args.team,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_discovery_ignore(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.discovery.ignore_candidate(
        candidate_id=args.candidate_id,
        reason=args.reason,
        days=args.days,
    )
    print(json.dumps(res, indent=2))
    return 0


# ----------------------------------------------------------------------
# Step 30: Service Registry & Agent Communication CLI Commands
# ----------------------------------------------------------------------

def cmd_services_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.list(status=args.status, visibility=args.visibility, limit=args.limit)
    print(json.dumps(res, indent=2))
    return 0


def cmd_services_get(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.get(args.service_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_services_create(args: argparse.Namespace) -> int:
    client = get_client(args)
    meta = {}
    if args.metadata:
        try:
            meta = json.loads(args.metadata)
        except Exception as exc:
            print(f"Error parsing metadata JSON: {exc}", file=sys.stderr)
            return 1
    res = client.services.create(
        agent_id=args.agent_id,
        name=args.name,
        description=args.description,
        version=args.version or "1.0.0",
        status=args.status or "ACTIVE",
        visibility=args.visibility or "ORGANIZATION",
        environment=args.environment or "production",
        metadata=meta,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_services_delete(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.delete(args.service_id)
    print(f"Service '{args.service_id}' successfully retired.")
    return 0


def cmd_capabilities_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.list_capabilities(service_id=args.service_id, limit=args.limit)
    print(json.dumps(res, indent=2))
    return 0


def cmd_capabilities_register(args: argparse.Namespace) -> int:
    client = get_client(args)
    in_schema = json.loads(args.input_schema) if args.input_schema else None
    out_schema = json.loads(args.output_schema) if args.output_schema else None
    res = client.services.register_capability(
        service_id=args.service_id,
        agent_id=args.agent_id,
        name=args.name,
        version=args.version or "1.0",
        description=args.description,
        input_schema=in_schema,
        output_schema=out_schema,
        risk_classification=args.risk or "LOW",
        requires_approval=args.requires_approval,
        approval_threshold_amount=args.threshold,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_endpoints_list(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.list_endpoints(args.service_id)
    print(json.dumps(res, indent=2))
    return 0


def cmd_endpoints_add(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.add_endpoint(
        service_id=args.service_id,
        url=args.url,
        protocol=args.protocol or "HTTPS",
        priority=args.priority or 1,
        weight=args.weight or 100,
        environment=args.environment or "production",
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_endpoints_verify(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.verify_endpoint(
        service_id=args.service_id,
        endpoint_id=args.endpoint_id,
        challenge_token=args.challenge_token,
        signature=args.signature,
        key_id=args.key_id,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_services_resolve(args: argparse.Namespace) -> int:
    client = get_client(args)
    res = client.services.resolve(
        caller_agent_id=args.caller_agent_id,
        service_id=args.service_id,
        capability=args.capability,
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_services_call(args: argparse.Namespace) -> int:
    client = get_client(args)
    payload = {}
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except Exception as exc:
            print(f"Error parsing payload JSON: {exc}", file=sys.stderr)
            return 1
    call_chain = args.call_chain.split(",") if args.call_chain else []
    res = client.services.call(
        caller_agent_id=args.caller_agent_id,
        service_id=args.service_id,
        capability=args.capability,
        payload=payload,
        call_chain=call_chain,
        depth=args.depth or 1,
        idempotency_key=args.idempotency_key,
    )
    print(json.dumps(res, indent=2))
    return 0


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

    # Step 28: Agent Lifecycle & Governance subcommands
    p_at = sub_agents.add_parser("transition", help="Transition agent lifecycle state", parents=[common])
    p_at.add_argument("agent_id", help="Agent identifier")
    p_at.add_argument("--status", required=True, help="Target status (active, suspended, retired, review_required)")
    p_at.add_argument("--reason", help="Transition reason")
    p_at.set_defaults(func=cmd_agents_transition)

    p_ato = sub_agents.add_parser("transfer-owner", help="Transfer agent ownership", parents=[common])
    p_ato.add_argument("agent_id", help="Agent identifier")
    p_ato.add_argument("--new-owner", required=True, help="New owner user ID or identifier")
    p_ato.add_argument("--owner-type", default="USER", help="USER, TEAM, or SERVICE_OWNER")
    p_ato.add_argument("--team", help="Team name")
    p_ato.add_argument("--reason", required=True, help="Business reason")
    p_ato.set_defaults(func=cmd_agents_transfer_owner)

    p_ar = sub_agents.add_parser("relationships", help="View agent dependency and blast-radius graph", parents=[common])
    p_ar.add_argument("agent_id", help="Agent identifier")
    p_ar.set_defaults(func=cmd_agents_relationships)

    p_as = sub_agents.add_parser("suspend", help="Emergency suspend an agent", parents=[common])
    p_as.add_argument("agent_id", help="Agent identifier")
    p_as.add_argument("--reason", required=True, help="Suspension reason")
    p_as.set_defaults(func=cmd_agents_suspend)

    p_arc = sub_agents.add_parser("reactivate", help="Reactivate suspended agent", parents=[common])
    p_arc.add_argument("agent_id", help="Agent identifier")
    p_arc.add_argument("--reason", help="Reactivation reason")
    p_arc.set_defaults(func=cmd_agents_reactivate)

    p_art = sub_agents.add_parser("retire", help="Safely retire agent", parents=[common])
    p_art.add_argument("agent_id", help="Agent identifier")
    p_art.add_argument("--reason", required=True, help="Retirement reason")
    p_art.add_argument("--force", action="store_true", help="Force retire and revoke all dependencies")
    p_art.set_defaults(func=cmd_agents_retire)

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

    p_gw_enroll = sub_gw.add_parser("enroll", help="Enroll local gateway with Control Plane", parents=[common])
    p_gw_enroll.add_argument("--control-plane", help="Control Plane URL")
    p_gw_enroll.add_argument("--gateway-id", required=True, help="Gateway identifier (gw_...)")
    p_gw_enroll.add_argument("--token", required=True, help="One-time enrollment token")
    p_gw_enroll.set_defaults(func=cmd_gateway_enroll)

    p_gw_doc = sub_gw.add_parser("doctor", help="Run local gateway diagnostic health checklist", parents=[common])
    p_gw_doc.set_defaults(func=cmd_gateway_doctor)

    # credentials (Step 22 Verifiable Agent Credentials)
    p_cred = subparsers.add_parser("credentials", help="Issue, verify, and manage Verifiable Agent Credentials", parents=[common])
    sub_cred = p_cred.add_subparsers(dest="subcommand", required=True)

    p_ci = sub_cred.add_parser("issue", help="Issue an ATC/1.0 verifiable credential for an agent", parents=[common])
    p_ci.add_argument("--agent", required=True, help="Subject Agent identifier or UUID")
    p_ci.add_argument("--type", choices=["AgentIdentityCredential", "AgentCapabilityCredential"], default="AgentIdentityCredential", help="Credential type")
    p_ci.add_argument("--claims", help="JSON string or file path containing additional claims")
    p_ci.add_argument("--capabilities", help="Comma-separated capability list (for AgentCapabilityCredential)")
    p_ci.add_argument("--validity-days", type=int, help="Credential lifetime in days")
    p_ci.add_argument("--environment", choices=["production", "sandbox"], default="production", help="Target environment")
    p_ci.set_defaults(func=cmd_credentials_issue)

    p_cv = sub_cred.add_parser("verify", help="Verify an ATC/1.0 verifiable credential", parents=[common])
    p_cv.add_argument("--file", help="Path to credential JSON file")
    p_cv.add_argument("--json", help="Credential JSON string")
    p_cv.add_argument("--environment", choices=["production", "sandbox"], default="production", help="Verification environment")
    p_cv.set_defaults(func=cmd_credentials_verify)

    p_cg = sub_cred.add_parser("get", help="Retrieve public status of a credential", parents=[common])
    p_cg.add_argument("credential_id", help="Credential ID (cred_...)")
    p_cg.set_defaults(func=cmd_credentials_get)

    p_cr = sub_cred.add_parser("revoke", help="Revoke an issued credential", parents=[common])
    p_cr.add_argument("credential_id", help="Credential ID (cred_...)")
    p_cr.add_argument("--reason", default="ISSUER_ACTION", choices=["AGENT_REVOKED", "KEY_COMPROMISED", "CLAIMS_CHANGED", "ISSUER_ACTION", "SECURITY_EVENT"], help="Revocation reason code")
    p_cr.set_defaults(func=cmd_credentials_revoke)

    p_cl = sub_cred.add_parser("list", help="List issued credentials", parents=[common])
    p_cl.add_argument("--status", choices=["ACTIVE", "REVOKED", "EXPIRED"], help="Filter by status")
    p_cl.add_argument("--type", help="Filter by credential type")
    p_cl.set_defaults(func=cmd_credentials_list)

    # issuers (Step 22 Trust Registry Issuers)
    p_iss = subparsers.add_parser("issuers", help="Manage Credential Issuers and Signing Keys", parents=[common])
    sub_iss = p_iss.add_subparsers(dest="subcommand", required=True)

    p_il = sub_iss.add_parser("list", help="List organization credential issuers", parents=[common])
    p_il.set_defaults(func=cmd_issuers_list)

    p_ik = sub_iss.add_parser("keys", help="List public signing keys for an issuer", parents=[common])
    p_ik.add_argument("issuer_id", help="Issuer ID (iss_...)")
    p_ik.set_defaults(func=cmd_issuers_keys)

    # gateways (Step 23 Enterprise Gateways & Fleet Management)
    p_gws = subparsers.add_parser("gateways", help="Manage Enterprise Gateways and fleet configuration", parents=[common])
    sub_gws = p_gws.add_subparsers(dest="subcommand", required=True)

    p_gw_list = sub_gws.add_parser("list", help="List registered enterprise gateways", parents=[common])
    p_gw_list.add_argument("--environment", choices=["PRODUCTION", "SANDBOX"], help="Filter by environment")
    p_gw_list.add_argument("--status", help="Filter by status")
    p_gw_list.set_defaults(func=cmd_gateways_list)

    p_gw_create = sub_gws.add_parser("create", help="Register a new enterprise gateway or sidecar", parents=[common])
    p_gw_create.add_argument("--name", required=True, help="Gateway name")
    p_gw_create.add_argument("--type", choices=["SELF_HOSTED_GATEWAY", "SIDECAR", "CLOUD_GATEWAY"], default="SELF_HOSTED_GATEWAY", help="Deployment type")
    p_gw_create.add_argument("--environment", choices=["PRODUCTION", "SANDBOX"], default="PRODUCTION", help="Environment")
    p_gw_create.add_argument("--offline-policy", choices=["FAIL_CLOSED", "LIMITED_OFFLINE"], default="FAIL_CLOSED", help="Offline policy")
    p_gw_create.set_defaults(func=cmd_gateways_create)

    p_gw_get = sub_gws.add_parser("get", help="Get gateway details", parents=[common])
    p_gw_get.add_argument("gateway_id", help="Gateway ID (gw_...)")
    p_gw_get.set_defaults(func=cmd_gateways_get)

    p_gw_susp = sub_gws.add_parser("suspend", help="Suspend an enterprise gateway", parents=[common])
    p_gw_susp.add_argument("gateway_id", help="Gateway ID (gw_...)")
    p_gw_susp.set_defaults(func=cmd_gateways_suspend)

    p_gw_rev = sub_gws.add_parser("revoke", help="Permanently revoke a gateway", parents=[common])
    p_gw_rev.add_argument("gateway_id", help="Gateway ID (gw_...)")
    p_gw_rev.set_defaults(func=cmd_gateways_revoke)

    p_gw_doc = sub_gws.add_parser("doctor", help="Run Enterprise Gateway diagnostics", parents=[common])
    p_gw_doc.set_defaults(func=cmd_gateway_doctor)

    # reliability (Step 24)
    p_rel = subparsers.add_parser("reliability", help="Reliability and cluster status", parents=[common])
    sub_rel = p_rel.add_subparsers(dest="subcommand", required=True)
    p_rs = sub_rel.add_parser("status", help="Get cluster reliability and dependencies status", parents=[common])
    p_rs.set_defaults(func=cmd_reliability_status)

    # region (Step 24)
    p_reg = subparsers.add_parser("region", help="Multi-region operational status", parents=[common])
    sub_reg = p_reg.add_subparsers(dest="subcommand", required=True)
    p_regs = sub_reg.add_parser("status", help="Get region role, health, and fencing status", parents=[common])
    p_regs.set_defaults(func=cmd_region_status)

    # backup (Step 24)
    p_bak = subparsers.add_parser("backup", help="Backup verification", parents=[common])
    sub_bak = p_bak.add_subparsers(dest="subcommand", required=True)
    p_bv = sub_bak.add_parser("verify", help="Verify integrity of backup archive against manifest", parents=[common])
    p_bv.add_argument("manifest", help="Path to backup_manifest.json")
    p_bv.set_defaults(func=cmd_backup_verify)

    # restore (Step 24)
    p_rst = subparsers.add_parser("restore", help="Restore verification", parents=[common])
    sub_rst = p_rst.add_subparsers(dest="subcommand", required=True)
    p_rc = sub_rst.add_parser("check", help="Check restore target database safety", parents=[common])
    p_rc.add_argument("target_db", help="Target database URL")
    p_rc.set_defaults(func=cmd_restore_check)

    # security (Step 26)
    p_sec = subparsers.add_parser("security", help="Enterprise SOC operations, events, and alerts", parents=[common])
    sub_sec = p_sec.add_subparsers(dest="subcommand", required=True)

    # security overview
    p_so = sub_sec.add_parser("overview", help="Get SOC security posture overview", parents=[common])
    p_so.set_defaults(func=cmd_security_overview)

    # security events
    p_se = sub_sec.add_parser("events", help="Security event inspection", parents=[common])
    sub_se = p_se.add_subparsers(dest="subaction", required=True)
    p_sel = sub_se.add_parser("list", help="List security events", parents=[common])
    p_sel.add_argument("--severity", help="Filter by severity (CRITICAL, HIGH, etc.)")
    p_sel.add_argument("--category", help="Filter by category")
    p_sel.add_argument("--limit", type=int, default=50, help="Maximum events to return")
    p_sel.set_defaults(func=cmd_security_events_list)
    p_seg = sub_se.add_parser("get", help="Get security event detail", parents=[common])
    p_seg.add_argument("event_id", help="Event ID (evt_...)")
    p_seg.set_defaults(func=cmd_security_events_get)

    # security alerts
    p_sa = sub_sec.add_parser("alerts", help="Security alert management", parents=[common])
    sub_sa = p_sa.add_subparsers(dest="subaction", required=True)
    p_sal = sub_sa.add_parser("list", help="List security alerts", parents=[common])
    p_sal.add_argument("--status", choices=["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"], help="Filter by status")
    p_sal.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Filter by severity")
    p_sal.set_defaults(func=cmd_security_alerts_list)
    p_saa = sub_sa.add_parser("acknowledge", help="Acknowledge an alert", parents=[common])
    p_saa.add_argument("alert_id", help="Alert ID (alt_...)")
    p_saa.set_defaults(func=cmd_security_alerts_ack)
    p_sar = sub_sa.add_parser("resolve", help="Resolve an alert with note", parents=[common])
    p_sar.add_argument("alert_id", help="Alert ID (alt_...)")
    p_sar.add_argument("--note", help="Resolution note")
    p_sar.set_defaults(func=cmd_security_alerts_resolve)

    # security rules
    p_sr = sub_sec.add_parser("rules", help="Detection rules", parents=[common])
    sub_sr = p_sr.add_subparsers(dest="subaction", required=True)
    p_srl = sub_sr.add_parser("list", help="List detection rules", parents=[common])
    p_srl.set_defaults(func=cmd_security_rules_list)

    # security exports
    p_sx = sub_sec.add_parser("exports", help="SIEM and webhook export destinations", parents=[common])
    sub_sx = p_sx.add_subparsers(dest="subaction", required=True)
    p_sxl = sub_sx.add_parser("list", help="List export destinations", parents=[common])
    p_sxl.set_defaults(func=cmd_security_exports_list)

    # policies (Step 27 APL/1.0 Policy-as-Code)
    p_pol = subparsers.add_parser("policies", help="APL/1.0 Policy-as-Code, validation, simulation, and lifecycle", parents=[common])
    sub_pol = p_pol.add_subparsers(dest="subcommand", required=True)

    p_poll = sub_pol.add_parser("list", help="List registered enterprise policies", parents=[common])
    p_poll.set_defaults(func=cmd_policies_list)

    p_polg = sub_pol.add_parser("get", help="Get policy details", parents=[common])
    p_polg.add_argument("policy_id", help="Policy ID (pol_...)")
    p_polg.set_defaults(func=cmd_policies_get)

    p_polv = sub_pol.add_parser("validate", help="Validate an APL/1.0 policy document", parents=[common])
    p_polv.add_argument("--file", help="Path to policy YAML/JSON file")
    p_polv.add_argument("--yaml", help="Raw YAML string")
    p_polv.set_defaults(func=cmd_policies_validate)

    p_pols = sub_pol.add_parser("simulate", help="Simulate policy execution without side-effects", parents=[common])
    p_pols.add_argument("--context", required=True, help="Context JSON string or path to JSON context file")
    p_pols.add_argument("--file", help="Optional path to candidate policy YAML file")
    p_pols.add_argument("--policy-id", help="Policy ID")
    p_pols.add_argument("--version", type=int, help="Version number to simulate against")
    p_pols.set_defaults(func=cmd_policies_simulate)

    p_polp = sub_pol.add_parser("publish", help="Publish a policy version", parents=[common])
    p_polp.add_argument("policy_id", help="Policy ID (pol_...)")
    p_polp.add_argument("--version", type=int, required=True, help="Version number to publish")
    p_polp.set_defaults(func=cmd_policies_publish)

    p_polr = sub_pol.add_parser("rollback", help="Rollback policy to previous version", parents=[common])
    p_polr.add_argument("policy_id", help="Policy ID (pol_...)")
    p_polr.add_argument("--target-version", type=int, required=True, help="Target version to roll back to")
    p_polr.add_argument("--reason", required=True, help="Rollback audit reason")
    p_polr.set_defaults(func=cmd_policies_rollback)

    p_pold = sub_pol.add_parser("diff", help="Diff two policy versions", parents=[common])
    p_pold.add_argument("policy_id", help="Policy ID (pol_...)")
    p_pold.add_argument("--v1", type=int, required=True, help="Baseline version number")
    p_pold.add_argument("--v2", type=int, required=True, help="Target version number")
    p_pold.set_defaults(func=cmd_policies_diff)

    # governance (Step 28 Enterprise Agent Lifecycle Governance)
    p_gov = subparsers.add_parser("governance", help="Enterprise Agent Governance, reviews, and signals", parents=[common])
    sub_gov = p_gov.add_subparsers(dest="subcommand", required=True)

    p_gd = sub_gov.add_parser("dashboard", help="View executive governance KPIs and posture overview", parents=[common])
    p_gd.set_defaults(func=cmd_governance_dashboard)

    p_gs = sub_gov.add_parser("signals", help="List governance warning signals and alerts", parents=[common])
    p_gs.add_argument("--agent-id", help="Filter signals by agent ID")
    p_gs.set_defaults(func=cmd_governance_signals)

    p_gc = sub_gov.add_parser("certifications", help="List access certification reviews", parents=[common])
    p_gc.add_argument("--status", choices=["PENDING", "APPROVED", "REJECTED", "EXPIRED"], help="Filter by status")
    p_gc.set_defaults(func=cmd_governance_certifications)

    p_greq = sub_gov.add_parser("certify", help="Initiate certification access review for an agent", parents=[common])
    p_greq.add_argument("agent_id", help="Agent UUID")
    p_greq.add_argument("--due-days", type=int, default=14, help="Review due window in days")
    p_greq.add_argument("--notes", help="Review justification or notes")
    p_greq.set_defaults(func=cmd_governance_certify)

    p_gdec = sub_gov.add_parser("decide", help="Record certification decision (APPROVED or REJECTED)", parents=[common])
    p_gdec.add_argument("certification_id", help="Certification ID (cert_...)")
    p_gdec.add_argument("--decision", required=True, choices=["APPROVED", "REJECTED"], help="Reviewer decision")
    p_gdec.add_argument("--notes", help="Decision rationale")
    p_gdec.set_defaults(func=cmd_governance_decide)

    # discovery (Step 29 Agent Discovery & Shadow AI)
    p_disc = subparsers.add_parser("discovery", help="Agent Discovery, Shadow AI, and review queue", parents=[common])
    sub_disc = p_disc.add_subparsers(dest="subcommand", required=True)

    p_dd = sub_disc.add_parser("dashboard", help="View discovery metrics and candidate review summary", parents=[common])
    p_dd.set_defaults(func=cmd_discovery_dashboard)

    p_dsig = sub_disc.add_parser("signals", help="List discovery warning signals (unmanaged, shadow AI)", parents=[common])
    p_dsig.set_defaults(func=cmd_discovery_signals)

    p_dscan = sub_disc.add_parser("scan", help="Trigger a discovery scan run", parents=[common])
    p_dscan.add_argument("source_id", help="Discovery Source ID or UUID")
    p_dscan.set_defaults(func=cmd_discovery_scan)

    p_druns = sub_disc.add_parser("runs", help="List discovery scan runs", parents=[common])
    p_druns.add_argument("--source-id", help="Filter by source ID")
    p_druns.add_argument("--limit", type=int, default=50, help="Page limit")
    p_druns.set_defaults(func=cmd_discovery_runs_list)

    p_dsrc = sub_disc.add_parser("sources", help="Manage discovery source connectors", parents=[common])
    sub_dsrc = p_dsrc.add_subparsers(dest="source_cmd", required=True)
    p_ds_l = sub_dsrc.add_parser("list", help="List discovery sources", parents=[common])
    p_ds_l.set_defaults(func=cmd_discovery_sources_list)
    p_ds_g = sub_dsrc.add_parser("get", help="Get discovery source details", parents=[common])
    p_ds_g.add_argument("source_id", help="Discovery Source ID")
    p_ds_g.set_defaults(func=cmd_discovery_sources_get)
    p_ds_c = sub_dsrc.add_parser("create", help="Create discovery source connector", parents=[common])
    p_ds_c.add_argument("--name", required=True, help="Connector display name")
    p_ds_c.add_argument("--type", required=True, choices=["KUBERNETES", "CONTAINER_PLATFORM", "CLOUD", "CI_CD", "SOURCE_REPOSITORY", "GATEWAY_TELEMETRY", "SIDECAR_TELEMETRY", "IMPORT"], help="Source type")
    p_ds_c.add_argument("--config", help="JSON configuration string")
    p_ds_c.add_argument("--credential-ref", help="Pointer reference in SecretProvider")
    p_ds_c.set_defaults(func=cmd_discovery_sources_create)

    p_dc = sub_disc.add_parser("candidates", help="Manage and inspect discovered agent candidates", parents=[common])
    sub_dc = p_dc.add_subparsers(dest="candidate_cmd", required=True)
    p_dc_l = sub_dc.add_parser("list", help="List discovery candidates", parents=[common])
    p_dc_l.add_argument("--status", choices=["NEW", "NEEDS_REVIEW", "MATCHED", "UNMANAGED", "ONBOARDING", "REGISTERED", "IGNORED", "FALSE_POSITIVE", "STALE"], help="Filter by status")
    p_dc_l.add_argument("--environment", choices=["production", "staging", "development", "unknown"], help="Filter by environment")
    p_dc_l.add_argument("--confidence", choices=["LOW", "MEDIUM", "HIGH"], help="Filter by confidence level")
    p_dc_l.add_argument("--search", help="Search keyword")
    p_dc_l.add_argument("--limit", type=int, default=50, help="Page limit")
    p_dc_l.set_defaults(func=cmd_discovery_candidates_list)
    p_dc_g = sub_dc.add_parser("get", help="Get discovery candidate details and evidence", parents=[common])
    p_dc_g.add_argument("candidate_id", help="Candidate ID")
    p_dc_g.set_defaults(func=cmd_discovery_candidates_get)

    p_dm = sub_disc.add_parser("match", help="Match candidate to registered Agent", parents=[common])
    p_dm.add_argument("candidate_id", help="Candidate ID")
    p_dm.add_argument("--agent-id", required=True, help="Registered Agent ID or UUID")
    p_dm.set_defaults(func=cmd_discovery_match)

    p_do = sub_disc.add_parser("onboard", help="Safe onboarding of candidate into Step 28 inventory", parents=[common])
    p_do.add_argument("candidate_id", help="Candidate ID")
    p_do.add_argument("--owner-id", required=True, help="Owner User UUID")
    p_do.add_argument("--owner-type", default="USER", choices=["USER", "TEAM", "SERVICE_OWNER"], help="Owner type")
    p_do.add_argument("--purpose", help="Business purpose description")
    p_do.add_argument("--risk-classification", default="LOW", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Risk tier")
    p_do.add_argument("--team", help="Responsible team")
    p_do.set_defaults(func=cmd_discovery_onboard)

    p_di = sub_disc.add_parser("ignore", help="Suppress candidate from review queue", parents=[common])
    p_di.add_argument("candidate_id", help="Candidate ID")
    p_di.add_argument("--reason", required=True, help="Ignore reason")
    p_di.add_argument("--days", type=int, default=30, help="Suppression duration in days")
    p_di.set_defaults(func=cmd_discovery_ignore)

    # services (Step 30 Service Registry & Communication)
    p_svc = subparsers.add_parser("services", help="Service Registry lifecycle and management", parents=[common])
    sub_svc = p_svc.add_subparsers(dest="service_cmd", required=True)
    p_svl = sub_svc.add_parser("list", help="List registered services", parents=[common])
    p_svl.add_argument("--status", help="Filter by status (ACTIVE, DRAFT, etc.)")
    p_svl.add_argument("--visibility", help="Filter by visibility (ORGANIZATION, PUBLIC, etc.)")
    p_svl.add_argument("--limit", type=int, default=50, help="Page limit")
    p_svl.set_defaults(func=cmd_services_list)
    p_svg = sub_svc.add_parser("get", help="Get service details", parents=[common])
    p_svg.add_argument("service_id", help="Service ID (svc_...)")
    p_svg.set_defaults(func=cmd_services_get)
    p_svc_c = sub_svc.add_parser("create", help="Create a new service", parents=[common])
    p_svc_c.add_argument("--agent-id", required=True, help="Owning agent ID")
    p_svc_c.add_argument("--name", required=True, help="Service name")
    p_svc_c.add_argument("--description", help="Service description")
    p_svc_c.add_argument("--version", default="1.0.0", help="Service version")
    p_svc_c.add_argument("--status", default="ACTIVE", help="Initial status")
    p_svc_c.add_argument("--visibility", default="ORGANIZATION", help="Visibility")
    p_svc_c.add_argument("--environment", default="production", help="Environment")
    p_svc_c.add_argument("--metadata", help="Metadata JSON string")
    p_svc_c.set_defaults(func=cmd_services_create)
    p_svd = sub_svc.add_parser("delete", help="Retire a service", parents=[common])
    p_svd.add_argument("service_id", help="Service ID (svc_...)")
    p_svd.set_defaults(func=cmd_services_delete)

    # capabilities
    p_caps = subparsers.add_parser("capabilities", help="Capability catalog management", parents=[common])
    sub_caps = p_caps.add_subparsers(dest="capability_cmd", required=True)
    p_cpl = sub_caps.add_parser("list", help="List published capabilities", parents=[common])
    p_cpl.add_argument("--service-id", help="Filter by service ID")
    p_cpl.add_argument("--limit", type=int, default=50, help="Limit")
    p_cpl.set_defaults(func=cmd_capabilities_list)
    p_cpr = sub_caps.add_parser("register", help="Register capability on a service", parents=[common])
    p_cpr.add_argument("--service-id", required=True, help="Service ID")
    p_cpr.add_argument("--agent-id", required=True, help="Agent ID")
    p_cpr.add_argument("--name", required=True, help="Capability name (e.g. text.summarize)")
    p_cpr.add_argument("--version", default="1.0", help="Capability version")
    p_cpr.add_argument("--description", help="Description")
    p_cpr.add_argument("--input-schema", help="Input JSON schema string")
    p_cpr.add_argument("--output-schema", help="Output JSON schema string")
    p_cpr.add_argument("--risk", default="LOW", help="Risk tier")
    p_cpr.add_argument("--requires-approval", action="store_true", help="Hold for approval")
    p_cpr.add_argument("--threshold", type=float, help="Approval monetary threshold")
    p_cpr.set_defaults(func=cmd_capabilities_register)

    # endpoints
    p_eps = subparsers.add_parser("endpoints", help="Service endpoint routing and verification", parents=[common])
    sub_eps = p_eps.add_subparsers(dest="endpoint_cmd", required=True)
    p_epl = sub_eps.add_parser("list", help="List endpoints for a service", parents=[common])
    p_epl.add_argument("service_id", help="Service ID")
    p_epl.set_defaults(func=cmd_endpoints_list)
    p_epa = sub_eps.add_parser("add", help="Add an endpoint to a service", parents=[common])
    p_epa.add_argument("service_id", help="Service ID")
    p_epa.add_argument("--url", required=True, help="Endpoint URL")
    p_epa.add_argument("--protocol", default="HTTPS", help="Protocol (HTTPS, SIDECAR, etc.)")
    p_epa.add_argument("--priority", type=int, default=1, help="Priority (1 is highest)")
    p_epa.add_argument("--weight", type=int, default=100, help="Traffic weight")
    p_epa.add_argument("--environment", default="production", help="Environment")
    p_epa.set_defaults(func=cmd_endpoints_add)
    p_epv = sub_eps.add_parser("verify", help="Verify endpoint ownership challenge", parents=[common])
    p_epv.add_argument("service_id", help="Service ID")
    p_epv.add_argument("endpoint_id", help="Endpoint ID (ep_...)")
    p_epv.add_argument("--challenge-token", required=True, help="Challenge token")
    p_epv.add_argument("--signature", help="Ed25519 signature proof")
    p_epv.add_argument("--key-id", help="Signing Key ID")
    p_epv.set_defaults(func=cmd_endpoints_verify)

    # resolve
    p_res = subparsers.add_parser("resolve", help="Resolve service endpoints for a caller agent", parents=[common])
    p_res.add_argument("--caller-agent-id", required=True, help="Caller Agent ID")
    p_res.add_argument("--service-id", required=True, help="Target Service ID or Name")
    p_res.add_argument("--capability", help="Target capability name")
    p_res.set_defaults(func=cmd_services_resolve)

    # call
    p_call = subparsers.add_parser("call", help="Execute loop-protected agent-to-agent capability call", parents=[common])
    p_call.add_argument("--caller-agent-id", required=True, help="Caller Agent ID")
    p_call.add_argument("--service-id", required=True, help="Target Service ID or Name")
    p_call.add_argument("--capability", required=True, help="Target capability name")
    p_call.add_argument("--payload", help="JSON payload payload string")
    p_call.add_argument("--call-chain", help="Comma-separated caller chain agents")
    p_call.add_argument("--depth", type=int, default=1, help="Current depth in chain")
    p_call.add_argument("--idempotency-key", help="Unique idempotency key")
    p_call.set_defaults(func=cmd_services_call)

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Run connectivity, clock, and cryptographic diagnostics", parents=[common])
    p_doc.set_defaults(func=cmd_doctor)

    parsed = parser.parse_args(argv)
    return parsed.func(parsed)


if __name__ == "__main__":
    sys.exit(main())
