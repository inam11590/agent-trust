# AgentTrust Python SDK

```python
from agenttrust import AgentTrust

client = AgentTrust(api_key="at_live_xxxxx", base_url="http://localhost:8000")
result = client.authorize(agent_id="agt_xxxxx", action="purchase", resource="flight", amount=420, currency="USD")
print(result.status)
```

Prefer the `AGENTTRUST_API_KEY` environment variable and `AgentTrust.from_env()`.

For an agent with a registered public signing key, use its matching **local** Ed25519 PKCS#8 private key:

```python
travel = client.agent(agent_id="agt_<24 lowercase hex>", key_id="key_ag_<24 lowercase hex>",
                      private_key_path="/secure/path/agent-private.pem")
result = travel.authorize(action="purchase", resource="flight", amount=420, currency="USD")
```

The private key stays on your machine. See [signing protocol](../../docs/AGENT_SIGNING.md).
