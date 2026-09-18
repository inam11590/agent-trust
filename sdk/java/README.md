# AgentTrust Java SDK

This small Java 21+ SDK uses the standard HTTP and Ed25519 providers and has no external dependencies.

```java
AgentTrustClient client = new AgentTrustClient(System.getenv("AGENTTRUST_API_KEY"));
AuthorizationResult result = client.authorize(
    new AuthorizationRequest("agt_xxxxx", "purchase", "flight", 420.0, "USD", "checkout-123")
);
```

For a registered signing key, use the matching local Ed25519 PKCS#8 PEM private key:

```java
SignedAgent travel = client.agent("agt_<24 lowercase hex>", "key_ag_<24 lowercase hex>",
    java.nio.file.Path.of("/secure/path/agent-private.pem"));
AuthorizationResult result = travel.authorize(
    new AuthorizationRequest("agt_<24 lowercase hex>", "purchase", "flight", 420.0, "USD", null));
```

The private key is read locally and is never sent to AgentTrust. See [signing protocol](../../docs/AGENT_SIGNING.md).
