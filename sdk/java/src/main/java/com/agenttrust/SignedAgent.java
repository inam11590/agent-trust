package com.agenttrust;

/** A developer-managed agent identity bound to one local private key. */
public final class SignedAgent {
    private final AgentTrustClient client;
    private final AgentSigning.Signer signer;

    SignedAgent(AgentTrustClient client, AgentSigning.Signer signer) {
        this.client = client; this.signer = signer;
    }

    public AuthorizationResult authorize(AuthorizationRequest request) {
        return client.authorizeSigned(request, signer);
    }
}
