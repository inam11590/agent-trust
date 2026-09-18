package com.agenttrust;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Properties;

public final class ClientTest {
    public static void main(String[] args) throws Exception {
        expectFailure(() -> new AgentTrustClient(""));
        expectFailure(() -> new AuthorizationRequest("", "purchase", "flight", 1.0, "USD", null));
        expectFailure(() -> new AuthorizationRequest("agt_test", "purchase", "flight", -1.0, "USD", null));
        AuthorizationRequest valid = new AuthorizationRequest("agt_test", "purchase", "flight", 420.0, "USD", "checkout-1");
        if (!valid.action().equals("purchase")) throw new AssertionError("Request parsing failed");
        testSigningVector();
        System.out.println("Java SDK tests passed");
    }

    private static void testSigningVector() throws Exception {
        Properties values = new Properties();
        try (var input = Files.newInputStream(Path.of("../../docs/test-vectors/agent-signing-v1.properties"))) {
            values.load(input);
        }
        byte[] body = Base64.getDecoder().decode(values.getProperty("body_base64"));
        byte[] canonical = AgentSigning.canonicalRequest(values.getProperty("method"), values.getProperty("path"),
            values.getProperty("agent_id"), values.getProperty("key_id"),
            values.getProperty("timestamp"), values.getProperty("nonce"), body);
        if (!Base64.getEncoder().encodeToString(canonical).equals(values.getProperty("canonical_base64")))
            throw new AssertionError("Java canonical request differs from official vector");
        String encoded = values.getProperty("private_pkcs8_base64");
        String pem = "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----\n";
        Path path = Files.createTempFile("agenttrust-test-only-", ".pem");
        try {
            Files.writeString(path, pem);
            var headers = new AgentSigning.Signer(values.getProperty("agent_id"), values.getProperty("key_id"), path)
                .headers(values.getProperty("method"), values.getProperty("path"), body,
                    values.getProperty("timestamp"), values.getProperty("nonce"));
            if (!headers.get("X-Agent-Signature").equals(values.getProperty("signature_base64")))
                throw new AssertionError("Java signature differs from official vector");
        } finally { Files.deleteIfExists(path); }
    }

    private static void expectFailure(Runnable action) {
        try { action.run(); throw new AssertionError("Expected validation failure"); }
        catch (IllegalArgumentException expected) { }
    }
}
