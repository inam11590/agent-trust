package com.agenttrust;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AgentTrustClient {
    private static final Pattern FIELD = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    private final String apiKey;
    private final String baseUrl;
    private final Duration timeout;
    private final HttpClient http;

    public AgentTrustClient(String apiKey) { this(apiKey, "https://api.agenttrust.example", Duration.ofSeconds(10)); }
    public AgentTrustClient(String apiKey, String baseUrl, Duration timeout) {
        if (apiKey == null || (!apiKey.startsWith("at_live_") && !apiKey.startsWith("at_test_"))) throw new IllegalArgumentException("A valid AgentTrust API key is required");
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) throw new IllegalArgumentException("baseUrl must use HTTP or HTTPS");
        this.apiKey = apiKey; this.baseUrl = baseUrl.replaceAll("/$", ""); this.timeout = timeout;
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    }
    public String getEnvironment() { return apiKey.startsWith("at_test_") ? "sandbox" : "production"; }
    public static AgentTrustClient fromEnvironment() { return new AgentTrustClient(System.getenv("AGENTTRUST_API_KEY")); }

    public AuthorizationResult authorize(AuthorizationRequest value) {
        return authorizeSigned(value, null);
    }
    public SignedAgent agent(String agentId, String keyId, Path privateKeyPath) {
        return new SignedAgent(this, new AgentSigning.Signer(agentId, keyId, privateKeyPath));
    }
    AuthorizationResult authorizeSigned(AuthorizationRequest value, AgentSigning.Signer signer) {
        if (signer != null && !signer.agentId().equals(value.agentId())) throw new IllegalArgumentException("Agent ID does not match signer");
        String amount = value.amount() == null ? "" : ",\"amount\":" + value.amount() + ",\"currency\":\"" + escape(value.currency()) + "\"";
        String body = "{\"agent_id\":\"" + escape(value.agentId()) + "\",\"action\":\"" + escape(value.action()) + "\",\"resource\":\"" + escape(value.resource()) + "\"" + amount + "}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        HttpRequest.Builder request = base("/api/v1/authorize").POST(HttpRequest.BodyPublishers.ofByteArray(bytes)).header("Content-Type", "application/json");
        if (signer != null) signer.headers("POST", "/api/v1/authorize", bytes).forEach(request::header);
        if (value.idempotencyKey() != null) request.header("Idempotency-Key", value.idempotencyKey());
        return send(request.build());
    }
    public AuthorizationResult getAuthorizationRequest(String requestId) {
        if (requestId == null || !requestId.startsWith("req_")) throw new IllegalArgumentException("A valid requestId is required");
        return send(base("/api/v1/authorization-requests/" + requestId).GET().build());
    }
    private HttpRequest.Builder base(String path) { return HttpRequest.newBuilder(URI.create(baseUrl + path)).timeout(timeout).header("Accept", "application/json").header("X-API-Key", apiKey); }
    private AuthorizationResult send(HttpRequest request) {
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw new AgentTrustException("AgentTrust API request failed", response.statusCode());
            return new AuthorizationResult(field(response.body(), "request_id"), field(response.body(), "status"), field(response.body(), "reason"));
        } catch (AgentTrustException error) { throw error;
        } catch (Exception error) { throw new AgentTrustException("Could not connect to AgentTrust", 0); }
    }
    private static String field(String json, String name) { Matcher match = Pattern.compile(String.format(FIELD.pattern(), Pattern.quote(name))).matcher(json); if (!match.find()) throw new AgentTrustException("Invalid AgentTrust response", 0); return match.group(1); }
    private static String escape(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\""); }
}
