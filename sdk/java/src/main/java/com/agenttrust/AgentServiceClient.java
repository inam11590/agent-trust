package com.agenttrust;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * AgentTrust Java SDK: Service Registry and Agent-to-Agent Communication (Step 30).
 */
public class AgentServiceClient {
    private final String baseUrl;
    private final String apiKey;
    private final HttpClient httpClient;

    public AgentServiceClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public String listServices(String status, int limit) throws IOException, InterruptedException {
        String url = String.format("%s/api/v1/services?limit=%d%s",
                baseUrl, limit, (status != null ? "&status=" + status : ""));
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + apiKey)
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public String resolveService(String callerAgentId, String serviceId, String capability) throws IOException, InterruptedException {
        String url = baseUrl + "/api/v1/services/resolve";
        String jsonBody = String.format(
                "{\"caller_agent_id\":\"%s\",\"service_id\":\"%s\"%s}",
                callerAgentId, serviceId, (capability != null ? ",\"capability\":\"" + capability + "\"" : "")
        );
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public String callService(String callerAgentId, String serviceId, String capability, String payloadJson) throws IOException, InterruptedException {
        String url = baseUrl + "/api/v1/services/call";
        String jsonBody = String.format(
                "{\"caller_agent_id\":\"%s\",\"service_id\":\"%s\",\"capability\":\"%s\",\"payload\":%s,\"depth\":1}",
                callerAgentId, serviceId, capability, payloadJson
        );
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
