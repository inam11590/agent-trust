package com.agenttrust;

public record AuthorizationRequest(
        String agentId, String action, String resource, Double amount, String currency, String idempotencyKey) {
    public AuthorizationRequest {
        if (agentId == null || agentId.isBlank() || action == null || action.isBlank() || resource == null || resource.isBlank()) {
            throw new IllegalArgumentException("agentId, action, and resource are required");
        }
        if ((amount == null) != (currency == null)) throw new IllegalArgumentException("amount and currency must be provided together");
        if (amount != null && amount < 0) throw new IllegalArgumentException("amount cannot be negative");
    }
}
