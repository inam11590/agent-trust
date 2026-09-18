package com.agenttrust;

public record AuthorizationResult(String requestId, String status, String reason) {}
