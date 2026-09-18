package com.agenttrust;

public final class AgentTrustException extends RuntimeException {
    private final int statusCode;
    public AgentTrustException(String message, int statusCode) { super(message); this.statusCode = statusCode; }
    public int statusCode() { return statusCode; }
}
