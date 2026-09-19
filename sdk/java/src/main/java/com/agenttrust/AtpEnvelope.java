package com.agenttrust;

/**
 * Representation of an ATP/1.0 protocol message envelope.
 */
public record AtpEnvelope(
    String protocol,
    String messageId,
    String messageType,
    String sourceAddress,
    String targetAddress,
    String capability,
    String timestamp,
    String nonce,
    String payloadSha256,
    String keyId,
    String signatureValue
) {
    public static final String PROTOCOL_VERSION = "ATP/1.0";
    public static final String SIGNING_VERSION = "ATP-SIG/1";
}
