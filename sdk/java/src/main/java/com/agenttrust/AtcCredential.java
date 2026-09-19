package com.agenttrust;

/**
 * Representation of an AgentTrust Verifiable Agent Credential (ATC/1.0).
 */
public record AtcCredential(
    String credentialVersion,
    String credentialId,
    String credentialType,
    String issuerId,
    String subjectOrgId,
    String subjectAgentId,
    String environment,
    String issuedAt,
    String notBefore,
    String expiresAt,
    String claimsJson,
    String keyId,
    String signatureValue
) {
    public static final String CREDENTIAL_VERSION = "ATC/1.0";
    public static final String SIGNING_PROFILE = "ATC-SIG/1";
}
