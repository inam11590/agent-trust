package com.agenttrust;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

/** AgentTrust v1 signing using the JDK Ed25519 provider. Private keys stay local. */
public final class AgentSigning {
    private AgentSigning() { }

    public static byte[] canonicalRequest(String method, String path, String agentId, String keyId,
                                          String timestamp, String nonce, byte[] body) {
        try {
            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            return String.join("\n", "v1", method.toUpperCase(), path, agentId, keyId, timestamp, nonce, hash, "")
                .getBytes(StandardCharsets.US_ASCII);
        } catch (Exception error) { throw new IllegalStateException("SHA-256 is unavailable", error); }
    }

    public static final class Signer {
        private final String agentId;
        private final String keyId;
        private final PrivateKey privateKey;

        public Signer(String agentId, String keyId, Path privateKeyPath) {
            this.agentId = agentId; this.keyId = keyId;
            try {
                String pem = Files.readString(privateKeyPath);
                if (!pem.contains("-----BEGIN PRIVATE KEY-----") || !pem.contains("-----END PRIVATE KEY-----"))
                    throw new IllegalArgumentException("An Ed25519 PKCS#8 private key is required");
                String encoded = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
                privateKey = KeyFactory.getInstance("Ed25519").generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded)));
            } catch (IllegalArgumentException error) { throw error;
            } catch (Exception error) { throw new IllegalArgumentException("Cannot load Ed25519 private key", error); }
        }

        public String agentId() { return agentId; }

        public Map<String, String> headers(String method, String path, byte[] body) {
            byte[] random = new byte[16]; new SecureRandom().nextBytes(random);
            return headers(method, path, body, Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
                "nonce_" + HexFormat.of().formatHex(random));
        }

        public Map<String, String> headers(String method, String path, byte[] body, String timestamp, String nonce) {
            try {
                Signature signature = Signature.getInstance("Ed25519");
                signature.initSign(privateKey);
                signature.update(canonicalRequest(method, path, agentId, keyId, timestamp, nonce, body));
                return Map.of("X-Agent-ID", agentId, "X-Agent-Key-ID", keyId,
                    "X-Agent-Timestamp", timestamp, "X-Agent-Nonce", nonce,
                    "X-Agent-Signature", Base64.getEncoder().encodeToString(signature.sign()),
                    "X-Agent-Signature-Version", "v1");
            } catch (Exception error) { throw new IllegalStateException("Ed25519 signing failed", error); }
        }

        public String signAtpBytes(byte[] canonicalBytes) {
            try {
                Signature signature = Signature.getInstance("Ed25519");
                signature.initSign(privateKey);
                signature.update(canonicalBytes);
                return Base64.getEncoder().encodeToString(signature.sign());
            } catch (Exception error) { throw new IllegalStateException("Ed25519 ATP signing failed", error); }
        }
    }

    public static byte[] canonicalAtpRequest(String messageId, String messageType, String sourceOrgId,
                                            String sourceAgentId, String targetOrgId, String targetAgentId,
                                            String capability, String timestamp, String nonce, String payloadSha256) {
        return String.join("\n", "ATP-SIG/1", messageId, messageType, sourceOrgId, sourceAgentId,
                           targetOrgId, targetAgentId, capability, timestamp, nonce, payloadSha256, "")
            .getBytes(StandardCharsets.UTF_8);
    }
}
