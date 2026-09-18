"""Unit tests for Step 20 cross-organization trust in Python SDK."""

import base64
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agenttrust.client import AgentTrust, CrossOrgAuthorizationResult, SignedAgent
from agenttrust.signing import AgentSigner, canonical_cross_org_request_v2


class TestCrossOrgTrustSDK(unittest.TestCase):
    def setUp(self):
        self.privkey = Ed25519PrivateKey.generate()
        self.pem = self.privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.source_agent_id = str(uuid4())
        self.target_agent_id = str(uuid4())
        self.source_org_id = str(uuid4())
        self.target_org_id = str(uuid4())
        self.key_id = "key_ag_test123"

    def test_canonical_cross_org_request_v2(self):
        body = b'{"action":"book_room","resource":"hotel"}'
        canonical = canonical_cross_org_request_v2(
            method="POST",
            path="/api/v1/cross-org/authorize",
            source_org_id=self.source_org_id,
            target_org_id=self.target_org_id,
            source_agent_id=self.source_agent_id,
            target_agent_id=self.target_agent_id,
            key_id=self.key_id,
            timestamp="2026-09-18T12:00:00Z",
            nonce="nonce_1234567890abcdef",
            body=body,
        )
        lines = canonical.decode("ascii").split("\n")
        self.assertEqual(lines[0], "v2")
        self.assertEqual(lines[1], "POST")
        self.assertEqual(lines[2], "/api/v1/cross-org/authorize")
        self.assertEqual(lines[3], self.source_org_id)
        self.assertEqual(lines[4], self.target_org_id)
        self.assertEqual(lines[5], self.source_agent_id)
        self.assertEqual(lines[6], self.target_agent_id)
        self.assertEqual(lines[7], self.key_id)
        self.assertEqual(lines[8], "2026-09-18T12:00:00Z")
        self.assertEqual(lines[9], "nonce_1234567890abcdef")
        self.assertEqual(lines[10], hashlib.sha256(body).hexdigest())

    def test_cross_org_headers(self):
        with patch.object(Path, "read_bytes", return_value=self.pem):
            signer = AgentSigner(self.source_agent_id, self.key_id, "dummy.pem")

        body = b'{"action":"test","resource":"res"}'
        headers = signer.cross_org_headers(
            method="POST",
            path="/api/v1/cross-org/authorize",
            body=body,
            source_org_id=self.source_org_id,
            target_org_id=self.target_org_id,
            target_agent_id=self.target_agent_id,
            timestamp="2026-09-18T12:00:00Z",
            nonce="nonce_xyz",
        )

        self.assertEqual(headers["X-Agent-ID"], self.source_agent_id)
        self.assertEqual(headers["X-Agent-Key-ID"], self.key_id)
        self.assertEqual(headers["X-Agent-Signature-Version"], "v2")
        self.assertEqual(headers["X-Source-Org-ID"], self.source_org_id)
        self.assertEqual(headers["X-Target-Org-ID"], self.target_org_id)
        self.assertEqual(headers["X-Target-Agent-ID"], self.target_agent_id)

        # Verify signature with public key
        sig = base64.b64decode(headers["X-Agent-Signature"])
        pubkey = self.privkey.public_key()
        canonical = canonical_cross_org_request_v2(
            method="POST",
            path="/api/v1/cross-org/authorize",
            source_org_id=self.source_org_id,
            target_org_id=self.target_org_id,
            source_agent_id=self.source_agent_id,
            target_agent_id=self.target_agent_id,
            key_id=self.key_id,
            timestamp="2026-09-18T12:00:00Z",
            nonce="nonce_xyz",
            body=body,
        )
        pubkey.verify(sig, canonical)

    def test_authorize_cross_org_client(self):
        client = AgentTrust(api_key="at_test_abcdef1234567890abcdef123456")
        mock_response = {
            "request_id": "xreq_1234567890abcdef123456",
            "status": "APPROVED",
            "reason": "Cross-organization request authorized",
            "pending_approvals": [],
        }

        with patch.object(client, "_request", return_value=mock_response):
            result = client.authorize_cross_org(
                source_agent_id=self.source_agent_id,
                target_org_id=self.target_org_id,
                target_agent_id=self.target_agent_id,
                action="book_hotel",
                resource="room",
                amount=200,
                currency="USD",
            )
            self.assertEqual(result.status, "APPROVED")
            self.assertEqual(result.request_id, "xreq_1234567890abcdef123456")
            self.assertEqual(result.pending_approvals, [])

    def test_signed_agent_authorize_external(self):
        client = AgentTrust(api_key="at_test_abcdef1234567890abcdef123456")
        with patch.object(Path, "read_bytes", return_value=self.pem):
            signer = AgentSigner(self.source_agent_id, self.key_id, "dummy.pem")
        signed_agent = SignedAgent(client, signer)

        mock_response = {
            "request_id": "xreq_9999999990abcdef123456",
            "status": "PENDING",
            "reason": "Awaiting multi-party approval",
            "pending_approvals": ["SOURCE", "TARGET"],
        }

        with patch.object(client, "_request", return_value=mock_response):
            result = signed_agent.authorize_external(
                target_org_id=self.target_org_id,
                target_agent_id=self.target_agent_id,
                action="book_suite",
                resource="hotel",
                amount=500,
                currency="USD",
            )
            self.assertEqual(result.status, "PENDING")
            self.assertEqual(result.pending_approvals, ["SOURCE", "TARGET"])
