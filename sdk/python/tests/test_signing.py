"""Shared test-only vector proves the Python SDK follows signing v1."""

import base64
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from agenttrust.signing import AgentSigner, canonical_request

VECTOR = Path(__file__).resolve().parents[3] / "docs" / "test-vectors" / "agent-signing-v1.properties"


class SigningTests(unittest.TestCase):
    def test_official_vector(self):
        values = dict(line.split("=", 1) for line in VECTOR.read_text().splitlines()
                      if line and not line.startswith("#"))
        body = base64.b64decode(values["body_base64"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), values["body_sha256"])
        canonical = canonical_request(values["method"], values["path"], values["agent_id"],
                                      values["key_id"], values["timestamp"], values["nonce"], body)
        self.assertEqual(base64.b64encode(canonical).decode(), values["canonical_base64"])
        private = serialization.load_der_private_key(base64.b64decode(values["private_pkcs8_base64"]), password=None)
        pem = private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with patch.object(Path, "read_bytes", return_value=pem):
            signer = AgentSigner(values["agent_id"], values["key_id"], "test-only-key.pem")
        headers = signer.headers(values["method"], values["path"], body,
            timestamp=values["timestamp"], nonce=values["nonce"])
        self.assertEqual(headers["X-Agent-Signature"], values["signature_base64"])
        self.assertEqual(headers["X-Agent-Signature-Version"], "v1")
