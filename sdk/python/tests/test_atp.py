"""Tests for Python SDK ATP/1.0 envelope generation and ATP-SIG/1 signing."""

import json
from pathlib import Path

from agenttrust.signing import AgentSigner


def test_python_sdk_atp_envelope_conformance():
    vectors_path = Path(__file__).resolve().parents[3] / "tests" / "protocol" / "v1" / "test_vectors.json"
    vector = json.loads(vectors_path.read_text(encoding="utf-8"))

    tmp_key = Path("./tmp_sdk_priv.pem")
    tmp_key.write_text(vector["private_key_pem"], encoding="utf-8")

    try:
        signer = AgentSigner(
            agent_id=vector["source"]["agent_id"],
            key_id="key_test_123",
            private_key_path=tmp_key,
        )

        envelope = signer.sign_atp_envelope(
            source_org_id=vector["source"]["organization_id"],
            target_org_id=vector["target"]["organization_id"],
            target_agent_id=vector["target"]["agent_id"],
            capability=vector["capability"],
            payload=vector["payload"],
            message_id=vector["message_id"],
            timestamp=vector["timestamp"],
            nonce=vector["nonce"],
        )

        assert envelope["protocol"] == "ATP/1.0"
        assert envelope["payload_sha256"] == vector["payload_sha256"]
        assert envelope["signature"]["value"] == vector["signature_base64"]
        assert envelope["source"]["address"] == f"atp://{vector['source']['organization_id']}/{vector['source']['agent_id']}"
        assert envelope["target"]["address"] == f"atp://{vector['target']['organization_id']}/{vector['target']['agent_id']}"
    finally:
        if tmp_key.exists():
            tmp_key.unlink()
