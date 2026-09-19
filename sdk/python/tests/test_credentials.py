"""Python SDK tests for Step 22 Verifiable Credentials (ATC/1.0)."""

import json
from pathlib import Path
from agenttrust.signing import canonical_atc_credential, verify_atc_credential_offline


def test_test_vector_conformance():
    vector_path = Path(__file__).resolve().parents[3] / "tests" / "credentials" / "v1" / "test_vectors.json"
    assert vector_path.exists(), f"Vector file not found: {vector_path}"

    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    cred = vector["credential"]
    expected_ascii = vector["canonical_ascii"]
    expected_claims_sha = vector["claims_sha256"]
    expected_sig = vector["expected_signature_base64"]
    pub_key_b64 = vector["issuer_public_key_base64"]

    subj = cred["subject"]
    canon_bytes, claims_sha = canonical_atc_credential(
        credential_version=cred["credential_version"],
        credential_id=cred["credential_id"],
        issuer_id=cred["issuer"],
        subject_org_id=subj["organization_id"],
        subject_agent_id=subj["agent_id"],
        credential_type=cred["credential_type"],
        issued_at=cred["issued_at"],
        not_before=cred.get("not_before"),
        expires_at=cred["expires_at"],
        environment=cred.get("environment", "production"),
        claims=cred["claims"],
    )

    assert claims_sha == expected_claims_sha
    assert canon_bytes.decode("ascii") == expected_ascii

    # Verify signature offline
    is_valid = verify_atc_credential_offline(cred, pub_key_b64)
    assert is_valid is True


def test_tampered_credential_fails_offline_verification():
    vector_path = Path(__file__).resolve().parents[3] / "tests" / "credentials" / "v1" / "test_vectors.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    cred = vector["credential"]
    pub_key_b64 = vector["issuer_public_key_base64"]

    # Tamper with claims
    tampered_cred = json.loads(json.dumps(cred))
    tampered_cred["claims"]["organization_membership"] = False

    assert verify_atc_credential_offline(tampered_cred, pub_key_b64) is False

    # Tamper with subject
    tampered_subj = json.loads(json.dumps(cred))
    tampered_subj["subject"]["agent_id"] = "agt_rogue"
    assert verify_atc_credential_offline(tampered_subj, pub_key_b64) is False
