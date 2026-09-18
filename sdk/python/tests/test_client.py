import json
import os
import unittest
from unittest.mock import patch

from agenttrust import AgentTrust, AgentTrustError


class Response:
    def __init__(self, body): self.body = json.dumps(body).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def read(self): return self.body


class ClientTests(unittest.TestCase):
    @patch("agenttrust.client.urlopen")
    def test_authorize(self, send):
        send.return_value = Response({"request_id": "req_abc", "status": "APPROVED", "reason": "Permission valid"})
        result = AgentTrust("at_live_" + "a" * 64, "http://localhost:8000").authorize(
            agent_id="agt_abc", action="purchase", resource="flight", amount=420, currency="USD",
            idempotency_key="checkout-1")
        self.assertEqual(result.status, "APPROVED")
        request = send.call_args.args[0]
        self.assertEqual(request.headers["X-api-key"], "at_live_" + "a" * 64)
        self.assertEqual(request.headers["Idempotency-key"], "checkout-1")

    @patch("agenttrust.client.urlopen")
    def test_get_request(self, send):
        send.return_value = Response({"request_id": "req_abc", "status": "PENDING", "reason": "User approval required"})
        result = AgentTrust("at_live_" + "a" * 64).get_request("req_abc")
        self.assertEqual(result.status, "PENDING")

    @patch("agenttrust.client.urlopen")
    def test_delegations(self, send):
        client = AgentTrust("at_live_" + "a" * 64, "http://localhost:8000")

        # Create delegation
        send.return_value = Response({"delegation_id": "delg_123", "status": "active", "action": "payments:transfer"})
        res = client.create_delegation({"parent_agent_id": "agt_p", "child_agent_id": "agt_c"})
        self.assertEqual(res["delegation_id"], "delg_123")

        # List delegations
        send.return_value = Response([{"delegation_id": "delg_123"}])
        delgs = client.list_delegations(parent_agent_id="agt_p")
        self.assertEqual(len(delgs), 1)

        # Get delegation chain
        send.return_value = Response({"delegation_id": "delg_123", "is_valid": True, "chain": []})
        chain = client.get_delegation_chain("delg_123")
        self.assertTrue(chain["is_valid"])

        # Revoke delegation
        send.return_value = Response({"delegation_id": "delg_123", "status": "revoked"})
        rev = client.revoke_delegation("delg_123", "Done")
        self.assertEqual(rev["status"], "revoked")

    def test_validation_and_environment(self):
        with self.assertRaises(ValueError): AgentTrust("")
        with patch.dict(os.environ, {"AGENTTRUST_API_KEY": "at_live_" + "b" * 64}):
            self.assertIsInstance(AgentTrust.from_env(), AgentTrust)


if __name__ == "__main__": unittest.main()
