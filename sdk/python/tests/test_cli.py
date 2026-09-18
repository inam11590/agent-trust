import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agenttrust.cli import main, cmd_keys_generate, cmd_configure, cmd_doctor


class CLITests(unittest.TestCase):
    def test_help(self):
        with self.assertRaises(SystemExit) as cm:
            with patch("sys.stdout", new=io.StringIO()):
                main(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_keys_generate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = ["keys", "generate", "--output-dir", tmpdir, "--name", "test_agt"]
            buf = io.StringIO()
            with patch("sys.stdout", new=buf):
                exit_code = main(args)
            self.assertEqual(exit_code, 0)
            output = buf.getvalue()
            self.assertIn("Generated Ed25519 keypair successfully", output)
            self.assertIn("key_ag_", output)
            self.assertIn("CRITICAL SECURITY NOTICE", output)

            priv_file = Path(tmpdir) / "test_agt_private.pem"
            pub_file = Path(tmpdir) / "test_agt_public.pem"
            self.assertTrue(priv_file.is_file())
            self.assertTrue(pub_file.is_file())
            self.assertIn("BEGIN PRIVATE KEY", priv_file.read_text())
            self.assertIn("BEGIN PUBLIC KEY", pub_file.read_text())

    def test_configure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_config_file = Path(tmpdir) / "config.json"
            with patch("agenttrust.cli.CONFIG_FILE", test_config_file), \
                 patch("agenttrust.cli.CONFIG_DIR", Path(tmpdir)):
                buf = io.StringIO()
                with patch("sys.stdout", new=buf):
                    exit_code = main(["configure", "--api-key", "at_test_" + "k" * 64, "--base-url", "https://api.test.example"])
                self.assertEqual(exit_code, 0)
                self.assertTrue(test_config_file.is_file())
                data = json.loads(test_config_file.read_text())
                self.assertTrue(data["api_key"].startswith("at_test_"))
                self.assertEqual(data["base_url"], "https://api.test.example")

    def test_doctor_self_test(self):
        buf = io.StringIO()
        with patch("sys.stdout", new=buf):
            exit_code = main(["doctor", "--api-key", "at_test_" + "k" * 64, "--base-url", "http://localhost:8000"])
        self.assertEqual(exit_code, 0)
        output = buf.getvalue()
        self.assertIn("AgentTrust Diagnostics", output)
        self.assertIn("Cryptographic Engine", output)
        self.assertIn("Ed25519 local signing operational", output)


if __name__ == "__main__":
    unittest.main()

