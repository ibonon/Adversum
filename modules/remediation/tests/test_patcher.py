import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from remediation.patcher import AutoPatcher

class TestPatcher(unittest.TestCase):
    def setUp(self):
        self.patcher = AutoPatcher()

    def test_solidity_tx_origin(self):
        finding = {"module": "solidity", "file": "test.sol", "rule_id": "tx.origin"}
        content = "require(tx.origin == owner);"
        patched, diff = self.patcher.generate_patch(finding, content)
        self.assertIn("msg.sender", patched)
        self.assertNotIn("tx.origin", patched)
        self.assertTrue(diff.startswith("--- test.sol"))

    def test_crypto_md5(self):
        finding = {"module": "crypto", "file": "test.py", "rule_id": "md5_used"}
        content = "h = hashlib.md5()"
        patched, diff = self.patcher.generate_patch(finding, content)
        self.assertIn("hashlib.sha256()", patched)

    def test_iac_privileged(self):
        finding = {"module": "iac", "file": "docker-compose.yml", "rule_id": "privileged_container"}
        content = "privileged: true"
        patched, diff = self.patcher.generate_patch(finding, content)
        self.assertIn("privileged: false", patched)

    def test_python_eval(self):
        finding = {"module": "crypto", "file": "test.py", "rule_id": "eval_used"}
        content = "eval('1+1')"
        patched, diff = self.patcher.generate_patch(finding, content)
        self.assertIn("ast.literal_eval('1+1')", patched)
        self.assertIn("import ast", patched)

if __name__ == '__main__':
    unittest.main()
