import os
import sys
import tempfile
import unittest
from pathlib import Path

MODULES_DIR = Path(__file__).resolve().parent.parent.parent
if str(MODULES_DIR) not in sys.path:
    sys.path.insert(0, str(MODULES_DIR))

from heal import AdversumHealer

class TestAdversumHealer(unittest.TestCase):
    def test_healer_init(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            healer = AdversumHealer(tmp_dir)
            self.assertEqual(healer.target_dir, os.path.abspath(tmp_dir))
            self.assertIsNotNone(healer.patcher)
            self.assertIsNotNone(healer.correlation_engine)

    def test_healer_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a vulnerable python file
            test_file = os.path.join(tmp_dir, "test_eval.py")
            with open(test_file, "w") as f:
                f.write("user_in = input()\nres = eval(user_in)\n")

            healer = AdversumHealer(tmp_dir)
            results = healer.heal_project(apply_changes=False, create_git_branch=False, verify=False)
            self.assertIn("scorecard_before", results)
            self.assertIn("healed_files", results)

if __name__ == "__main__":
    unittest.main()
