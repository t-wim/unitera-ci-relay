"""Offline-only tests for the quarantined marketing CI relay contract."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "vm"))
from marketing_ci_contract import (ADMISSION_STATE, RUNNER_LABELS, SOURCE_REPOSITORY,
                                   authorize_execution, reviewed_python_plan, validate_pins)

class MarketingRelayContractTests(unittest.TestCase):
    def test_identifiers(self):
        self.assertEqual(SOURCE_REPOSITORY, "baum777/unitera_marketing_agent-team")
        self.assertEqual(RUNNER_LABELS, ("self-hosted", "Linux", "X64", "unitera-ci", "relay"))

    def test_exact_sha_and_pr(self):
        self.assertTrue(validate_pins("a"*40,"b"*40,"b"*40,"7"))
        for case in (("x","b"*40,"b"*40,"7"),("a"*40,"b"*40,"c"*40,"7"),
                     ("a"*40,"b"*40,"b"*40,"0"),("a"*40,"b"*40,"b"*40,"7;true")):
            with self.assertRaises(ValueError):
                validate_pins(*case)

    def test_fixed_offline_commands(self):
        plan=reviewed_python_plan()
        self.assertEqual(len(plan),3)
        self.assertEqual(plan[0][2],("python3","scripts/validate.py"))
        self.assertEqual(plan[1][2],("python3","-m","unittest","discover","-s","tests","-v"))
        self.assertEqual(plan[2][2],("python3","-m","compileall","-q","scripts","tests"))
        for name,timeout,argv in plan:
            self.assertTrue(name.startswith("marketing_"))
            self.assertGreater(timeout,0)
            self.assertNotIn("-c",argv)
            self.assertNotIn("openrouter_pilot.py"," ".join(argv))

    def test_quarantine_cannot_be_self_approved(self):
        self.assertEqual(ADMISSION_STATE,"QUARANTINED")
        with self.assertRaisesRegex(PermissionError,"MARKETING_CI_QUARANTINED"):
            authorize_execution(qualified=True,owner_approval=True)

if __name__ == "__main__":
    unittest.main()
