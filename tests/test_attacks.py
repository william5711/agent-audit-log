"""Week 3 tests: every attack runs end to end, and the harness catches it in every condition."""

import unittest

from attacks import ALL_ATTACKS
from experiments import run_attacks, run_clean


class AttackSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = run_attacks.run(trials=2, seed=123)

    def rows_for(self, condition):
        return [r for r in self.rows if r["condition"] == condition]

    def test_every_attack_ran_in_every_condition(self):
        expected = len(ALL_ATTACKS) * 2 * 2  # attacks x sophistication x trials
        for cond in ("baseline", "harness", "harness_logwrite"):
            self.assertEqual(len(self.rows_for(cond)), expected)

    def test_harness_detects_every_attack(self):
        for cond in ("harness", "harness_logwrite"):
            missed = [(r["attack"], r["sophistication"]) for r in self.rows_for(cond) if not r["detected"]]
            self.assertEqual(missed, [], cond)

    def test_baseline_misses_careful_attacks(self):
        careful = [r for r in self.rows_for("baseline") if r["sophistication"] == "careful"]
        self.assertTrue(careful)
        self.assertFalse(any(r["detected"] for r in careful))

    def test_logwrite_edits_are_caught_by_mac_or_anchor(self):
        for r in self.rows_for("harness_logwrite"):
            if r["sophistication"] == "careful" and r["attack"] in ("A1", "A2", "A3", "A4", "A5"):
                self.assertIn("mac", r["issue_kinds"], r)
            if r["attack"] in ("A2t", "A6"):
                self.assertIn("anchor", r["issue_kinds"], r)


class CleanRunTests(unittest.TestCase):
    def test_no_false_positives(self):
        rows = run_clean.run(runs=5, seed=123)
        self.assertEqual([r for r in rows if r["detected"]], [])


if __name__ == "__main__":
    unittest.main()
