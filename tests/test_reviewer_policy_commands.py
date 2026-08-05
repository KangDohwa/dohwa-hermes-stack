from pathlib import Path
import unittest

from reviewer.policy import load_policies


POLICY_PATH = Path(__file__).parents[1] / "reviewer" / "policies" / "central.yml"
REVIEWER_TEST_COMMAND = (
    "python3",
    "-m",
    "unittest",
    "discover",
    "-s",
    "tests/reviewer",
    "-v",
)


class ReviewerPolicyCommandTests(unittest.TestCase):
    def test_runs_reviewer_test_suite(self):
        policy = load_policies(POLICY_PATH)["KangDohwa/dohwa-hermes-stack"]

        self.assertIn(REVIEWER_TEST_COMMAND, policy.test_commands)


if __name__ == "__main__":
    unittest.main()
