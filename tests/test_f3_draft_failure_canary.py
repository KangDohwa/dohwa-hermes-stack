import unittest


class F3DraftFailureCanaryTests(unittest.TestCase):
    def test_intentional_failure(self) -> None:
        self.fail("intentional F3 draft-mode failure canary")
