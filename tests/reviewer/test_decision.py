import unittest

from reviewer.decision import (
    ci_satisfies_policy,
    find_existing_review,
    format_review,
    has_blocking_human_review,
)
from reviewer.review_schema import ReviewDecision, ReviewResult


SHA = "0123456789abcdef0123456789abcdef01234567"


class DecisionTests(unittest.TestCase):
    def result(self) -> ReviewResult:
        return ReviewResult.from_dict({
            "decision": "pass", "reviewed_head_sha": SHA, "summary": "model passed",
            "findings": [], "tests": [], "confidence": "high",
        })

    def test_final_decision_is_used_in_marker_and_heading(self):
        body = format_review(
            self.result(),
            {"tests": [{"command": "tests", "result": "failed", "detail": "x"}]},
            decision=ReviewDecision.CHANGES_REQUIRED,
            mode="draft",
        )
        self.assertIn(f"dohwa-bot-review:{SHA}:changes_required", body)
        self.assertIn("결과: `changes_required`", body)
        self.assertNotIn("결과: `pass`", body)

    def test_existing_review_marker_deduplicates_write(self):
        marker = f"<!-- dohwa-bot-review:{SHA}:pass -->"
        existing = {"id": 7, "body": marker + "\nreview", "state": "APPROVED", "user": {"login": "example-reviewer[bot]"}}
        self.assertEqual(existing, find_existing_review([existing], marker, event="APPROVE", actor="example-reviewer[bot]"))
        self.assertIsNone(find_existing_review([existing], marker, event="COMMENT", actor="example-reviewer[bot]"))
        self.assertIsNone(find_existing_review([existing], marker, event="APPROVE", actor="attacker"))
        self.assertIsNone(find_existing_review([], marker, event="APPROVE", actor="example-reviewer[bot]"))

    def test_ci_requires_explicit_named_success(self):
        self.assertFalse(ci_satisfies_policy((), [], {"state": "success"}))
        self.assertFalse(ci_satisfies_policy(("tests",), [], {"state": "success"}))
        self.assertFalse(ci_satisfies_policy(
            ("tests",), [{"name": "tests", "status": "completed", "conclusion": "failure"}], {"state": "success"}
        ))
        self.assertTrue(ci_satisfies_policy(
            ("tests",), [{"name": "tests", "status": "completed", "conclusion": "success"}], {"state": "success", "statuses": []}
        ))
        self.assertFalse(ci_satisfies_policy(
            ("tests",), [
                {"name": "tests", "status": "completed", "conclusion": "success"},
                {"name": "lint", "status": "in_progress", "conclusion": None},
            ], {"state": "success", "statuses": []}
        ))

    def test_latest_human_review_blocks_until_superseded(self):
        app = "example-reviewer[bot]"
        reviews = [
            {"id": 1, "state": "CHANGES_REQUESTED", "user": {"login": "alice"}},
            {"id": 2, "state": "APPROVED", "user": {"login": app}},
        ]
        self.assertTrue(has_blocking_human_review(reviews, app_actor=app))
        reviews.append({"id": 3, "state": "APPROVED", "user": {"login": "alice"}})
        self.assertFalse(has_blocking_human_review(reviews, app_actor=app))


if __name__ == "__main__":
    unittest.main()
