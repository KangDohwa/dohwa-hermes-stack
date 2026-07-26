import unittest

from reviewer.approval import new_uuid7
from reviewer.decision import (
    ci_satisfies_policy,
    find_existing_review,
    find_review_attempt_review,
    find_review_context_review,
    format_review,
    has_blocking_human_review,
    parse_review_attempt_marker,
    parse_review_context_marker,
    review_attempt_marker,
    review_context_marker,
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

    def test_schema_two_attempt_marker_is_canonical_and_round_trips(self):
        attempt_id = new_uuid7(timestamp_ms=1, random_bits=2)
        marker = review_attempt_marker(
            "Example/repository", 7, SHA, attempt_id
        )
        parsed = parse_review_attempt_marker(marker)
        self.assertIsNotNone(parsed)
        self.assertEqual("Example/repository", parsed.repository)
        self.assertEqual(7, parsed.pull_number)
        self.assertEqual(SHA, parsed.head_sha)
        self.assertEqual(attempt_id, parsed.review_attempt_id)
        self.assertIsNone(parse_review_attempt_marker(marker + " "))
        self.assertIsNone(
            parse_review_attempt_marker(marker.replace("pr=7", "pr=07"))
        )
        self.assertIsNone(
            parse_review_attempt_marker(marker.replace(SHA, SHA.upper()))
        )

    def test_attempt_reconciliation_requires_exact_trusted_review(self):
        attempt_id = new_uuid7(timestamp_ms=1, random_bits=2)
        marker = review_attempt_marker(
            "Example/repository", 7, SHA, attempt_id
        )
        review = {
            "id": 9,
            "body": "review\n" + marker,
            "state": "COMMENTED",
            "commit_id": SHA,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        self.assertEqual(
            review,
            find_review_attempt_review(
                [review],
                marker,
                event="COMMENT",
                actor="example-reviewer[bot]",
                head_sha=SHA,
            ),
        )
        for field, replacement in (
            ("id", 0),
            ("state", "APPROVED"),
            ("commit_id", "f" * 40),
            ("submitted_at", "2026-07-25T00:00:00.1Z"),
            ("user", {"login": "example-reviewer[bot]", "type": "User"}),
            ("body", "review\n" + marker + "\n" + marker),
        ):
            candidate = dict(review)
            candidate[field] = replacement
            with self.subTest(field=field):
                self.assertIsNone(
                    find_review_attempt_review(
                        [candidate],
                        marker,
                        event="COMMENT",
                        actor="example-reviewer[bot]",
                        head_sha=SHA,
                    )
                )

        with self.assertRaisesRegex(RuntimeError, "multiple GitHub reviews"):
            find_review_attempt_review(
                [review, dict(review, id=10)],
                marker,
                event="COMMENT",
                actor="example-reviewer[bot]",
                head_sha=SHA,
            )

    def test_attempt_reconciliation_allows_exact_context_marker(self):
        attempt_marker = review_attempt_marker(
            "Example/repository", 7, SHA, new_uuid7(timestamp_ms=1, random_bits=2)
        )
        context_marker = review_context_marker(
            "Example/repository",
            42,
            7,
            "b" * 40,
            SHA,
            "d" * 64,
            "17",
            ReviewDecision.PASS,
        )
        review = {
            "id": 9,
            "body": attempt_marker + "\n" + context_marker + "\nreview",
            "state": "COMMENTED",
            "commit_id": SHA,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }

        self.assertEqual(
            review,
            find_review_attempt_review(
                [review],
                attempt_marker,
                event="COMMENT",
                actor="example-reviewer[bot]",
                head_sha=SHA,
            ),
        )

    def test_schema_three_marker_binds_exact_context_and_trusted_review(self):
        marker = review_context_marker(
            "Example/repository",
            42,
            7,
            "b" * 40,
            SHA,
            "d" * 64,
            "17",
            ReviewDecision.CHANGES_REQUIRED,
        )
        parsed = parse_review_context_marker(marker)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(42, parsed.repository_id)
        self.assertEqual("b" * 40, parsed.base_sha)
        self.assertEqual("d" * 64, parsed.diff_sha256)
        self.assertEqual("17", parsed.policy_version)
        review = {
            "id": 11,
            "body": marker + "\nreview",
            "state": "CHANGES_REQUESTED",
            "commit_id": SHA,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        self.assertEqual(
            review,
            find_review_context_review(
                [review],
                marker,
                event="REQUEST_CHANGES",
                actor="example-reviewer[bot]",
                head_sha=SHA,
            ),
        )
        self.assertIsNone(
            find_review_context_review(
                [dict(review, commit_id="f" * 40)],
                marker,
                event="REQUEST_CHANGES",
                actor="example-reviewer[bot]",
                head_sha=SHA,
            )
        )
        self.assertIsNone(
            parse_review_context_marker(marker.replace("base=" + "b" * 40,
                                                       "base=" + "B" * 40))
        )

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
