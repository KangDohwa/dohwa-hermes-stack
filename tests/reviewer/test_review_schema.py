import json
import unittest

from reviewer.review_schema import ReviewDecision, ReviewResult, parse_review_output


SHA = "a" * 40


class ReviewSchemaTests(unittest.TestCase):
    def valid(self):
        return {
            "decision": "pass",
            "reviewed_head_sha": SHA,
            "summary": "No blocking issues.",
            "findings": [],
            "tests": [{"command": "python -m unittest", "result": "passed", "detail": ""}],
            "confidence": "high",
        }

    def test_parses_strict_json(self):
        result = parse_review_output(json.dumps(self.valid()))
        self.assertEqual(result.decision, ReviewDecision.PASS)
        self.assertEqual(result.reviewed_head_sha, SHA)

    def test_rejects_low_confidence_pass(self):
        value = self.valid()
        value["confidence"] = "low"
        with self.assertRaisesRegex(ValueError, "low confidence"):
            ReviewResult.from_dict(value)

    def test_rejects_blocking_finding_on_pass(self):
        value = self.valid()
        value["findings"] = [{
            "severity": "P1",
            "path": "app.py",
            "line": 1,
            "title": "Bug",
            "evidence": "This fails.",
            "recommendation": "Fix it.",
        }]
        with self.assertRaisesRegex(ValueError, "blocking"):
            ReviewResult.from_dict(value)

    def test_rejects_path_traversal(self):
        value = self.valid()
        value["decision"] = "changes_required"
        value["findings"] = [{
            "severity": "P2",
            "path": "../secret",
            "line": 1,
            "title": "Bad path",
            "evidence": "Bad.",
            "recommendation": "Fix.",
        }]
        with self.assertRaisesRegex(ValueError, "repository-relative"):
            ReviewResult.from_dict(value)


if __name__ == "__main__":
    unittest.main()
