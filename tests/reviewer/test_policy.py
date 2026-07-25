from pathlib import Path
import unittest

from reviewer.policy import RepositoryPolicy, load_policies


POLICY_PATH = Path(__file__).parents[2] / "reviewer" / "policies" / "central.yml"


def pull(**overrides):
    value = {
        "state": "open",
        "draft": False,
        "base": {"ref": "main"},
        "head": {"repo": {"full_name": "KangDohwa/dohwa-hermes-stack"}},
        "labels": [],
    }
    value.update(overrides)
    return value


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policies(POLICY_PATH)["KangDohwa/dohwa-hermes-stack"]

    def test_eligible_pull(self):
        result = self.policy.evaluate(pull(), [{"filename": "tests/test_ok.py", "additions": 3, "patch": "+ok"}])
        self.assertTrue(result.eligible)
        self.assertEqual(result.state, "QUEUED")
        self.assertEqual("1", self.policy.policy_version)

    def test_skip_labels_are_case_insensitive(self):
        result = self.policy.evaluate(
            pull(labels=[{"name": "HeRmEs:SkIp"}]),
            [],
        )
        self.assertFalse(result.eligible)
        self.assertEqual(result.state, "SKIPPED")
        self.assertIn("hermes:skip", result.reason)

    def test_draft_waits(self):
        result = self.policy.evaluate(pull(draft=True), [])
        self.assertFalse(result.eligible)
        self.assertEqual(result.state, "WAITING_READY")

    def test_high_risk_path_needs_human(self):
        result = self.policy.evaluate(pull(), [{"filename": "reviewer/app.py", "additions": 1, "patch": "+ok"}])
        self.assertEqual(result.state, "HUMAN_REVIEW")
        self.assertEqual(result.reason_code, "high_risk_paths")
        self.assertEqual(result.actual, 1)
        self.assertEqual(result.limit, 0)
        self.assertEqual(result.affected_paths, ("reviewer/app.py",))

    def test_file_and_line_limits_include_actual_and_allowed_values(self):
        too_many_files = [
            {"filename": f"safe/{index}.py", "patch": "+ok"}
            for index in range(self.policy.max_files + 1)
        ]
        file_result = self.policy.evaluate(pull(), too_many_files)
        self.assertEqual(file_result.reason_code, "changed_file_limit")
        self.assertEqual(file_result.actual, self.policy.max_files + 1)
        self.assertEqual(file_result.limit, self.policy.max_files)

        line_result = self.policy.evaluate(
            pull(),
            [
                {
                    "filename": "safe/large.py",
                    "additions": self.policy.max_changed_lines,
                    "deletions": 1,
                    "patch": "+ok",
                }
            ],
        )
        self.assertEqual(line_result.reason_code, "changed_line_limit")
        self.assertEqual(line_result.actual, self.policy.max_changed_lines + 1)
        self.assertEqual(line_result.limit, self.policy.max_changed_lines)

    def test_security_infrastructure_and_dependency_paths_need_human(self):
        for path in (
            "Dockerfile.hermes",
            "compose.yaml",
            "hermes_cli/auth.py",
            ".github/CODEOWNERS",
            "requirements.txt",
        ):
            with self.subTest(path=path):
                result = self.policy.evaluate(
                    pull(), [{"filename": path, "additions": 1, "patch": "+ok"}]
                )
                self.assertEqual("HUMAN_REVIEW", result.state)

    def test_high_risk_rename_and_root_migration_need_human(self):
        cases = (
            [{"filename": "safe.yml", "previous_filename": ".github/workflows/ci.yml", "additions": 1, "deletions": 1, "patch": "x"}],
            [{"filename": "migrations/001.sql", "additions": 1, "deletions": 0, "patch": "x"}],
        )
        for files in cases:
            with self.subTest(files=files):
                self.assertEqual("HUMAN_REVIEW", self.policy.evaluate(pull(), files).state)

    def test_missing_patch_fails_closed(self):
        for file in (
            {"filename": "large.py", "additions": 10, "deletions": 0},
            {"filename": "image.png", "additions": 0, "deletions": 0, "changes": 0},
        ):
            with self.subTest(file=file):
                result = self.policy.evaluate(pull(), [file])
                self.assertFalse(result.eligible)
                self.assertIn("diff content unavailable", result.reason)
                self.assertEqual(result.reason_code, "diff_unavailable")
                self.assertEqual(result.actual, 1)
                self.assertEqual(result.limit, 0)
                self.assertEqual(result.affected_paths, (file["filename"],))

    def test_fork_needs_human(self):
        value = pull()
        value["head"] = {"repo": {"full_name": "someone/fork"}}
        result = self.policy.evaluate(value, [])
        self.assertEqual(result.state, "HUMAN_REVIEW")

    def test_writable_test_paths_are_narrow_and_repository_relative(self):
        self.assertEqual((), self.policy.writable_test_paths)

        for invalid in (".", "../data", "/tmp/data"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "repository-relative"):
                    RepositoryPolicy.from_mapping(
                        "example/test-repo",
                        {"writable_test_paths": [invalid]},
                    )

        for invalid in ("data", [123]):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "array of paths"):
                    RepositoryPolicy.from_mapping(
                        "example/test-repo",
                        {"writable_test_paths": invalid},
                    )


if __name__ == "__main__":
    unittest.main()
