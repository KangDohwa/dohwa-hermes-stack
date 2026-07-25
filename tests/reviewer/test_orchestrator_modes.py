import unittest
import sys
from types import ModuleType
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, MagicMock


try:
    import fastapi  # noqa: F401
except ModuleNotFoundError:
    fastapi_stub = ModuleType("fastapi")

    class _FastAPI:
        def __init__(self, *_args, **_kwargs):
            self.state = SimpleNamespace()

        def get(self, *_args, **_kwargs):
            return lambda function: function

        def post(self, *_args, **_kwargs):
            return lambda function: function

    fastapi_stub.FastAPI = _FastAPI
    fastapi_stub.HTTPException = type("HTTPException", (Exception,), {})
    fastapi_stub.Request = object
    fastapi_stub.Response = object
    sys.modules["fastapi"] = fastapi_stub

from reviewer.models import ReviewJob, ReviewState
from reviewer.orchestrator import ReviewerRuntime
from reviewer.policy import RepositoryPolicy


REPOSITORY = "example/example-repo"
HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40


class CommentModeTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_decision_only_creates_comment_review(self):
        for decision, expected_state in (
            ("pass", ReviewState.HUMAN_REVIEW),
            ("changes_required", ReviewState.CHANGES_REQUIRED),
            ("human_review", ReviewState.HUMAN_REVIEW),
        ):
            with self.subTest(decision=decision):
                runtime, job = self._runtime(decision)

                await runtime.process_job(job)

                runtime._create_review_once.assert_awaited_once_with(
                    job,
                    body=ANY,
                    event="COMMENT",
                )
                self.assertTrue(
                    any(
                        call.args[:2] == (job.id, expected_state)
                        for call in runtime.store.transition.call_args_list
                    )
                )
                runtime.github.convert_pull_request_to_draft.assert_not_called()
                runtime.github.squash_merge.assert_not_called()

    async def test_auto_pass_is_blocked_without_atomic_backend(self):
        runtime, job = self._runtime("pass", mode="auto")

        await runtime.process_job(job)

        runtime._create_review_once.assert_awaited_once_with(
            job,
            body=ANY,
            event="COMMENT",
        )
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
            review_decision="pass",
            findings_hash=ANY,
            github_review_id=7,
            last_error="ATOMIC_SERVER_GATES_UNAVAILABLE",
        )
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.github.squash_merge.assert_not_called()

    def _runtime(
        self, decision: str, *, mode: str = "comment"
    ) -> tuple[ReviewerRuntime, ReviewJob]:
        pull = {
            "state": "open",
            "draft": False,
            "title": "Comment mode canary",
            "html_url": "https://github.com/example/example-repo/pull/10",
            "node_id": "PR_node",
            "labels": [],
            "base": {"ref": "main", "sha": BASE_SHA},
            "head": {
                "sha": HEAD_SHA,
                "repo": {"full_name": REPOSITORY},
            },
        }
        files = [
            {
                "filename": "canary/comment-mode.md",
                "additions": 1,
                "deletions": 0,
                "patch": "@@ -0,0 +1 @@\n+canary",
            }
        ]
        diff = "diff --git a/canary/comment-mode.md b/canary/comment-mode.md"
        github = MagicMock()
        github.get_pull_request.side_effect = [pull, pull]
        github.list_pull_request_files.side_effect = [files, files]
        github.get_pull_request_diff.side_effect = [diff, diff]
        github.convert_pull_request_to_draft.side_effect = AssertionError(
            "comment mode must not convert a pull request to draft"
        )
        github.squash_merge.side_effect = AssertionError(
            "comment mode must not merge a pull request"
        )

        runtime = object.__new__(ReviewerRuntime)
        runtime.settings = SimpleNamespace(mode=mode, app_slug="example-reviewer")
        runtime.github = github
        runtime.store = MagicMock()
        runtime.policies = {
            REPOSITORY: RepositoryPolicy(
                full_name=REPOSITORY,
                base_branches=("main",),
                merge_method="squash",
                max_files=50,
                max_changed_lines=3_000,
                timeout_minutes=20,
                high_risk_paths=(),
                skip_labels=(),
                test_commands=(),
                required_checks=(),
                writable_test_paths=(),
            )
        }
        runtime._dispatch = AsyncMock(
            return_value={
                "ok": True,
                "result": {
                    "decision": decision,
                    "reviewed_head_sha": HEAD_SHA,
                    "summary": f"{decision} result",
                    "findings": [],
                    "tests": [],
                    "confidence": "high",
                },
            }
        )
        runtime._run_tests = AsyncMock(return_value={"tests": [], "all_passed": True})
        runtime._report = AsyncMock(return_value=True)
        runtime._create_review_once = AsyncMock(return_value={"id": 7})
        return runtime, ReviewJob(
            id=10,
            repository_id=1,
            repository=REPOSITORY,
            pull_number=10,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            state=ReviewState.REVIEWING,
            queued_at=None,
            started_at=None,
            finished_at=None,
            attempt_count=1,
            review_decision=None,
            findings_hash=None,
            github_review_id=None,
            github_comment_id=None,
            discord_message_id=None,
            discord_thread_id=None,
            merge_sha=None,
            last_error=None,
            retry_at=None,
            created_at="2026-07-24T00:00:00+00:00",
            updated_at="2026-07-24T00:00:00+00:00",
        )


if __name__ == "__main__":
    unittest.main()
