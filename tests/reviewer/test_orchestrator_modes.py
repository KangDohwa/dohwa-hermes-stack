import unittest
import sys
from types import ModuleType
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, MagicMock, call


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
                runtime.github.add_labels.assert_not_called()
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
        runtime.github.add_labels.assert_not_called()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.github.squash_merge.assert_not_called()

    async def test_draft_and_auto_changes_required_are_confirmed_draft(self):
        for mode in ("draft", "auto"):
            with self.subTest(mode=mode):
                runtime, job = self._runtime("changes_required", mode=mode)
                pull = self._fresh_pull()
                confirmed = self._fresh_pull()
                confirmed["draft"] = True
                runtime.github.get_pull_request.side_effect = [pull] * 4 + [confirmed]
                runtime.github.add_labels.return_value = [
                    {"name": "hermes:changes-requested"}
                ]
                runtime.github.convert_pull_request_to_draft.return_value = {
                    "id": "PR_node",
                    "isDraft": True,
                }

                await runtime.process_job(job)

                runtime._create_review_once.assert_awaited_once_with(
                    job,
                    body=ANY,
                    event="REQUEST_CHANGES",
                )
                runtime.github.add_labels.assert_called_once_with(
                    REPOSITORY,
                    10,
                    ["hermes:changes-requested"],
                )
                runtime.github.convert_pull_request_to_draft.assert_called_once_with(
                    REPOSITORY,
                    10,
                    pull_request_node_id="PR_node",
                )
                self.assertLess(
                    runtime.github.method_calls.index(
                        call.add_labels(
                            REPOSITORY, 10, ["hermes:changes-requested"]
                        )
                    ),
                    runtime.github.method_calls.index(
                        call.convert_pull_request_to_draft(
                            REPOSITORY, 10, pull_request_node_id="PR_node"
                        )
                    ),
                )
                self.assertTrue(
                    any(
                        call.args[:2] == (job.id, ReviewState.WAITING_READY)
                        for call in runtime.store.transition.call_args_list
                    )
                )
                runtime.github.squash_merge.assert_not_called()

    async def test_failed_tests_downgrade_pass_and_convert_to_draft(self):
        runtime, job = self._runtime("pass", mode="draft")
        pull = self._fresh_pull()
        confirmed = self._fresh_pull()
        confirmed["draft"] = True
        runtime.github.get_pull_request.side_effect = [pull] * 4 + [confirmed]
        runtime._run_tests.return_value = {"tests": [], "all_passed": False}
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }

        await runtime.process_job(job)

        runtime._create_review_once.assert_awaited_once_with(
            job,
            body=ANY,
            event="REQUEST_CHANGES",
        )
        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_called_once()
        runtime.github.squash_merge.assert_not_called()

    async def test_pass_and_human_review_never_convert_or_merge(self):
        for mode, decision in (
            ("draft", "pass"),
            ("draft", "human_review"),
            ("auto", "human_review"),
        ):
            with self.subTest(mode=mode, decision=decision):
                runtime, job = self._runtime(decision, mode=mode)

                await runtime.process_job(job)

                runtime._create_review_once.assert_awaited_once_with(
                    job,
                    body=ANY,
                    event="COMMENT",
                )
                runtime.github.add_labels.assert_not_called()
                runtime.github.convert_pull_request_to_draft.assert_not_called()
                runtime.github.squash_merge.assert_not_called()

    async def test_head_race_stops_before_draft_write(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        initial = self._fresh_pull()
        changed = self._fresh_pull()
        changed["head"] = {
            "sha": "f" * 40,
            "repo": {"full_name": REPOSITORY},
        }
        runtime.github.get_pull_request.side_effect = [initial, initial, changed]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_not_called()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )
        runtime.github.squash_merge.assert_not_called()

    async def test_base_race_stops_before_label_write(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        initial = self._fresh_pull()
        changed = self._fresh_pull()
        changed["base"]["sha"] = "e" * 40
        runtime.github.get_pull_request.side_effect = [initial, initial, changed]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_not_called()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )

    async def test_closed_race_stops_before_draft_write(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        initial = self._fresh_pull()
        closed = self._fresh_pull()
        closed["state"] = "closed"
        runtime.github.get_pull_request.side_effect = [initial, initial, closed]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_not_called()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.CLOSED,
            expected=ReviewState.REVIEWING,
        )
        runtime.github.squash_merge.assert_not_called()

    async def test_head_race_after_label_stops_before_draft_conversion(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        changed = self._fresh_pull()
        changed["head"] = {
            "sha": "f" * 40,
            "repo": {"full_name": REPOSITORY},
        }
        runtime.github.get_pull_request.side_effect = [
            current,
            current,
            current,
            changed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )

    async def test_base_race_after_label_stops_before_draft_conversion(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        changed = self._fresh_pull()
        changed["base"]["sha"] = "e" * 40
        runtime.github.get_pull_request.side_effect = [
            current,
            current,
            current,
            changed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )

    async def test_closed_race_after_label_stops_before_draft_conversion(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        closed = self._fresh_pull()
        closed["state"] = "closed"
        runtime.github.get_pull_request.side_effect = [
            current,
            current,
            current,
            closed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.CLOSED,
            expected=ReviewState.REVIEWING,
        )

    async def test_head_race_after_conversion_is_marked_obsolete(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        changed = self._fresh_pull()
        changed["head"] = {
            "sha": "f" * 40,
            "repo": {"full_name": REPOSITORY},
        }
        runtime.github.get_pull_request.side_effect = [
            current,
            current,
            current,
            current,
            changed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_called_once()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )

    async def test_base_race_after_conversion_is_marked_obsolete(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        changed = self._fresh_pull()
        changed["base"]["sha"] = "e" * 40
        runtime.github.get_pull_request.side_effect = [
            current,
            current,
            current,
            current,
            changed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_called_once()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )

    async def test_closed_race_after_conversion_is_terminal(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        closed = self._fresh_pull()
        closed["state"] = "closed"
        runtime.github.get_pull_request.side_effect = [
            current,
            current,
            current,
            current,
            closed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_called_once()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.CLOSED,
            expected=ReviewState.REVIEWING,
        )

    async def test_conversion_response_without_persisted_draft_fails_closed(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        current = self._fresh_pull()
        runtime.github.get_pull_request.side_effect = [current] * 5
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }

        with self.assertRaisesRegex(RuntimeError, "did not persist"):
            await runtime.process_job(job)

        runtime.store.transition.assert_not_called()

    async def test_already_draft_race_does_not_repeat_write(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        initial = self._fresh_pull()
        already_draft = self._fresh_pull()
        already_draft["draft"] = True
        runtime.github.get_pull_request.side_effect = [
            initial,
            initial,
            already_draft,
            already_draft,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once_with(
            REPOSITORY,
            10,
            ["hermes:changes-requested"],
        )
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.WAITING_READY,
            expected=ReviewState.REVIEWING,
            review_decision="changes_required",
            findings_hash=ANY,
            github_review_id=7,
        )
        runtime.github.squash_merge.assert_not_called()

    async def test_unconfirmed_draft_conversion_fails_without_terminal_state(self):
        for converted in ({}, {"id": "PR_node", "isDraft": False}):
            with self.subTest(converted=converted):
                runtime, job = self._runtime("changes_required", mode="draft")
                pull = self._fresh_pull()
                runtime.github.get_pull_request.side_effect = [pull] * 4
                runtime.github.add_labels.return_value = [
                    {"name": "hermes:changes-requested"}
                ]
                runtime.github.convert_pull_request_to_draft.return_value = converted

                with self.assertRaisesRegex(RuntimeError, "did not confirm"):
                    await runtime.process_job(job)

                runtime.store.transition.assert_not_called()
                runtime.github.squash_merge.assert_not_called()

    async def test_unconfirmed_changes_requested_label_stops_before_draft(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        pull = self._fresh_pull()
        runtime.github.get_pull_request.side_effect = [pull] * 3
        runtime.github.add_labels.return_value = [{"name": "other-label"}]

        with self.assertRaisesRegex(RuntimeError, "changes-requested label"):
            await runtime.process_job(job)

        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.store.transition.assert_not_called()
        runtime.github.squash_merge.assert_not_called()

    async def test_converted_webhook_cas_race_converges_on_waiting_ready(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        pull = self._fresh_pull()
        confirmed = self._fresh_pull()
        confirmed["draft"] = True
        runtime.github.get_pull_request.side_effect = [pull] * 4 + [confirmed]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }
        runtime.store.transition.side_effect = [
            RuntimeError("job 10 is WAITING_READY, expected REVIEWING"),
            SimpleNamespace(state=ReviewState.WAITING_READY),
        ]
        runtime.store.get_job_by_id.return_value = SimpleNamespace(
            state=ReviewState.WAITING_READY
        )

        await runtime.process_job(job)

        runtime.store.get_job_by_id.assert_called_once_with(job.id)
        self.assertEqual(
            [
                call(
                    job.id,
                    ReviewState.WAITING_READY,
                    expected=ReviewState.REVIEWING,
                    review_decision="changes_required",
                    findings_hash=ANY,
                    github_review_id=7,
                ),
                call(
                    job.id,
                    ReviewState.WAITING_READY,
                    expected=ReviewState.WAITING_READY,
                    review_decision="changes_required",
                    findings_hash=ANY,
                    github_review_id=7,
                ),
            ],
            runtime.store.transition.call_args_list,
        )
        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_called_once()
        runtime.github.squash_merge.assert_not_called()

    async def test_draft_cas_race_with_other_state_fails_closed(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        pull = self._fresh_pull()
        confirmed = self._fresh_pull()
        confirmed["draft"] = True
        runtime.github.get_pull_request.side_effect = [pull] * 4 + [confirmed]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]
        runtime.github.convert_pull_request_to_draft.return_value = {
            "id": "PR_node",
            "isDraft": True,
        }
        runtime.store.transition.side_effect = RuntimeError("CAS state changed")
        runtime.store.get_job_by_id.return_value = SimpleNamespace(
            state=ReviewState.HUMAN_REVIEW
        )

        with self.assertRaisesRegex(RuntimeError, "CAS state changed"):
            await runtime.process_job(job)

        runtime.store.get_job_by_id.assert_called_once_with(job.id)
        runtime.github.squash_merge.assert_not_called()

    @staticmethod
    def _fresh_pull() -> dict:
        return {
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
        if mode == "comment":
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
