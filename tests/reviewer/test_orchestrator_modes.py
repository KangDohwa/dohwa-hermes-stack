import asyncio
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

from reviewer.models import ReviewJob, ReviewState, WebhookEvent
from reviewer.approval_runtime import ApprovalReconciliationPending
from reviewer.discord_reporter import COMPACT_SUMMARY_UNITS, _discord_units
from reviewer.orchestrator import ReviewerRuntime, _policy_exclusion_summary
from reviewer.policy import Eligibility, RepositoryPolicy
from reviewer.review_publisher import ReviewPublishUnknown


REPOSITORY = "example/example-repo"
HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40


class CommentModeTests(unittest.IsolatedAsyncioTestCase):
    async def test_bootstrap_delivery_identity_includes_base_context(self):
        runtime, _ = self._runtime("pass")
        first = self._fresh_pull()
        rebased = self._fresh_pull()
        first["number"] = 10
        rebased["number"] = 10
        rebased["base"]["sha"] = "3" * 40
        runtime.settings.repositories = (REPOSITORY,)
        runtime._stop = asyncio.Event()
        runtime.github.list_open_pull_requests.side_effect = [[first], [rebased]]

        await runtime._bootstrap_open_pulls()
        await runtime._bootstrap_open_pulls()

        events = [entry.args[0] for entry in runtime.store.ingest.call_args_list]
        self.assertEqual(2, len(events))
        self.assertNotEqual(events[0].delivery_id, events[1].delivery_id)
        self.assertIn(BASE_SHA, events[0].delivery_id)
        self.assertIn("3" * 40, events[1].delivery_id)
        self.assertEqual([1, 1], [item.repository_id for item in events])

    async def test_bootstrap_reconciles_same_snapshot_on_each_run(self):
        runtime, _ = self._runtime("pass")
        pull = self._fresh_pull()
        pull["number"] = 10
        runtime.settings.repositories = (REPOSITORY,)
        runtime._stop = asyncio.Event()
        runtime.github.list_open_pull_requests.return_value = [pull]

        await runtime._bootstrap_open_pulls()
        await runtime._bootstrap_open_pulls()

        events = [entry.args[0] for entry in runtime.store.ingest.call_args_list]
        self.assertEqual(2, len(events))
        self.assertNotEqual(events[0].delivery_id, events[1].delivery_id)
        self.assertEqual(
            ["bootstrap_reconcile", "bootstrap_reconcile"],
            [item.action for item in events],
        )

    async def test_approval_label_is_queued_without_general_ingest(self):
        runtime, _ = self._runtime("pass", mode="draft")
        event = self._approval_label_event()

        await runtime.ingest_webhook(event)

        runtime.approval_runtime.enqueue_label_event.assert_called_once_with(
            event,
            policy=runtime.policies[REPOSITORY],
        )
        runtime.approval_runtime.process_reconciliation_row.assert_not_called()
        runtime.store.ingest.assert_not_called()

    async def test_approval_enqueue_failure_leaves_general_delivery_unrecorded(self):
        runtime, _ = self._runtime("pass", mode="draft")
        event = self._approval_label_event()
        runtime.approval_runtime.enqueue_label_event.side_effect = RuntimeError(
            "durable inbox unavailable"
        )

        with self.assertRaisesRegex(RuntimeError, "inbox unavailable"):
            await runtime.ingest_webhook(event)

        runtime.store.ingest.assert_not_called()

    async def test_comment_mode_does_not_enable_approval_adapter(self):
        runtime, _ = self._runtime("pass", mode="comment")
        event = self._approval_label_event()

        await runtime.ingest_webhook(event)

        runtime.approval_runtime.enqueue_label_event.assert_not_called()
        runtime.store.ingest.assert_called_once_with(event)

    async def test_comment_mode_terminalizes_expired_pending_row(self):
        runtime, _ = self._runtime("pass", mode="comment")
        row = {
            "id": 11,
            "repository": REPOSITORY,
            "claimed_at": "2026-07-25T01:00:00+00:00",
            "attempt_count": 1,
        }
        runtime._stop = asyncio.Event()
        runtime.store.claim_next_approval_reconciliation.return_value = row
        runtime.approval_runtime.reconciliation_deadline_expired.return_value = True
        runtime.approval_runtime.reject_reconciliation_after_error.side_effect = (
            lambda *_args, **_kwargs: runtime._stop.set()
        )

        await runtime._approval_reconciliation_loop()

        runtime.store.claim_next_approval_reconciliation.assert_called_once_with()
        runtime.approval_runtime.process_reconciliation_row.assert_not_called()
        runtime.approval_runtime.reject_reconciliation_after_error.assert_called_once_with(
            row
        )
        runtime.store.retry_approval_reconciliation.assert_not_called()
        runtime.store.complete_approval_reconciliation.assert_not_called()

    async def test_reconciliation_worker_retries_pending_row(self):
        runtime, _ = self._runtime("pass", mode="draft")
        row = {
            "id": 12,
            "repository": REPOSITORY,
            "claimed_at": "2026-07-25T01:00:01+00:00",
            "attempt_count": 1,
        }
        runtime._stop = asyncio.Event()
        runtime.store.claim_next_approval_reconciliation.return_value = row
        runtime.approval_runtime.process_reconciliation_row.side_effect = (
            ApprovalReconciliationPending("timeline visibility pending")
        )
        runtime.approval_runtime.reconciliation_deadline_expired.return_value = False
        runtime.store.retry_approval_reconciliation.side_effect = (
            lambda *_args, **_kwargs: runtime._stop.set()
        )

        await runtime._approval_reconciliation_loop()

        runtime.approval_runtime.process_reconciliation_row.assert_called_once_with(
            row,
            policy=runtime.policies[REPOSITORY],
        )
        runtime.store.retry_approval_reconciliation.assert_called_once_with(
            12,
            "ApprovalReconciliationPending: timeline visibility pending",
            claimed_at="2026-07-25T01:00:01+00:00",
            attempt_count=1,
        )
        runtime.store.complete_approval_reconciliation.assert_not_called()

    async def test_reconciliation_worker_completes_visible_row(self):
        runtime, _ = self._runtime("pass", mode="draft")
        row = {
            "id": 13,
            "repository": REPOSITORY,
            "claimed_at": "2026-07-25T01:00:02+00:00",
            "attempt_count": 2,
        }
        runtime._stop = asyncio.Event()
        runtime.store.claim_next_approval_reconciliation.return_value = row
        runtime.approval_runtime.process_reconciliation_row.return_value = object()
        runtime.store.complete_approval_reconciliation.side_effect = (
            lambda *_args, **_kwargs: runtime._stop.set()
        )

        await runtime._approval_reconciliation_loop()

        runtime.approval_runtime.process_reconciliation_row.assert_called_once_with(
            row,
            policy=runtime.policies[REPOSITORY],
        )
        runtime.store.complete_approval_reconciliation.assert_called_once_with(
            13,
            claimed_at="2026-07-25T01:00:02+00:00",
            attempt_count=2,
        )
        runtime.store.retry_approval_reconciliation.assert_not_called()

    async def test_stop_waits_for_reconciliation_before_closing_store(self):
        runtime, _ = self._runtime("pass", mode="draft")
        runtime._stop = asyncio.Event()
        runtime._worker = None
        runtime._reconciler = None
        runtime._bootstrapper = None
        runtime._approval_outbox_sender = None
        started = asyncio.Event()
        release = asyncio.Event()
        order = []

        async def reconciliation_worker():
            started.set()
            await release.wait()
            order.append("reconciliation-complete")

        runtime._approval_reconciliation_worker = asyncio.create_task(
            reconciliation_worker()
        )
        runtime.store.close.side_effect = lambda: order.append("store-close")
        await started.wait()

        stopping = asyncio.create_task(runtime.stop())
        await asyncio.sleep(0)

        self.assertFalse(stopping.done())
        self.assertFalse(runtime._approval_reconciliation_worker.cancelled())
        runtime.store.close.assert_not_called()

        release.set()
        await stopping

        self.assertEqual(
            ["reconciliation-complete", "store-close"],
            order,
        )
        runtime.store.close.assert_called_once_with()

    def test_policy_report_keeps_required_action_before_bounded_path_evidence(self):
        paths = tuple(
            f"reviewer/{index}-" + "😀" * 500 + "\n@everyone"
            for index in range(8)
        )
        summary = _policy_exclusion_summary(
            Eligibility(
                False,
                "HUMAN_REVIEW",
                "high-risk paths changed",
                reason_code="high_risk_paths",
                actual=len(paths),
                limit=0,
                affected_paths=paths,
            ),
            analyzer_ran=False,
        )

        required, evidence = summary.split("\n근거 경로: ", 1)
        self.assertLessEqual(_discord_units(required), COMPACT_SUMMARY_UNITS)
        self.assertLess(_discord_units(summary), 2_000)
        self.assertIn("필요 조치:", required)
        self.assertIn("Hermes analyzer: 호출하지 않음", required)
        self.assertIn("외 3개", evidence)
        self.assertNotIn("\n", evidence)

    async def test_line_limit_report_has_values_analyzer_status_and_action(self):
        runtime, job = self._runtime("pass")
        files = [
            {
                "filename": "safe/large.py",
                "additions": 3_001,
                "deletions": 0,
                "patch": "+ok",
            }
        ]
        runtime.github.list_pull_request_files.side_effect = [files]

        await runtime.process_job(job)

        runtime._dispatch.assert_not_awaited()
        runtime._run_tests.assert_not_awaited()
        runtime._report.assert_awaited_once()
        report = runtime._report.await_args
        self.assertEqual(report.args[:2], (job, "자동 검토 제외"))
        summary = report.args[2]
        self.assertIn("변경 줄 3,001줄 / 3,000줄", summary)
        self.assertIn("Hermes analyzer: 호출하지 않음", summary)
        self.assertIn("모델 사용량 없음", summary)
        self.assertIn("필요 조치:", summary)
        self.assertIn("PR을 변경 줄 수 한도 이하로 분할", summary)
        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
            review_decision="human_review",
            last_error="changed line limit exceeded",
        )

    async def test_policy_change_after_analysis_reports_result_not_applied(self):
        runtime, job = self._runtime("pass")
        safe_files = [
            {
                "filename": "safe/change.py",
                "additions": 1,
                "deletions": 0,
                "patch": "+ok",
            }
        ]
        risky_files = [
            {
                "filename": "reviewer/orchestrator.py",
                "additions": 1,
                "deletions": 0,
                "patch": "+changed",
            }
        ]
        runtime.github.list_pull_request_files.side_effect = [
            safe_files,
            risky_files,
        ]
        runtime.policies[REPOSITORY] = RepositoryPolicy(
            full_name=REPOSITORY,
            base_branches=("main",),
            merge_method="squash",
            max_files=50,
            max_changed_lines=3_000,
            timeout_minutes=20,
            high_risk_paths=("reviewer/**",),
            skip_labels=(),
            test_commands=(),
            required_checks=(),
            writable_test_paths=(),
        )

        await runtime.process_job(job)

        runtime._dispatch.assert_awaited_once()
        runtime._run_tests.assert_awaited_once()
        self.assertEqual(runtime._report.await_count, 2)
        report = runtime._report.await_args
        self.assertEqual(report.args[:2], (job, "자동 검토 제외"))
        summary = report.args[2]
        self.assertIn("고위험 경로 1개 / 0개", summary)
        self.assertIn("Hermes analyzer: 이미 실행됨", summary)
        self.assertIn("현재 상태에는 분석 결과를 적용하지 않음", summary)
        self.assertIn("근거 경로: reviewer/orchestrator.py", summary)

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

    async def test_comment_review_body_is_bound_to_exact_schema_three_context(self):
        runtime, job = self._runtime("human_review")

        await runtime.process_job(job)

        body = runtime._create_review_once.await_args.kwargs["body"]
        marker = body.splitlines()[0]
        self.assertIn("repo=example/example-repo", marker)
        self.assertIn("repo_id=1", marker)
        self.assertIn(f"base={BASE_SHA}", marker)
        self.assertIn(f"head={HEAD_SHA}", marker)
        self.assertIn("diff=", marker)
        self.assertIn("policy=1", marker)
        self.assertIn("decision=human_review", marker)
        self.assertTrue(marker.endswith("schema=3 -->"))

    async def test_recreated_repository_identity_stops_before_analysis_or_write(self):
        runtime, job = self._runtime("pass", mode="draft")
        replaced = self._fresh_pull()
        replaced["base"]["repo"]["id"] = 777
        runtime.github.get_pull_request.side_effect = [replaced]

        with self.assertRaisesRegex(RuntimeError, "identity changed"):
            await runtime.process_job(job)

        runtime._dispatch.assert_not_awaited()
        runtime._create_review_once.assert_not_awaited()
        runtime.github.add_labels.assert_not_called()
        runtime.github.convert_pull_request_to_draft.assert_not_called()

    async def test_comment_review_does_not_dismiss_stale_bot_block(self):
        runtime, job = self._runtime("human_review")
        marker = (
            "<!-- dohwa-bot-review repo=example/example-repo repo_id=1 pr=10 "
            f"base={BASE_SHA} head={HEAD_SHA} diff={'d' * 64} "
            "policy=1 decision=human_review schema=3 -->"
        )
        stale = {
            "id": 6,
            "body": "<!-- stale -->",
            "state": "CHANGES_REQUESTED",
            "commit_id": HEAD_SHA,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        created = {
            "id": 7,
            "body": marker + "\nreview",
            "state": "COMMENTED",
            "commit_id": HEAD_SHA,
            "submitted_at": "2026-07-25T00:01:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        runtime.github.list_pull_request_reviews.return_value = [stale]
        runtime.github.create_review.return_value = created

        result = await ReviewerRuntime._create_review_once(
            runtime,
            job,
            body=marker + "\nreview",
            event="COMMENT",
        )

        self.assertEqual(created, result)
        runtime.github.dismiss_review.assert_not_called()

    async def test_blocking_review_dismisses_stale_block_after_replacement(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        marker = (
            "<!-- dohwa-bot-review repo=example/example-repo repo_id=1 pr=10 "
            f"base={BASE_SHA} head={HEAD_SHA} diff={'d' * 64} "
            "policy=1 decision=changes_required schema=3 -->"
        )
        stale = {
            "id": 6,
            "body": "<!-- stale -->",
            "state": "CHANGES_REQUESTED",
            "commit_id": HEAD_SHA,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        created = {
            "id": 7,
            "body": marker + "\nreview",
            "state": "CHANGES_REQUESTED",
            "commit_id": HEAD_SHA,
            "submitted_at": "2026-07-25T00:01:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        runtime.github.list_pull_request_reviews.return_value = [stale]
        runtime.github.create_review.return_value = created

        result = await ReviewerRuntime._create_review_once(
            runtime,
            job,
            body=marker + "\nreview",
            event="REQUEST_CHANGES",
        )

        self.assertEqual(created, result)
        runtime.github.dismiss_review.assert_called_once_with(
            REPOSITORY,
            10,
            6,
            message="Superseded by a new exact review context.",
        )

    async def test_failed_blocking_replacement_keeps_stale_block(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        marker = (
            "<!-- dohwa-bot-review repo=example/example-repo repo_id=1 pr=10 "
            f"base={BASE_SHA} head={HEAD_SHA} diff={'d' * 64} "
            "policy=1 decision=changes_required schema=3 -->"
        )
        stale = {
            "id": 6,
            "body": "<!-- stale -->",
            "state": "CHANGES_REQUESTED",
            "commit_id": HEAD_SHA,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        runtime.github.list_pull_request_reviews.side_effect = [[stale], [stale]]
        runtime.github.create_review.return_value = {}

        with self.assertRaises(ReviewPublishUnknown):
            await ReviewerRuntime._create_review_once(
                runtime,
                job,
                body=marker + "\nreview",
                event="REQUEST_CHANGES",
            )

        runtime.github.dismiss_review.assert_not_called()

    async def test_ambiguous_review_post_reconciles_visible_exact_review(self):
        runtime, job = self._runtime("changes_required", mode="draft")
        marker = (
            "<!-- dohwa-bot-review repo=example/example-repo repo_id=1 pr=10 "
            f"base={BASE_SHA} head={HEAD_SHA} diff={'d' * 64} "
            "policy=1 decision=changes_required schema=3 -->"
        )
        created = {
            "id": 7,
            "body": marker + "\nreview",
            "state": "CHANGES_REQUESTED",
            "commit_id": HEAD_SHA,
            "submitted_at": "2026-07-25T00:01:00Z",
            "user": {"login": "example-reviewer[bot]", "type": "Bot"},
        }
        runtime.store.begin_review_publication.return_value = True
        runtime.github.list_pull_request_reviews.side_effect = [[], [created]]
        runtime.github.create_review.side_effect = TimeoutError("response lost")

        result = await ReviewerRuntime._create_review_once(
            runtime,
            job,
            body=marker + "\nreview",
            event="REQUEST_CHANGES",
        )

        self.assertEqual(created, result)
        runtime.store.confirm_review_publication.assert_called_with(
            job_id=job.id,
            marker=marker,
            event="REQUEST_CHANGES",
            github_review_id=7,
        )

    async def test_unresolved_review_post_is_fenced_from_repost(self):
        runtime, job = self._runtime("human_review")
        marker = (
            "<!-- dohwa-bot-review repo=example/example-repo repo_id=1 pr=10 "
            f"base={BASE_SHA} head={HEAD_SHA} diff={'d' * 64} "
            "policy=1 decision=human_review schema=3 -->"
        )
        runtime.store.begin_review_publication.side_effect = [True, False]
        runtime.github.list_pull_request_reviews.return_value = []
        runtime.github.create_review.side_effect = TimeoutError("response lost")

        with self.assertRaises(ReviewPublishUnknown):
            await ReviewerRuntime._create_review_once(
                runtime,
                job,
                body=marker + "\nreview",
                event="COMMENT",
            )
        with self.assertRaises(ReviewPublishUnknown):
            await ReviewerRuntime._create_review_once(
                runtime,
                job,
                body=marker + "\nreview",
                event="COMMENT",
            )

        runtime.github.create_review.assert_called_once()

    async def test_closed_after_analysis_is_recorded_terminal(self):
        runtime, job = self._runtime("human_review")
        initial = self._fresh_pull()
        closed = self._fresh_pull()
        closed["state"] = "closed"
        runtime.github.get_pull_request.side_effect = [initial, closed]

        await runtime.process_job(job)

        runtime.store.transition.assert_called_once_with(
            job.id,
            ReviewState.CLOSED,
            expected=ReviewState.REVIEWING,
            merge_sha=None,
        )
        runtime._create_review_once.assert_not_awaited()

    async def test_auto_pass_waits_for_exact_context_approval(self):
        runtime, job = self._runtime("pass", mode="auto")

        await runtime.process_job(job)

        runtime._create_review_once.assert_not_awaited()
        runtime.approval_runtime.publish_pass_review.assert_called_once_with(
            job,
            pull=ANY,
            diff=ANY,
            body=ANY,
            findings_hash=ANY,
            policy=runtime.policies[REPOSITORY],
        )
        runtime.store.transition.assert_not_called()
        self.assertEqual(
            "명시적 승인 대기",
            runtime._report.await_args.args[1],
        )
        self.assertIn(
            "hermes:merge-approved",
            runtime._report.await_args.args[2],
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
                runtime.github.get_pull_request.side_effect = [pull] * 5 + [confirmed]
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
        runtime.github.get_pull_request.side_effect = [pull] * 5 + [confirmed]
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

                if decision == "pass":
                    runtime._create_review_once.assert_not_awaited()
                    runtime.approval_runtime.publish_pass_review.assert_called_once()
                else:
                    runtime._create_review_once.assert_awaited_once_with(
                        job,
                        body=ANY,
                        event="COMMENT",
                    )
                    runtime.approval_runtime.publish_pass_review.assert_not_called()
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
            current,
            changed,
        ]
        runtime.github.add_labels.return_value = [
            {"name": "hermes:changes-requested"}
        ]

        await runtime.process_job(job)

        runtime.github.add_labels.assert_called_once()
        runtime.github.convert_pull_request_to_draft.assert_not_called()
        runtime.github.dismiss_review.assert_called_once_with(
            REPOSITORY,
            10,
            7,
            message="Exact review context changed before Draft enforcement.",
        )
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
        runtime.github.get_pull_request.side_effect = [current] * 6
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
            initial,
            initial,
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
                runtime.github.get_pull_request.side_effect = [pull] * 5
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
        runtime.github.get_pull_request.side_effect = [pull] * 4
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
        runtime.github.get_pull_request.side_effect = [pull] * 5 + [confirmed]
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
        runtime.github.get_pull_request.side_effect = [pull] * 5 + [confirmed]
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
            "base": {
                "ref": "main",
                "sha": BASE_SHA,
                "repo": {"id": 1, "full_name": REPOSITORY},
            },
            "head": {
                "sha": HEAD_SHA,
                "repo": {"full_name": REPOSITORY},
            },
        }

    @staticmethod
    def _approval_label_event() -> WebhookEvent:
        return WebhookEvent(
            delivery_id="delivery-label",
            event_name="pull_request",
            action="labeled",
            repository_id=1,
            repository=REPOSITORY,
            installation_id=99,
            pull_number=10,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            is_draft=False,
            is_merged=False,
            merge_sha=None,
            label_id=1,
            label_node_id="LA_approval",
            label_name="hermes:merge-approved",
            sender_id=303,
            sender_node_id="U_303",
            sender_login="approver",
            sender_type="User",
            pull_updated_at="2026-07-25T01:00:00Z",
            payload_sha256="d" * 64,
        )

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
            "base": {
                "ref": "main",
                "sha": BASE_SHA,
                "repo": {"id": 1, "full_name": REPOSITORY},
            },
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
        runtime.approval_runtime = MagicMock()
        runtime.approval_runtime.approval_label = "hermes:merge-approved"
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
        job = ReviewJob(
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
        runtime.approval_runtime.publish_pass_review.return_value = SimpleNamespace(
            job=SimpleNamespace(state=ReviewState.READY_TO_MERGE)
        )
        return runtime, job


if __name__ == "__main__":
    unittest.main()
