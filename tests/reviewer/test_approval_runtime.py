from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from reviewer.approval import ReviewAttemptStatus
from reviewer.approval_runtime import (
    ApprovalReconciliationPending,
    ApprovalRuntime,
    MAX_REVIEW_BODY_CHARS,
)
from reviewer.decision import parse_review_attempt_marker
from reviewer.github_client import (
    GitHubAPIError,
    GitHubClockDateStatus,
    GitHubClockObservation,
    LabelTimelineEvent,
    LabelTimelineSnapshot,
)
from reviewer.models import ReviewState, WebhookEvent
from reviewer.policy import RepositoryPolicy
from reviewer.review_publisher import ReviewPublishUnknown
from reviewer.state import StateStore


REPOSITORY = "example/example-repo"
REPOSITORY_ID = 42
PULL_NUMBER = 7
BASE_SHA = "b" * 40
HEAD_SHA = "a" * 40
MERGE_BASE_SHA = "c" * 40
ACTOR = "example-reviewer[bot]"
APPROVAL_LABEL = "hermes:merge-approved"


def pull_event(*, repository_id: int | None = None) -> WebhookEvent:
    return WebhookEvent(
        delivery_id="delivery-open",
        event_name="pull_request",
        action="opened",
        repository_id=repository_id,
        repository=REPOSITORY,
        installation_id=99,
        pull_number=PULL_NUMBER,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        is_draft=False,
        is_merged=False,
        merge_sha=None,
    )


def label_event(
    *,
    delivery_id: str = "delivery-label",
    action: str = "labeled",
    sender_id: int = 303,
    sender_login: str = "approver",
    sender_type: str = "User",
    pull_updated_at: str = "2026-07-25T00:10:00Z",
    payload_sha256: str = "d" * 64,
) -> WebhookEvent:
    return WebhookEvent(
        delivery_id=delivery_id,
        event_name="pull_request",
        action=action,
        repository_id=REPOSITORY_ID,
        repository=REPOSITORY,
        installation_id=99,
        pull_number=PULL_NUMBER,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        is_draft=False,
        is_merged=False,
        merge_sha=None,
        label_id=1,
        label_node_id="LA_approval",
        label_name=APPROVAL_LABEL,
        sender_id=sender_id,
        sender_node_id=f"NODE_{sender_id}",
        sender_login=sender_login,
        sender_type=sender_type,
        pull_updated_at=pull_updated_at,
        payload_sha256=payload_sha256,
    )


def reconciliation_row(
    event: WebhookEvent,
    *,
    row_id: int = 1,
    deadline_at: datetime | None = None,
) -> dict[str, object]:
    return {
        "id": row_id,
        "delivery_id": event.delivery_id,
        "event_name": event.event_name,
        "payload_sha256": event.payload_sha256,
        "repository_id": event.repository_id,
        "repository": event.repository,
        "installation_id": event.installation_id,
        "pull_number": event.pull_number,
        "action": event.action,
        "is_draft": event.is_draft,
        "is_merged": event.is_merged,
        "merge_sha": event.merge_sha,
        "label_id": event.label_id,
        "label_node_id": event.label_node_id,
        "label_name": event.label_name,
        "sender_type": event.sender_type,
        "sender_github_user_id": event.sender_id,
        "sender_node_id": event.sender_node_id,
        "sender_login": event.sender_login,
        "signed_base_sha": event.base_sha,
        "signed_head_sha": event.head_sha,
        "pull_updated_at": event.pull_updated_at,
        "expected_policy_version": policy().policy_version,
        "received_at": "2026-07-25T00:10:01+00:00",
        "deadline_at": (
            deadline_at
            or datetime.now(timezone.utc) + timedelta(minutes=1)
        ).isoformat(),
        "claimed_at": "2026-07-25T00:10:01+00:00",
        "attempt_count": 1,
    }


def matching_timeline_event(
    event: WebhookEvent,
    *,
    event_id: str = "LE_label",
    ordinal: int = 1,
    predecessor_event_id: str | None = None,
) -> LabelTimelineEvent:
    return LabelTimelineEvent(
        event_id=event_id,
        action=event.action or "",
        created_at=event.pull_updated_at or "",
        actor_type=event.sender_type,
        actor_node_id=event.sender_node_id,
        actor_database_id=event.sender_id,
        actor_login=event.sender_login,
        label_node_id=event.label_node_id or "",
        label_name=event.label_name or "",
        cursor=f"cursor-{ordinal}",
        ordinal=ordinal,
        predecessor_event_id=predecessor_event_id,
    )


def timeline_snapshot(
    event: WebhookEvent,
    *events: LabelTimelineEvent,
    request_rtt_seconds: float = 0.1,
) -> LabelTimelineSnapshot:
    server_date = datetime.strptime(
        event.pull_updated_at or "", "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    observed_at = time.monotonic()
    return LabelTimelineSnapshot(
        repository_node_id="R_repo",
        repository_database_id=event.repository_id or 0,
        repository=event.repository or "",
        pull_number=event.pull_number or 0,
        timeline_updated_at=event.pull_updated_at or "",
        total_count=len(events),
        events=events,
        clock=GitHubClockObservation(
            response_date=format_datetime(server_date, usegmt=True),
            server_date_epoch_seconds=int(server_date.timestamp()),
            request_started_monotonic=observed_at - request_rtt_seconds,
            response_received_monotonic=observed_at,
            request_rtt_seconds=request_rtt_seconds,
            date_status=GitHubClockDateStatus.VALID,
        ),
    )


def pull(*, labels: tuple[str, ...] = ()) -> dict:
    return {
        "state": "open",
        "draft": False,
        "title": "Approval runtime",
        "html_url": f"https://github.com/{REPOSITORY}/pull/{PULL_NUMBER}",
        "labels": [{"name": label} for label in labels],
        "base": {
            "sha": BASE_SHA,
            "repo": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        },
        "head": {"sha": HEAD_SHA},
    }


def policy() -> RepositoryPolicy:
    return RepositoryPolicy(
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
        policy_version="17",
    )


class FakeGitHub:
    def __init__(self) -> None:
        self.reviews: list[dict] = []
        self.created_bodies: list[str] = []
        self.removed_labels: list[tuple[str, int, str]] = []
        self.remove_error: Exception | None = None
        self.confirmed_pull = pull()
        self.pull_responses: list[dict] = []
        self.timeline = object()
        self.timeline_responses: list[object] = []
        self.timeline_calls = 0

    def list_pull_request_reviews(self, repository: str, pull_number: int):
        return list(self.reviews)

    def create_review(
        self,
        repository: str,
        pull_number: int,
        *,
        body: str,
        event: str,
        commit_id: str | None = None,
    ) -> dict:
        self.created_bodies.append(body)
        review = {
            "id": 501,
            "body": body,
            "state": "COMMENTED",
            "commit_id": commit_id,
            "submitted_at": "2026-07-25T00:00:00Z",
            "user": {"login": ACTOR, "type": "Bot"},
        }
        self.reviews.append(review)
        return review

    def get_merge_base_sha(
        self, repository: str, *, base_sha: str, head_sha: str
    ) -> str:
        if (repository, base_sha, head_sha) != (
            REPOSITORY,
            BASE_SHA,
            HEAD_SHA,
        ):
            raise AssertionError("unexpected merge base identity")
        return MERGE_BASE_SHA

    def remove_label(
        self, repository: str, pull_number: int, label: str
    ) -> list[dict]:
        self.removed_labels.append((repository, pull_number, label))
        if self.remove_error is not None:
            raise self.remove_error
        return []

    def get_pull_request(self, repository: str, pull_number: int) -> dict:
        if self.pull_responses:
            return self.pull_responses.pop(0)
        return self.confirmed_pull

    def list_pull_request_label_timeline(
        self,
        repository: str,
        pull_number: int,
        *,
        should_stop=None,
    ) -> object:
        self.timeline_calls += 1
        if should_stop is not None and should_stop():
            raise GitHubAPIError("timeline reconciliation stopped")
        if self.timeline_responses:
            return self.timeline_responses.pop(0)
        return self.timeline

    def installation_id_for_repository(self, repository: str) -> int:
        return 99


class ApprovalRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.store = StateStore(
            Path(self.temporary_directory.name) / "state.sqlite3"
        )
        job = self.store.ingest(pull_event()).job
        assert job is not None
        self.job = self.store.transition(
            job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        self.github = FakeGitHub()
        self.reporter = MagicMock()
        self.runtime = ApprovalRuntime(
            self.store,
            self.github,
            self.reporter,
            app_actor=ACTOR,
            approver_ids=(303,),
            approval_label=APPROVAL_LABEL,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary_directory.cleanup()

    def test_pass_review_binds_exact_context_and_waits_without_merge(self) -> None:
        publication = self.runtime.publish_pass_review(
            self.job,
            pull=pull(),
            diff="exact diff",
            body="x" * MAX_REVIEW_BODY_CHARS,
            findings_hash="f" * 64,
            policy=policy(),
        )

        self.assertEqual(ReviewState.READY_TO_MERGE, publication.job.state)
        self.assertEqual("EXPLICIT_APPROVAL_REQUIRED", publication.job.last_error)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, publication.attempt.status)
        self.assertEqual(REPOSITORY_ID, publication.job.repository_id)
        context = self.store.get_review_context(publication.attempt.content_id)
        assert context is not None
        self.assertEqual(REPOSITORY_ID, context.value.repository_id)
        self.assertEqual(BASE_SHA, context.value.base_sha)
        self.assertEqual(HEAD_SHA, context.value.head_sha)
        self.assertEqual(MERGE_BASE_SHA, context.value.merge_base_sha)
        self.assertEqual("17", context.value.policy_version)
        self.assertEqual(1, len(self.github.created_bodies))
        review_body = self.github.created_bodies[0]
        self.assertEqual(MAX_REVIEW_BODY_CHARS, len(review_body))
        marker = parse_review_attempt_marker(review_body.splitlines()[0])
        self.assertIsNotNone(marker)
        assert marker is not None
        self.assertEqual(
            publication.attempt.review_attempt_id,
            marker.review_attempt_id,
        )

    def test_stale_label_404_is_accepted_only_after_exact_confirmation(self) -> None:
        self.github.remove_error = GitHubAPIError("not found", status=404)

        self.runtime.publish_pass_review(
            self.job,
            pull=pull(labels=(APPROVAL_LABEL,)),
            diff="exact diff",
            body="review passed",
            findings_hash="f" * 64,
            policy=policy(),
        )

        self.assertEqual(
            [(REPOSITORY, PULL_NUMBER, APPROVAL_LABEL)],
            self.github.removed_labels,
        )

    def test_unresolved_generic_publication_blocks_pass_review(self) -> None:
        bound = self.store.bind_job_repository_id(self.job.id, REPOSITORY_ID)
        self.store.begin_review_publication(
            job_id=bound.id,
            marker="<!-- unresolved-generic-review -->",
            event="REQUEST_CHANGES",
        )

        with self.assertRaises(ReviewPublishUnknown):
            self.runtime.publish_pass_review(
                self.job,
                pull=pull(),
                diff="exact diff",
                body="review passed",
                findings_hash="f" * 64,
                policy=policy(),
            )

        self.assertEqual([], self.github.created_bodies)

    def test_head_race_stops_before_review_publication(self) -> None:
        self.github.confirmed_pull = pull()
        self.github.confirmed_pull["head"] = {"sha": "d" * 40}

        with self.assertRaisesRegex(RuntimeError, "was not confirmed"):
            self.runtime.publish_pass_review(
                self.job,
                pull=pull(),
                diff="exact diff",
                body="review passed",
                findings_hash="f" * 64,
                policy=policy(),
            )

        self.assertEqual([], self.github.created_bodies)

    def test_post_publication_base_race_invalidates_attempt_and_job(self) -> None:
        changed = pull()
        changed["base"]["sha"] = "e" * 40
        self.github.pull_responses = [pull(), changed]

        publication = self.runtime.publish_pass_review(
            self.job,
            pull=pull(),
            diff="exact diff",
            body="review passed",
            findings_hash="f" * 64,
            policy=policy(),
        )

        self.assertEqual(ReviewState.OBSOLETE, publication.job.state)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, publication.attempt.status)
        self.assertEqual(
            "POST_REVIEW_CONTEXT_CHANGED",
            publication.attempt.invalidation_reason,
        )
        self.assertEqual(1, len(self.github.created_bodies))

    def test_target_label_event_is_durably_enqueued_without_github_read(self) -> None:
        event = label_event()

        with patch.object(
            self.store,
            "enqueue_approval_reconciliation",
            return_value=True,
        ) as enqueue:
            result = self.runtime.enqueue_label_event(event, policy=policy())

        self.assertTrue(result)
        enqueue.assert_called_once_with(
            event,
            expected_policy_version="17",
        )
        self.assertEqual(0, self.github.timeline_calls)
        self.assertFalse(self.store.has_delivery(event.delivery_id))

    def test_malformed_signed_label_event_is_not_enqueued(self) -> None:
        event = label_event(payload_sha256="not-a-sha256")

        with patch.object(
            self.store,
            "enqueue_approval_reconciliation",
        ) as enqueue:
            with self.assertRaisesRegex(
                ValueError,
                "complete signed label evidence",
            ):
                self.runtime.enqueue_label_event(event, policy=policy())

        enqueue.assert_not_called()
        self.assertEqual(0, self.github.timeline_calls)

    def test_reconciliation_defers_zero_then_applies_visible_event_once(self) -> None:
        expected = object()
        event = label_event()
        row = reconciliation_row(event)
        row["expected_policy_version"] = "16"
        missing = timeline_snapshot(event)
        visible = timeline_snapshot(event, matching_timeline_event(event))
        self.github.timeline_responses = [missing, visible]

        with patch(
            "reviewer.approval_runtime.process_github_label_approval",
            return_value=expected,
        ) as process:
            with self.assertRaises(ApprovalReconciliationPending):
                self.runtime.process_reconciliation_row(row, policy())
            result = self.runtime.process_reconciliation_row(row, policy())

        self.assertIs(expected, result)
        self.assertEqual(2, self.github.timeline_calls)
        self.assertTrue(self.store.has_delivery(event.delivery_id))
        process.assert_called_once_with(
            self.store,
            snapshot=visible,
            webhook=event,
            allowed_approver_ids=(303,),
            expected_installation_id=99,
            expected_policy_version="17",
            target_label=APPROVAL_LABEL,
            evidence_received_at="2026-07-25T00:10:01+00:00",
            reconciliation_id=1,
            reconciliation_claimed_at="2026-07-25T00:10:01+00:00",
            reconciliation_attempt_count=1,
        )

    def test_reconciliation_archive_does_not_rewind_newer_base_context(self) -> None:
        current_base_sha = "e" * 40
        changed = self.store.ingest(
            replace(
                pull_event(repository_id=REPOSITORY_ID),
                delivery_id="delivery-base-change",
                action="edited",
                base_sha=current_base_sha,
            )
        ).job
        assert changed is not None
        changed = self.store.transition(
            changed.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        changed_pull = pull()
        changed_pull["base"]["sha"] = current_base_sha
        self.github.confirmed_pull = changed_pull
        with patch.object(
            self.github,
            "get_merge_base_sha",
            return_value=MERGE_BASE_SHA,
        ):
            publication = self.runtime.publish_pass_review(
                changed,
                pull=changed_pull,
                diff="exact current diff",
                body="review passed",
                findings_hash="e" * 64,
                policy=policy(),
            )
        event = label_event()
        self.github.timeline = timeline_snapshot(event)

        with self.assertRaises(ApprovalReconciliationPending):
            self.runtime.process_reconciliation_row(
                reconciliation_row(event),
                policy(),
            )

        persisted = self.store.get_job(REPOSITORY, PULL_NUMBER, HEAD_SHA)
        assert persisted is not None
        attempt = self.store.get_review_attempt(
            publication.attempt.review_context_id
        )
        assert attempt is not None
        self.assertEqual(current_base_sha, persisted.base_sha)
        self.assertEqual(ReviewState.READY_TO_MERGE, persisted.state)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, attempt.status)
        self.assertTrue(self.store.has_delivery(event.delivery_id))

    def test_shutdown_after_exact_timeline_stops_before_installation_or_adapter(
        self,
    ) -> None:
        event = label_event()
        row = reconciliation_row(event)
        self.github.timeline = timeline_snapshot(
            event,
            matching_timeline_event(event),
        )
        stop_requested = MagicMock(side_effect=[False, True])
        runtime = ApprovalRuntime(
            self.store,
            self.github,
            self.reporter,
            app_actor=ACTOR,
            approver_ids=(303,),
            approval_label=APPROVAL_LABEL,
            stop_requested=stop_requested,
        )

        with (
            patch.object(
                self.github,
                "installation_id_for_repository",
                return_value=99,
            ) as installation,
            patch(
                "reviewer.approval_runtime.process_github_label_approval"
            ) as process,
        ):
            with self.assertRaisesRegex(
                ApprovalReconciliationPending,
                "shutdown requested",
            ):
                runtime.process_reconciliation_row(row, policy())

        self.assertEqual(1, self.github.timeline_calls)
        self.assertEqual(2, stop_requested.call_count)
        installation.assert_not_called()
        process.assert_not_called()

    def test_bot_unlabel_waits_for_visibility_without_rejection_report(self) -> None:
        self.runtime.publish_pass_review(
            self.job,
            pull=pull(),
            diff="exact diff",
            body="review passed",
            findings_hash="f" * 64,
            policy=policy(),
        )
        user_event = label_event()
        labeled = matching_timeline_event(user_event)
        self.github.timeline = timeline_snapshot(user_event, labeled)
        self.runtime.enqueue_label_event(user_event, policy=policy())
        user_row = self.store.claim_next_approval_reconciliation()
        self.assertIsNotNone(user_row)
        approval = self.runtime.process_reconciliation_row(
            user_row,
            policy(),
        )
        self.assertEqual("ACCEPTED", approval.outcome)
        self.assertEqual(2, len(self.store.list_approval_outbox()))
        self.assertIsNotNone(
            self.store.list_approval_reconciliations()[0]["completed_at"]
        )

        bot_event = label_event(
            delivery_id="delivery-bot-unlabel",
            action="unlabeled",
            sender_id=404,
            sender_login=ACTOR,
            sender_type="Bot",
            pull_updated_at="2026-07-25T00:11:00Z",
            payload_sha256="e" * 64,
        )
        removed = matching_timeline_event(
            bot_event,
            event_id="UNLE_bot_cleanup",
            ordinal=2,
            predecessor_event_id=labeled.event_id,
        )
        self.github.timeline_responses = [
            timeline_snapshot(bot_event, labeled),
            timeline_snapshot(bot_event, labeled, removed),
        ]
        self.runtime.enqueue_label_event(bot_event, policy=policy())
        bot_row = self.store.claim_next_approval_reconciliation()
        self.assertIsNotNone(bot_row)

        with self.assertRaises(ApprovalReconciliationPending):
            self.runtime.process_reconciliation_row(
                bot_row,
                policy(),
            )
        result = self.runtime.process_reconciliation_row(
            bot_row,
            policy(),
        )

        self.assertEqual("ACCEPTED", result.outcome)
        self.assertIsNone(result.reason)
        self.assertIsNone(result.approval_id)
        self.assertEqual(2, len(self.store.list_approval_outbox()))
        self.assertIsNotNone(
            self.store.list_approval_reconciliations()[1]["completed_at"]
        )

    def test_deadline_equality_is_terminal_without_github_or_adapter_call(self) -> None:
        event = label_event()
        deadline = datetime(2026, 7, 25, 0, 10, 30, tzinfo=timezone.utc)
        row = reconciliation_row(event, deadline_at=deadline)
        self.github.timeline = timeline_snapshot(event)
        terminal = {
            "delivery_id": event.delivery_id,
            "outcome": "REJECTED",
            "reason": "RECONCILIATION_DEADLINE_EXCEEDED",
            "event_id": None,
            "approval_id": None,
            "generation": None,
            "attestation_digest": None,
            "duplicate": False,
        }

        with (
            patch.object(
                self.store,
                "reject_timed_out_approval_reconciliation",
                return_value=terminal,
            ) as reject,
            patch(
                "reviewer.approval_runtime.process_github_label_approval"
            ) as process,
        ):
            result = self.runtime.process_reconciliation_row(
                row,
                policy(),
                now=deadline,
            )

        self.assertEqual("REJECTED", result.outcome)
        self.assertEqual("RECONCILIATION_DEADLINE_EXCEEDED", result.reason)
        self.assertEqual(0, self.github.timeline_calls)
        reject.assert_called_once_with(
            1,
            reason="RECONCILIATION_DEADLINE_EXCEEDED",
            claimed_at="2026-07-25T00:10:01+00:00",
            attempt_count=1,
            affects_current=True,
        )
        process.assert_not_called()

    def test_bot_cleanup_rejection_report_is_not_user_approval_failure(self) -> None:
        self.runtime.deliver_outbox_row(
            {
                "action": "DISCORD_REPORT",
                "repository": REPOSITORY,
                "pull_number": PULL_NUMBER,
                "payload": (
                    '{"reason":"TIMELINE_EVENT_VISIBILITY_TIMEOUT",'
                    '"sender_type":"Bot",'
                    '"webhook_action":"unlabeled"}'
                ),
            }
        )

        summary = self.reporter.send.call_args.kwargs["summary"]
        self.assertIn("자동 정리 event", summary)
        self.assertIn("추가 승인이나 자동 병합 없음", summary)
        self.assertNotIn("승인 요청을 적용하지 않았습니다", summary)

    def test_outbox_label_404_is_idempotent_and_report_is_bounded(self) -> None:
        self.github.timeline = SimpleNamespace(
            repository_database_id=REPOSITORY_ID,
            repository=REPOSITORY,
            pull_number=PULL_NUMBER,
            events=(
                SimpleNamespace(
                    label_name=APPROVAL_LABEL,
                    action="labeled",
                    event_id="LE_approval",
                ),
            ),
        )
        self.github.remove_error = GitHubAPIError("not found", status=404)
        self.runtime.deliver_outbox_row(
            {
                "action": "REMOVE_LABEL",
                "repository": REPOSITORY,
                "pull_number": PULL_NUMBER,
                "label_name": APPROVAL_LABEL,
                "payload": (
                    '{"approval_id":"approval-1","generation":1,'
                    '"label_event_id":"LE_approval","repository_id":42}'
                ),
            }
        )
        self.github.remove_error = None

        self.runtime.deliver_outbox_row(
            {
                "action": "DISCORD_REPORT",
                "repository": REPOSITORY,
                "pull_number": PULL_NUMBER,
                "payload": (
                    '{"reason":"ATOMIC_SERVER_GATES_UNAVAILABLE",'
                    '"approval_id":"approval-1"}'
                ),
            }
        )

        self.reporter.send.assert_called_once()
        report = self.reporter.send.call_args.kwargs
        self.assertEqual("병합 승인 처리", report["event"])
        self.assertIn("자동 병합 차단", report["summary"])
        self.assertIn("직접 병합", report["summary"])

    def test_outbox_does_not_remove_newer_label_generation(self) -> None:
        self.github.timeline = SimpleNamespace(
            repository_database_id=REPOSITORY_ID,
            repository=REPOSITORY,
            pull_number=PULL_NUMBER,
            events=(
                SimpleNamespace(
                    label_name=APPROVAL_LABEL,
                    action="labeled",
                    event_id="LE_old",
                ),
                SimpleNamespace(
                    label_name=APPROVAL_LABEL,
                    action="unlabeled",
                    event_id="UE_old",
                ),
                SimpleNamespace(
                    label_name=APPROVAL_LABEL,
                    action="labeled",
                    event_id="LE_new",
                ),
            ),
        )

        self.runtime.deliver_outbox_row(
            {
                "action": "REMOVE_LABEL",
                "repository": REPOSITORY,
                "pull_number": PULL_NUMBER,
                "label_name": APPROVAL_LABEL,
                "payload": (
                    '{"approval_id":"approval-1","generation":1,'
                    '"label_event_id":"LE_old","repository_id":42}'
                ),
            }
        )

        self.assertEqual([], self.github.removed_labels)

    def test_outbox_404_with_label_still_present_is_retried(self) -> None:
        self.github.timeline = SimpleNamespace(
            repository_database_id=REPOSITORY_ID,
            repository=REPOSITORY,
            pull_number=PULL_NUMBER,
            events=(
                SimpleNamespace(
                    label_name=APPROVAL_LABEL,
                    action="labeled",
                    event_id="LE_approval",
                ),
            ),
        )
        self.github.remove_error = GitHubAPIError("not found", status=404)
        self.github.confirmed_pull = pull(labels=(APPROVAL_LABEL,))

        with self.assertRaisesRegex(RuntimeError, "absence"):
            self.runtime.deliver_outbox_row(
                {
                    "action": "REMOVE_LABEL",
                    "repository": REPOSITORY,
                    "pull_number": PULL_NUMBER,
                    "label_name": APPROVAL_LABEL,
                    "payload": (
                        '{"approval_id":"approval-1","generation":1,'
                        '"label_event_id":"LE_approval","repository_id":42}'
                    ),
                }
            )


if __name__ == "__main__":
    unittest.main()
