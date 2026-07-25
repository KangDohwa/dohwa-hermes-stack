from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import tempfile
import threading
import unittest
from typing import Any

from reviewer.approval import ReviewAttemptStatus, ReviewContextContent
from reviewer.decision import review_attempt_marker
from reviewer.models import ReviewState, WebhookEvent
from reviewer.review_publisher import (
    REVIEW_PUBLISH_UNKNOWN,
    ReviewAttemptPublisher,
    ReviewPublishUnknown,
)
from reviewer.state import StateStore


HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
ACTOR = "example-reviewer[bot]"


def pull_event() -> WebhookEvent:
    return WebhookEvent(
        delivery_id="delivery-1",
        event_name="pull_request",
        action="opened",
        repository_id=42,
        repository="example/example-repo",
        installation_id=99,
        pull_number=7,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        is_draft=False,
        is_merged=False,
        merge_sha=None,
    )


class FakeGitHub:
    def __init__(self) -> None:
        self.reviews: list[dict[str, Any]] = []
        self.list_calls = 0
        self.create_calls = 0
        self.create_error: Exception | None = None
        self.invalid_response: dict[str, Any] | None = None
        self.persist_before_error = False
        self.store_created_review = True
        self._lock = threading.Lock()

    def list_pull_request_reviews(
        self, repository: str, pull_number: int
    ) -> list[dict[str, Any]]:
        with self._lock:
            self.list_calls += 1
            return [dict(item) for item in self.reviews]

    def create_review(
        self,
        repository: str,
        pull_number: int,
        *,
        body: str,
        event: str,
        commit_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self.create_calls += 1
            review = trusted_review(
                body,
                review_id=100 + self.create_calls,
                event=event,
                commit_id=commit_id or "",
            )
            if self.persist_before_error and self.store_created_review:
                self.reviews.append(review)
            if self.create_error is not None:
                raise self.create_error
            if not self.persist_before_error and self.store_created_review:
                self.reviews.append(review)
            if self.invalid_response is not None:
                return dict(self.invalid_response)
            return dict(review)


def trusted_review(
    body: str,
    *,
    review_id: int = 101,
    event: str = "COMMENT",
    commit_id: str = HEAD_SHA,
) -> dict[str, Any]:
    return {
        "id": review_id,
        "body": body,
        "state": "APPROVED" if event == "APPROVE" else "COMMENTED",
        "commit_id": commit_id,
        "submitted_at": "2026-07-25T00:00:00Z",
        "user": {"login": ACTOR, "type": "Bot"},
    }


class ReviewAttemptPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary_directory.name) / "state.sqlite3"
        self.store = StateStore(self.db_path)
        self.job = self.store.ingest(pull_event()).job
        context = self.store.store_review_context(
            ReviewContextContent(
                repository_id=42,
                pull_number=7,
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                merge_base_sha="c" * 40,
                diff_sha256="d" * 64,
                policy_version="phase3-v1",
            )
        )
        self.attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=context.content_id,
        )
        self.marker = review_attempt_marker(
            self.job.repository,
            self.job.pull_number,
            self.job.head_sha,
            self.attempt.review_attempt_id,
        )
        self.body = self.marker + "\nreview passed"
        self.github = FakeGitHub()
        self.publisher = ReviewAttemptPublisher(
            self.store, self.github, app_actor=ACTOR
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary_directory.cleanup()

    def test_not_sent_posts_once_and_activates_trusted_response(self) -> None:
        active = self.publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )

        self.assertEqual(1, self.github.create_calls)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, active.status)
        self.assertEqual(101, active.github_review_id)
        self.assertEqual(
            "CONFIRMED",
            self.store.get_review_attempt_publish_state(
                self.attempt.review_context_id
            ),
        )

    def test_timeout_after_remote_write_reconciles_once_and_activates(self) -> None:
        self.github.persist_before_error = True
        self.github.create_error = TimeoutError("response lost")

        active = self.publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )

        self.assertEqual(1, self.github.create_calls)
        self.assertEqual(2, self.github.list_calls)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, active.status)

    def test_timeout_without_visible_review_is_quarantined_and_never_reposted(
        self,
    ) -> None:
        self.github.create_error = TimeoutError("response lost")

        with self.assertRaisesRegex(
            ReviewPublishUnknown, REVIEW_PUBLISH_UNKNOWN
        ):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )
        self.assertEqual(
            "MAYBE_SENT",
            self.store.get_review_attempt_publish_state(
                self.attempt.review_context_id
            ),
        )
        self.assertEqual(
            ReviewAttemptStatus.PREPARED,
            self.store.get_review_attempt(
                self.attempt.review_context_id
            ).status,
        )

        self.github.create_error = None
        with self.assertRaisesRegex(
            ReviewPublishUnknown, REVIEW_PUBLISH_UNKNOWN
        ):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )
        self.assertEqual(1, self.github.create_calls)
        other_context = self.store.store_review_context(
            ReviewContextContent(
                repository_id=42,
                pull_number=7,
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                merge_base_sha="c" * 40,
                diff_sha256="e" * 64,
                policy_version="phase3-v1",
            )
        )
        with self.assertRaisesRegex(RuntimeError, "open review attempt"):
            self.store.prepare_review_attempt(
                job_id=self.job.id,
                content_id=other_context.content_id,
            )

    def test_restart_with_maybe_sent_only_reconciles_marker(self) -> None:
        self.store.mark_review_attempt_publish_maybe_sent(
            self.attempt.review_context_id
        )
        self.github.reviews.append(trusted_review(self.body))
        self.store.close()
        self.store = StateStore(self.db_path)
        publisher = ReviewAttemptPublisher(
            self.store, self.github, app_actor=ACTOR
        )

        active = publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )

        self.assertEqual(0, self.github.create_calls)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, active.status)

    def test_trusted_remote_marker_with_not_sent_state_is_not_duplicated(
        self,
    ) -> None:
        self.github.reviews.append(trusted_review(self.body))

        active = self.publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )

        self.assertEqual(0, self.github.create_calls)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, active.status)
        self.assertEqual(
            "CONFIRMED",
            self.store.get_review_attempt_publish_state(
                self.attempt.review_context_id
            ),
        )

    def test_crash_before_post_leaves_maybe_sent_and_does_not_post(self) -> None:
        self.store.mark_review_attempt_publish_maybe_sent(
            self.attempt.review_context_id
        )

        with self.assertRaises(ReviewPublishUnknown):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )

        self.assertEqual(0, self.github.create_calls)
        self.assertEqual(
            "MAYBE_SENT",
            self.store.get_review_attempt_publish_state(
                self.attempt.review_context_id
            ),
        )

    def test_context_invalidated_after_cas_is_quarantined_without_post(
        self,
    ) -> None:
        mark = self.store.mark_review_attempt_publish_maybe_sent

        def mark_then_invalidate(review_context_id: str) -> str:
            result = mark(review_context_id)
            self.store.transition(
                self.job.id,
                ReviewState.FAILED,
                expected=ReviewState.QUEUED,
                last_error="context changed",
            )
            return result

        self.store.mark_review_attempt_publish_maybe_sent = mark_then_invalidate

        with self.assertRaises(ReviewPublishUnknown):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )

        self.assertEqual(0, self.github.create_calls)
        self.assertEqual(
            "MAYBE_SENT",
            self.store.get_review_attempt_publish_state(
                self.attempt.review_context_id
            ),
        )
        self.assertEqual(
            ReviewAttemptStatus.INVALIDATED,
            self.store.get_review_attempt(
                self.attempt.review_context_id
            ).status,
        )

    def test_late_trusted_marker_terminally_confirms_invalidated_attempt(
        self,
    ) -> None:
        self.store.transition(
            self.job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            self.attempt.review_context_id
        )
        self.store.transition(
            self.job.id,
            ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
            last_error="operator review required",
        )
        self.github.reviews.append(trusted_review(self.body, review_id=311))

        terminal = self.publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )

        self.assertEqual(0, self.github.create_calls)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, terminal.status)
        self.assertEqual("CONFIRMED", self.store.get_review_attempt_publish_state(
            terminal.review_context_id
        ))
        self.assertEqual(311, terminal.github_review_id)
        self.assertEqual(
            "2026-07-25T00:00:00Z", terminal.submitted_at
        )
        self.assertEqual(
            "JOB_HUMAN_REVIEW",
            terminal.invalidation_reason,
        )

        self.store.transition(
            self.job.id,
            ReviewState.QUEUED,
            expected=ReviewState.HUMAN_REVIEW,
        )
        replacement_context = self.store.store_review_context(
            ReviewContextContent(
                repository_id=42,
                pull_number=7,
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                merge_base_sha="c" * 40,
                diff_sha256="e" * 64,
                policy_version="phase3-v1",
            )
        )
        replacement = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=replacement_context.content_id,
        )
        self.assertEqual(ReviewAttemptStatus.PREPARED, replacement.status)
        self.assertNotEqual(
            self.attempt.review_attempt_id,
            replacement.review_attempt_id,
        )

    def test_manual_invalidation_with_valid_context_is_not_terminally_confirmed(
        self,
    ) -> None:
        self.store.mark_review_attempt_publish_maybe_sent(
            self.attempt.review_context_id
        )
        self.store.invalidate_review_attempt(
            self.attempt.review_context_id,
            reason="MANUAL_INVALIDATION",
        )
        self.github.reviews.append(trusted_review(self.body, review_id=312))

        with self.assertRaisesRegex(RuntimeError, "context remains valid"):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )

        unresolved = self.store.get_review_attempt(
            self.attempt.review_context_id
        )
        self.assertEqual("MAYBE_SENT", self.store.get_review_attempt_publish_state(
            unresolved.review_context_id
        ))
        self.assertIsNone(unresolved.github_review_id)
        self.assertEqual("MANUAL_INVALIDATION", unresolved.invalidation_reason)
        self.assertEqual(0, self.github.create_calls)

    def test_existing_review_identity_conflict_is_not_swallowed(self) -> None:
        active = self.publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )
        self.github.reviews = [trusted_review(self.body, review_id=999)]

        with self.assertRaisesRegex(RuntimeError, "bound to another review"):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )

        persisted = self.store.get_review_attempt(active.review_context_id)
        self.assertEqual(active.github_review_id, persisted.github_review_id)
        self.assertEqual(1, self.github.create_calls)

    def test_invalid_post_response_relists_and_activates_visible_review(self) -> None:
        self.github.invalid_response = {"id": 0}

        active = self.publisher.publish(
            self.job, self.attempt, body=self.body, event="COMMENT"
        )

        self.assertEqual(1, self.github.create_calls)
        self.assertEqual(2, self.github.list_calls)
        self.assertEqual(ReviewAttemptStatus.ACTIVE, active.status)

    def test_duplicate_or_mismatched_marker_fails_closed_before_post(self) -> None:
        duplicate = trusted_review(self.body)
        self.github.reviews = [duplicate, dict(duplicate, id=102)]
        with self.assertRaises(ReviewPublishUnknown):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )
        self.assertEqual(0, self.github.create_calls)

        self.github.reviews = [
            dict(
                trusted_review(self.body),
                commit_id="f" * 40,
            )
        ]
        with self.assertRaises(ReviewPublishUnknown):
            self.publisher.publish(
                self.job, self.attempt, body=self.body, event="COMMENT"
            )
        self.assertEqual(0, self.github.create_calls)

    def test_response_requires_expected_event_commit_timestamp_and_bot(self) -> None:
        self.github.invalid_response = dict(
            trusted_review(self.body),
            user={"login": ACTOR, "type": "User"},
        )
        self.github.store_created_review = False

        with self.assertRaises(ReviewPublishUnknown):
            self.publisher.publish(
                self.job,
                self.attempt,
                body=self.body,
                event="COMMENT",
            )

        self.assertEqual(1, self.github.create_calls)
        self.assertEqual(2, self.github.list_calls)
        self.assertEqual(
            "MAYBE_SENT",
            self.store.get_review_attempt_publish_state(
                self.attempt.review_context_id
            ),
        )

    def test_body_event_and_job_attempt_identity_are_validated_before_io(
        self,
    ) -> None:
        for body, event, job, attempt in (
            ("review\n" + self.marker, "COMMENT", self.job, self.attempt),
            (self.body + "\n" + self.marker, "COMMENT", self.job, self.attempt),
            (self.body, "REQUEST_CHANGES", self.job, self.attempt),
            (
                self.body,
                "COMMENT",
                replace(self.job, repository="example/other"),
                self.attempt,
            ),
            (
                self.body,
                "COMMENT",
                self.job,
                replace(self.attempt, job_id=self.job.id + 1),
            ),
        ):
            with self.subTest(event=event, body=body[:20]):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.publisher.publish(
                        job, attempt, body=body, event=event
                    )
        self.assertEqual(0, self.github.list_calls)
        self.assertEqual(0, self.github.create_calls)

    def test_concurrent_publishers_issue_at_most_one_post(self) -> None:
        other = StateStore(self.db_path)
        first = ReviewAttemptPublisher(
            self.store, self.github, app_actor=ACTOR
        )
        second = ReviewAttemptPublisher(other, self.github, app_actor=ACTOR)

        def publish(publisher: ReviewAttemptPublisher) -> object:
            try:
                return publisher.publish(
                    self.job,
                    self.attempt,
                    body=self.body,
                    event="COMMENT",
                )
            except ReviewPublishUnknown as exc:
                return exc

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(publish, (first, second)))
        finally:
            other.close()

        self.assertEqual(1, self.github.create_calls)
        self.assertTrue(
            any(
                getattr(result, "status", None) is ReviewAttemptStatus.ACTIVE
                for result in results
            )
        )
        self.assertEqual(
            ReviewAttemptStatus.ACTIVE,
            self.store.get_review_attempt(
                self.attempt.review_context_id
            ).status,
        )


if __name__ == "__main__":
    unittest.main()
