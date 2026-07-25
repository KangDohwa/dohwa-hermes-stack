from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from reviewer.approval import ReviewAttemptStatus
from reviewer.approval_runtime import ApprovalRuntime, MAX_REVIEW_BODY_CHARS
from reviewer.decision import parse_review_attempt_marker
from reviewer.github_client import GitHubAPIError
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


def label_event() -> WebhookEvent:
    return WebhookEvent(
        delivery_id="delivery-label",
        event_name="pull_request",
        action="labeled",
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
        sender_id=303,
        sender_node_id="U_303",
        sender_login="approver",
        sender_type="User",
        pull_updated_at="2026-07-25T01:00:00Z",
        payload_sha256="d" * 64,
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
        self, repository: str, pull_number: int
    ) -> object:
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

    def test_label_event_uses_authoritative_snapshot_and_bound_policy(self) -> None:
        expected = object()
        event = label_event()

        with patch(
            "reviewer.approval_runtime.process_github_label_approval",
            return_value=expected,
        ) as process:
            result = self.runtime.process_label_event(event, policy=policy())

        self.assertIs(expected, result)
        process.assert_called_once_with(
            self.store,
            snapshot=self.github.timeline,
            webhook=event,
            allowed_approver_ids=(303,),
            expected_installation_id=99,
            expected_policy_version="17",
            target_label=APPROVAL_LABEL,
        )

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
