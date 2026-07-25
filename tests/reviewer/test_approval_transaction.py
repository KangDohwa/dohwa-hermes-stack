from __future__ import annotations

from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from reviewer.approval import ReviewContextContent, ReviewAttemptStatus, new_uuid7
from reviewer.approval_adapter import (
    expire_github_label_approvals,
    process_github_label_approval,
)
from reviewer.github_client import (
    GitHubClockDateStatus,
    GitHubClockObservation,
    LabelTimelineEvent,
    LabelTimelineSnapshot,
)
from reviewer.models import ReviewState, WebhookEvent
from reviewer.state import StateStore, _approval_attestation_digest


REPOSITORY = "example/project"
REPOSITORY_ID = 101
PULL_NUMBER = 7
BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
TARGET_LABEL = "dohwa-approved"
APPROVER_ID = 303
EVENT_AT = "2026-07-25T04:01:00Z"


def pull_opened() -> WebhookEvent:
    return WebhookEvent(
        delivery_id="open-delivery",
        event_name="pull_request",
        action="opened",
        repository_id=REPOSITORY_ID,
        repository=REPOSITORY,
        installation_id=202,
        pull_number=PULL_NUMBER,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        is_draft=False,
        is_merged=False,
        merge_sha=None,
    )


def signed_label_webhook(
    *,
    delivery_id: str = "label-delivery",
    payload_sha256: str = "f" * 64,
    sender_id: int = APPROVER_ID,
    action: str = "labeled",
    sender_type: str = "User",
    pull_updated_at: str = EVENT_AT,
) -> WebhookEvent:
    return WebhookEvent(
        delivery_id=delivery_id,
        event_name="pull_request",
        action=action,
        repository_id=REPOSITORY_ID,
        repository=REPOSITORY,
        installation_id=202,
        pull_number=PULL_NUMBER,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        is_draft=False,
        is_merged=False,
        merge_sha=None,
        label_id=404,
        label_node_id="LA_target",
        label_name=TARGET_LABEL,
        sender_id=sender_id,
        sender_node_id=f"U_{sender_id}",
        sender_login=f"user-{sender_id}",
        sender_type=sender_type,
        pull_updated_at=pull_updated_at,
        payload_sha256=payload_sha256,
    )


def timeline_event(
    *,
    event_id: str = "LE_target",
    label_node_id: str = "LA_target",
    label_name: str = TARGET_LABEL,
    actor_id: int = APPROVER_ID,
    ordinal: int = 1,
    predecessor: str | None = None,
    action: str = "labeled",
    actor_type: str = "User",
    created_at: str = EVENT_AT,
) -> LabelTimelineEvent:
    return LabelTimelineEvent(
        event_id=event_id,
        action=action,
        created_at=created_at,
        actor_type=actor_type,
        actor_node_id=f"U_{actor_id}",
        actor_database_id=actor_id,
        actor_login=f"user-{actor_id}",
        label_node_id=label_node_id,
        label_name=label_name,
        cursor=f"cursor-{ordinal}",
        ordinal=ordinal,
        predecessor_event_id=predecessor,
    )


def snapshot(
    *events: LabelTimelineEvent,
    clock: GitHubClockObservation | None = None,
) -> LabelTimelineSnapshot:
    server_date = datetime(2026, 7, 25, 4, 1, tzinfo=timezone.utc)
    return LabelTimelineSnapshot(
        repository_node_id="R_repo",
        repository_database_id=REPOSITORY_ID,
        repository=REPOSITORY,
        pull_number=PULL_NUMBER,
        timeline_updated_at=EVENT_AT,
        total_count=len(events),
        events=events,
        clock=clock or GitHubClockObservation(
            response_date=format_datetime(server_date, usegmt=True),
            server_date_epoch_seconds=int(server_date.timestamp()),
            request_started_monotonic=100.0,
            response_received_monotonic=100.1,
            request_rtt_seconds=0.1,
            date_status=GitHubClockDateStatus.VALID,
        ),
    )


class ApprovalTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary_directory.name) / "state.sqlite3"
        self.store = StateStore(self.db_path)
        job = self.store.ingest(pull_opened()).job
        assert job is not None
        self.job_id = job.id
        self.store.transition(
            job.id, ReviewState.REVIEWING, review_decision="pass"
        )
        context = self.store.store_review_context(
            ReviewContextContent(
                repository_id=REPOSITORY_ID,
                pull_number=PULL_NUMBER,
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                merge_base_sha="c" * 40,
                diff_sha256="d" * 64,
                policy_version="phase3-v1",
            )
        )
        attempt = self.store.prepare_review_attempt(
            job_id=job.id, content_id=context.content_id,
            review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        self.attempt = self.store.activate_review_attempt(
            attempt.review_context_id,
            github_review_id=505,
            submitted_at="2026-07-25T04:00:00Z",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary_directory.cleanup()

    def process(
        self,
        *,
        timeline: LabelTimelineSnapshot | None = None,
        webhook: WebhookEvent | None = None,
        allowlist: frozenset[int] = frozenset({APPROVER_ID}),
        expected_policy_version: str = "phase3-v1",
        monotonic_ns=lambda: 100_200_000_000,
        store: StateStore | None = None,
    ):
        return process_github_label_approval(
            store or self.store,
            snapshot=timeline or snapshot(timeline_event()),
            webhook=webhook or signed_label_webhook(),
            allowed_approver_ids=allowlist,
            expected_installation_id=202,
            expected_policy_version=expected_policy_version,
            target_label=TARGET_LABEL,
            monotonic_ns=monotonic_ns,
        )

    def seed_active_approval(
        self,
        *events: LabelTimelineEvent,
        generation: int,
        approval_event_id: str,
    ) -> str:
        approval_id = new_uuid7()
        delivery_id = f"seed-delivery-{generation}"
        digest = _approval_attestation_digest(
            approval_id=approval_id,
            repository_id=REPOSITORY_ID,
            pull_number=PULL_NUMBER,
            review_context_id=self.attempt.review_context_id,
            review_attempt_id=self.attempt.review_attempt_id,
            content_id=self.attempt.content_id,
            label_event_id=approval_event_id,
            webhook_delivery_id=delivery_id,
            approver_github_user_id=APPROVER_ID,
            generation=generation,
            event_created_at=EVENT_AT,
            accepted_at=EVENT_AT,
            expires_at="2026-07-25T04:11:00Z",
        )
        with self.store._approval_transaction() as db:
            generations: dict[str, int] = {}
            for event in events:
                label_generation = generations.get(event.label_name, 0)
                if event.action == "labeled":
                    label_generation += 1
                generations[event.label_name] = label_generation
                db.execute(
                    """
                    INSERT INTO github_label_events(
                        event_id, repository_id, repository, pull_number,
                        label_node_id, label_name, action, actor_type,
                        actor_github_user_id, actor_node_id, actor_login,
                        created_at, ordinal, predecessor_event_id, generation,
                        disposition, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id, REPOSITORY_ID, REPOSITORY, PULL_NUMBER,
                        event.label_node_id, event.label_name, event.action.upper(),
                        event.actor_type, event.actor_database_id,
                        event.actor_node_id, event.actor_login, event.created_at,
                        event.ordinal, event.predecessor_event_id,
                        label_generation,
                        "SIGNED_APPROVAL_CANDIDATE"
                        if event.event_id == approval_event_id
                        else "ORDER_ONLY_NO_APPROVAL",
                        EVENT_AT,
                    ),
                )
            db.execute(
                """
                INSERT INTO github_label_webhook_evidence(
                    delivery_id, payload_sha256, event_id, review_context_id,
                    repository_id, repository, installation_id, pull_number,
                    action, label_id, label_node_id, label_name, sender_type,
                    sender_github_user_id, sender_node_id, sender_login,
                    signed_base_sha, signed_head_sha, pull_updated_at, outcome,
                    received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'labeled', ?, ?, ?, 'User',
                    ?, ?, ?, ?, ?, ?, 'ACCEPTED', ?)
                """,
                (
                    delivery_id, str(generation) * 64, approval_event_id,
                    self.attempt.review_context_id, REPOSITORY_ID, REPOSITORY,
                    202, PULL_NUMBER, 404, "LA_target", TARGET_LABEL,
                    APPROVER_ID, f"U_{APPROVER_ID}", f"user-{APPROVER_ID}",
                    BASE_SHA, HEAD_SHA, EVENT_AT, EVENT_AT,
                ),
            )
            db.execute(
                """
                INSERT INTO approvals(
                    approval_id, source, source_version, status, repository_id,
                    pull_number, review_context_id, review_attempt_id, content_id,
                    label_event_id, webhook_delivery_id, approver_github_user_id,
                    generation, event_created_at, accepted_at, expires_at,
                    attestation_digest
                ) VALUES (?, 'github_label', 'approval-ttl/v1', 'ACTIVE', ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id, REPOSITORY_ID, PULL_NUMBER,
                    self.attempt.review_context_id,
                    self.attempt.review_attempt_id, self.attempt.content_id,
                    approval_event_id, delivery_id, APPROVER_ID, generation,
                    EVENT_AT, EVENT_AT, "2026-07-25T04:11:00Z", digest,
                ),
            )
            db.executemany(
                """
                INSERT INTO approval_transition_audit(
                    approval_id, sequence, from_status, to_status, recorded_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (approval_id, 1, None, "PENDING", EVENT_AT),
                    (approval_id, 2, "PENDING", "ACTIVE", EVENT_AT),
                ),
            )
        return approval_id

    def test_accepts_then_fail_closes_without_merge_capability(self):
        result = self.process()

        self.assertEqual("ACCEPTED", result.outcome)
        self.assertEqual("ATOMIC_SERVER_GATES_UNAVAILABLE", result.reason)
        self.assertIsNotNone(result.approval_id)
        approval = self.store.get_approval_record(result.approval_id or "")
        assert approval is not None
        self.assertEqual("INVALIDATED", approval["status"])
        self.assertEqual(
            "ATOMIC_SERVER_GATES_UNAVAILABLE", approval["invalidation_reason"]
        )
        self.assertEqual(
            approval["attestation_digest"],
            _approval_attestation_digest(
                approval_id=approval["approval_id"],
                repository_id=approval["repository_id"],
                pull_number=approval["pull_number"],
                review_context_id=approval["review_context_id"],
                review_attempt_id=approval["review_attempt_id"],
                content_id=approval["content_id"],
                label_event_id=approval["label_event_id"],
                webhook_delivery_id=approval["webhook_delivery_id"],
                approver_github_user_id=approval["approver_github_user_id"],
                generation=approval["generation"],
                event_created_at=approval["event_created_at"],
                accepted_at=approval["accepted_at"],
                expires_at=approval["expires_at"],
            ),
        )
        evidence = self.store._connection.execute(
            "SELECT review_context_id FROM github_label_webhook_evidence"
        ).fetchone()
        self.assertEqual(approval["review_context_id"], evidence["review_context_id"])
        attempt = self.store.get_review_attempt(self.attempt.review_context_id)
        assert attempt is not None
        self.assertEqual(ReviewAttemptStatus.ACTIVE, attempt.status)
        self.assertEqual(
            ReviewState.HUMAN_REVIEW,
            self.store.get_job_by_id(self.job_id).state,  # type: ignore[union-attr]
        )
        self.assertEqual(
            ["REMOVE_LABEL", "DISCORD_REPORT"],
            [row["action"] for row in self.store.list_approval_outbox()],
        )
        audit = self.store._connection.execute(
            """
            SELECT sequence, to_status, reason FROM approval_transition_audit
            WHERE approval_id = ? ORDER BY sequence
            """,
            (result.approval_id,),
        ).fetchall()
        self.assertEqual([1, 2, 3], [row["sequence"] for row in audit])
        self.assertEqual(
            ["PENDING", "ACTIVE", "INVALIDATED"],
            [row["to_status"] for row in audit],
        )

    def test_duplicate_is_idempotent_across_restart(self):
        first = self.process()
        self.store.close()
        self.store = StateStore(self.db_path)

        duplicate = self.process()

        self.assertTrue(duplicate.duplicate)
        self.assertEqual(first.approval_id, duplicate.approval_id)
        self.assertEqual(first.reason, duplicate.reason)
        self.assertEqual(first.attestation_digest, duplicate.attestation_digest)
        self.assertEqual(
            1, self.store._connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        )
        self.assertEqual(2, len(self.store.list_approval_outbox()))

    def test_outbox_retries_in_order_and_completes_idempotently(self):
        self.process()

        remove = self.store.claim_next_approval_outbox()
        assert remove is not None
        self.assertEqual("REMOVE_LABEL", remove["action"])
        self.assertEqual(1, remove["attempt_count"])
        self.assertIsNone(self.store.claim_next_approval_outbox())

        self.store.retry_approval_outbox(
            remove["id"],
            "temporary failure",
            claimed_at=remove["claimed_at"],
            attempt_count=remove["attempt_count"],
        )
        retried = self.store.list_approval_outbox()[0]
        self.assertIsNone(retried["claimed_at"])
        self.assertEqual("temporary failure", retried["last_error"])
        self.assertIsNotNone(retried["retry_at"])
        self.assertIsNone(self.store.claim_next_approval_outbox())

        with self.store._approval_transaction() as db:
            db.execute(
                "UPDATE approval_outbox SET retry_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00+00:00", remove["id"]),
            )
        remove_again = self.store.claim_next_approval_outbox()
        assert remove_again is not None
        self.assertEqual(remove["id"], remove_again["id"])
        self.assertEqual(2, remove_again["attempt_count"])
        self.store.complete_approval_outbox(
            remove_again["id"],
            claimed_at=remove_again["claimed_at"],
            attempt_count=remove_again["attempt_count"],
        )
        self.store.complete_approval_outbox(
            remove_again["id"],
            claimed_at=remove_again["claimed_at"],
            attempt_count=remove_again["attempt_count"],
        )

        report = self.store.claim_next_approval_outbox()
        assert report is not None
        self.assertEqual("DISCORD_REPORT", report["action"])
        self.store.complete_approval_outbox(
            report["id"],
            claimed_at=report["claimed_at"],
            attempt_count=report["attempt_count"],
        )
        self.assertIsNone(self.store.claim_next_approval_outbox())
        self.assertTrue(
            all(row["delivered_at"] for row in self.store.list_approval_outbox())
        )

    def test_restart_releases_unfinished_outbox_claim(self):
        self.process()
        claimed = self.store.claim_next_approval_outbox()
        assert claimed is not None

        self.store.recover_after_restart()

        recovered = self.store.claim_next_approval_outbox()
        assert recovered is not None
        self.assertEqual(claimed["id"], recovered["id"])
        self.assertEqual(2, recovered["attempt_count"])

    def test_stale_worker_cannot_complete_or_retry_newer_claim(self):
        self.process()
        stale = self.store.claim_next_approval_outbox()
        assert stale is not None
        with self.store._approval_transaction() as db:
            db.execute(
                "UPDATE approval_outbox SET claimed_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00+00:00", stale["id"]),
            )
        current = self.store.claim_next_approval_outbox()
        assert current is not None

        with self.assertRaisesRegex(RuntimeError, "ownership changed"):
            self.store.complete_approval_outbox(
                stale["id"],
                claimed_at=stale["claimed_at"],
                attempt_count=stale["attempt_count"],
            )
        with self.assertRaisesRegex(RuntimeError, "ownership changed"):
            self.store.retry_approval_outbox(
                stale["id"],
                "stale failure",
                claimed_at=stale["claimed_at"],
                attempt_count=stale["attempt_count"],
            )
        persisted = self.store.list_approval_outbox()[0]
        self.assertEqual(current["claimed_at"], persisted["claimed_at"])
        self.assertEqual(current["attempt_count"], persisted["attempt_count"])

    def test_ttl_samples_inside_transaction_and_rejects_margin_equality(self):
        sampled_in_transaction = []

        def delayed_clock() -> int:
            sampled_in_transaction.append(self.store._connection.in_transaction)
            return 669_000_000_000

        result = self.process(monotonic_ns=delayed_clock)

        self.assertEqual([True], sampled_in_transaction)
        self.assertEqual("EXPIRED_OR_WITHIN_SAFETY_MARGIN", result.reason)
        self.assertIsNone(result.approval_id)

    def test_changed_policy_rejects_without_sampling_ttl_clock(self):
        sampled = []
        result = self.process(
            expected_policy_version="phase3-v2",
            monotonic_ns=lambda: sampled.append(True) or 100_200_000_000,
        )
        self.assertEqual("POLICY_VERSION_MISMATCH", result.reason)
        self.assertEqual([], sampled)

    def test_label_before_review_is_evidence_only_and_keeps_prepared_attempt(self):
        self.store.invalidate_review_attempt(
            self.attempt.review_context_id, reason="REVIEW_REPLACED"
        )
        prepared = self.store.prepare_review_attempt(
            job_id=self.job_id, content_id=self.attempt.content_id,
            review_decision="pass",
        )

        result = self.process()

        self.assertEqual("LABEL_BEFORE_REVIEW", result.reason)
        current = self.store.get_review_attempt(prepared.review_context_id)
        assert current is not None
        self.assertEqual(ReviewAttemptStatus.PREPARED, current.status)
        self.assertEqual(
            ReviewState.REVIEWING,
            self.store.get_job_by_id(self.job_id).state,  # type: ignore[union-attr]
        )

    def test_changes_required_comment_attempt_cannot_enter_approval_lifecycle(self):
        self.store.transition(
            self.job_id,
            ReviewState.REVIEWING,
            expected=ReviewState.REVIEWING,
            review_decision="changes_required",
        )

        result = self.process()

        self.assertEqual("REJECTED", result.outcome)
        self.assertEqual("REVIEW_JOB_DECISION_NOT_PASS", result.reason)
        self.assertIsNone(result.approval_id)
        self.assertEqual(
            0,
            self.store._connection.execute(
                "SELECT count(*) FROM approvals"
            ).fetchone()[0],
        )

    def test_order_only_unlabel_invalidates_exact_generation_then_reapproves(self):
        first = timeline_event(event_id="LE_gen1")
        prior_approval = self.seed_active_approval(
            first, generation=1, approval_event_id="LE_gen1"
        )
        removed = timeline_event(
            event_id="LE_remove1", ordinal=2, predecessor="LE_gen1",
            action="unlabeled",
        )
        second = timeline_event(
            event_id="LE_gen2", ordinal=3, predecessor="LE_remove1",
            created_at="2026-07-25T04:02:00Z",
        )

        result = self.process(
            timeline=snapshot(first, removed, second),
            webhook=signed_label_webhook(
                pull_updated_at="2026-07-25T04:02:00Z"
            ),
        )

        self.assertEqual("ACCEPTED", result.outcome)
        self.assertNotEqual(prior_approval, result.approval_id)
        prior = self.store.get_approval_record(prior_approval)
        assert prior is not None
        self.assertEqual("LABEL_REMOVED", prior["invalidation_reason"])
        self.assertEqual(
            "ORDER_ONLY_NO_APPROVAL",
            self.store._connection.execute(
                "SELECT disposition FROM github_label_events WHERE event_id = 'LE_remove1'"
            ).fetchone()[0],
        )
        attempt = self.store.get_review_attempt(self.attempt.review_context_id)
        assert attempt is not None
        self.assertEqual(ReviewAttemptStatus.ACTIVE, attempt.status)

    def test_delayed_old_unlabel_does_not_invalidate_newer_generation(self):
        first = timeline_event(event_id="LE_gen1")
        removed = timeline_event(
            event_id="LE_remove1", ordinal=2, predecessor="LE_gen1",
            action="unlabeled",
        )
        second = timeline_event(
            event_id="LE_gen2", ordinal=3, predecessor="LE_remove1"
        )
        newer = self.seed_active_approval(
            first, removed, second, generation=2, approval_event_id="LE_gen2"
        )

        result = self.process(
            timeline=snapshot(first, removed, second),
            webhook=signed_label_webhook(
                delivery_id="late-remove", payload_sha256="9" * 64,
                action="unlabeled",
            ),
        )

        self.assertEqual("TIMELINE_EVENT_ALREADY_RECORDED", result.reason)
        approval = self.store.get_approval_record(newer)
        assert approval is not None
        self.assertEqual("ACTIVE", approval["status"])
        attempt = self.store.get_review_attempt(self.attempt.review_context_id)
        assert attempt is not None
        self.assertEqual(ReviewAttemptStatus.ACTIVE, attempt.status)
        self.assertEqual(
            ReviewState.REVIEWING,
            self.store.get_job_by_id(self.job_id).state,  # type: ignore[union-attr]
        )

    def test_true_ambiguous_match_invalidates_approval_and_attempt(self):
        first = timeline_event(event_id="LE_gen1")
        approval_id = self.seed_active_approval(
            first, generation=1, approval_event_id="LE_gen1"
        )
        removed = timeline_event(
            event_id="LE_remove1", ordinal=2, predecessor="LE_gen1",
            action="unlabeled",
        )
        second = timeline_event(
            event_id="LE_gen2", ordinal=3, predecessor="LE_remove1"
        )

        result = self.process(timeline=snapshot(first, removed, second))

        self.assertEqual("TIMELINE_EVENT_MATCH_NOT_UNIQUE", result.reason)
        self.assertEqual(
            "INVALIDATED", self.store.get_approval_record(approval_id)["status"]
        )
        self.assertEqual(
            ReviewAttemptStatus.INVALIDATED,
            self.store.get_review_attempt(self.attempt.review_context_id).status,
        )

    def test_bot_unlabel_is_accepted_cancellation_without_approval(self):
        first = timeline_event(event_id="LE_bot_gen1")
        approval_id = self.seed_active_approval(
            first, generation=1, approval_event_id="LE_bot_gen1"
        )
        removed = timeline_event(
            event_id="LE_bot_remove", ordinal=2,
            predecessor="LE_bot_gen1", action="unlabeled", actor_type="Bot",
        )

        result = self.process(
            timeline=snapshot(first, removed),
            webhook=signed_label_webhook(
                delivery_id="bot-remove", payload_sha256="8" * 64,
                action="unlabeled", sender_type="Bot",
            ),
        )

        self.assertEqual("ACCEPTED", result.outcome)
        self.assertIsNone(result.approval_id)
        self.assertEqual(
            "LABEL_REMOVED",
            self.store.get_approval_record(approval_id)["invalidation_reason"],
        )
        self.assertEqual(
            ReviewAttemptStatus.ACTIVE,
            self.store.get_review_attempt(self.attempt.review_context_id).status,
        )

    def test_expiry_sweep_is_restart_safe_and_invalidates_at_equality(self):
        event = timeline_event(event_id="LE_expiry")
        approval_id = self.seed_active_approval(
            event, generation=1, approval_event_id="LE_expiry"
        )
        self.store.close()
        self.store = StateStore(self.db_path)
        sampled_in_transaction = []

        result = expire_github_label_approvals(
            self.store,
            snapshot=snapshot(event),
            monotonic_ns=lambda: (
                sampled_in_transaction.append(self.store._connection.in_transaction)
                or 669_000_000_000
            ),
        )

        self.assertEqual([True], sampled_in_transaction)
        self.assertEqual(((approval_id, "EXPIRED"),), result.invalidated)
        self.assertEqual(
            "EXPIRED", self.store.get_approval_record(approval_id)["invalidation_reason"]
        )

    def test_expiry_missing_github_date_fails_closed(self):
        event = timeline_event(event_id="LE_missing_date")
        approval_id = self.seed_active_approval(
            event, generation=1, approval_event_id="LE_missing_date"
        )
        missing_clock = GitHubClockObservation(
            response_date=None,
            server_date_epoch_seconds=None,
            request_started_monotonic=100.0,
            response_received_monotonic=100.1,
            request_rtt_seconds=0.1,
            date_status=GitHubClockDateStatus.MISSING,
        )

        result = expire_github_label_approvals(
            self.store,
            snapshot=snapshot(event, clock=missing_clock),
            monotonic_ns=lambda: 100_200_000_000,
        )

        self.assertEqual(
            ((approval_id, "REJECTED_MISSING_GITHUB_DATE"),),
            result.invalidated,
        )

    def test_terminal_job_transition_invalidates_open_approval_and_audits(self):
        event = timeline_event(event_id="LE_job")
        approval_id = self.seed_active_approval(
            event, generation=1, approval_event_id="LE_job"
        )

        self.store.transition(
            self.job_id, ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
        )

        approval = self.store.get_approval_record(approval_id)
        assert approval is not None
        self.assertEqual("JOB_HUMAN_REVIEW", approval["invalidation_reason"])
        audit = self.store._connection.execute(
            """
            SELECT sequence, reason FROM approval_transition_audit
            WHERE approval_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (approval_id,),
        ).fetchone()
        self.assertEqual((3, "JOB_HUMAN_REVIEW"), tuple(audit))

    def test_unapproved_actor_is_terminal_and_never_upgraded(self):
        denied = self.process(allowlist=frozenset({999}))
        self.assertEqual("REJECTED", denied.outcome)
        self.assertEqual("APPROVER_NOT_ALLOWED", denied.reason)
        disposition = self.store._connection.execute(
            "SELECT disposition FROM github_label_events"
        ).fetchone()[0]
        self.assertEqual("REJECTED_AMBIGUOUS", disposition)

        late = self.process(
            webhook=signed_label_webhook(
                delivery_id="redelivery", payload_sha256="f" * 64
            )
        )
        self.assertEqual("REJECTED", late.outcome)
        self.assertEqual("TIMELINE_EVENT_ALREADY_RECORDED", late.reason)
        self.assertEqual(
            0, self.store._connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        )
        self.assertEqual(
            ["DISCORD_REPORT", "DISCORD_REPORT"],
            [row["action"] for row in self.store.list_approval_outbox()],
        )

    def test_installation_mismatch_is_rejected_before_approval(self):
        result = process_github_label_approval(
            self.store,
            snapshot=snapshot(timeline_event()),
            webhook=signed_label_webhook(),
            allowed_approver_ids={APPROVER_ID},
            expected_installation_id=999,
            expected_policy_version="phase3-v1",
            target_label=TARGET_LABEL,
            monotonic_ns=lambda: 100_200_000_000,
        )
        self.assertEqual("INSTALLATION_ID_MISMATCH", result.reason)
        self.assertEqual(
            0, self.store._connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        )

    def test_bot_actor_is_terminal_and_never_approves(self):
        bot_event = timeline_event(actor_type="Bot")
        bot_webhook = signed_label_webhook(sender_type="Bot")

        result = self.process(
            timeline=snapshot(bot_event), webhook=bot_webhook
        )

        self.assertEqual("REJECTED", result.outcome)
        self.assertEqual("ACTOR_NOT_USER", result.reason)
        self.assertEqual(
            0,
            self.store._connection.execute(
                "SELECT count(*) FROM approvals"
            ).fetchone()[0],
        )
        self.assertEqual(
            "REJECTED_AMBIGUOUS",
            self.store._connection.execute(
                "SELECT disposition FROM github_label_events"
            ).fetchone()[0],
        )

    def test_unlabel_with_different_node_is_ambiguous(self):
        labeled = timeline_event(event_id="LE_add")
        removed = timeline_event(
            event_id="LE_remove",
            label_node_id="LA_recreated",
            ordinal=2,
            predecessor="LE_add",
            action="unlabeled",
        )
        webhook = signed_label_webhook(action="unlabeled")
        webhook = WebhookEvent(
            **{
                **{field: getattr(webhook, field) for field in webhook.__dataclass_fields__},
                "label_node_id": "LA_recreated",
            }
        )
        result = self.process(timeline=snapshot(labeled, removed), webhook=webhook)
        self.assertEqual("TIMELINE_ORDER_AMBIGUOUS", result.reason)

    def test_concurrent_duplicate_commits_one_approval(self):
        barrier = threading.Barrier(2)
        results = []
        errors = []
        second_store = StateStore(self.db_path)

        def worker(store: StateStore) -> None:
            try:
                barrier.wait()
                results.append(self.process(store=store))
            except BaseException as exc:  # surfaced below with full repr
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(store,))
            for store in (self.store, second_store)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        second_store.close()

        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(1, sum(result.duplicate for result in results))
        self.assertEqual(
            1, self.store._connection.execute("SELECT count(*) FROM approvals").fetchone()[0]
        )

    def test_preceding_timeline_event_is_order_only(self):
        other = timeline_event(
            event_id="LE_other",
            label_node_id="LA_other",
            label_name="unrelated",
            actor_id=808,
        )
        target = timeline_event(ordinal=2, predecessor="LE_other")

        result = self.process(timeline=snapshot(other, target))

        self.assertEqual("ACCEPTED", result.outcome)
        rows = self.store._connection.execute(
            "SELECT event_id, disposition FROM github_label_events ORDER BY ordinal"
        ).fetchall()
        self.assertEqual(
            [("LE_other", "ORDER_ONLY_NO_APPROVAL"),
             ("LE_target", "SIGNED_APPROVAL_CANDIDATE")],
            [(row["event_id"], row["disposition"]) for row in rows],
        )

    def test_managed_tables_reject_direct_injection_and_mutation(self):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "StateStore-managed"):
            self.store._connection.execute(
                """
                INSERT INTO github_label_events(
                    event_id, repository_id, repository, pull_number,
                    label_node_id, label_name, action, created_at, ordinal,
                    generation, disposition, recorded_at
                ) VALUES ('poison', 1, 'x/y', 1, 'L', 'x', 'LABELED',
                    '2026-07-25T04:01:00Z', 1, 1,
                    'ORDER_ONLY_NO_APPROVAL', 'now')
                """
            )
        result = self.process()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.store._connection.execute(
                "UPDATE github_label_events SET label_name = 'poison' WHERE event_id = ?",
                (result.event_id,),
            )


if __name__ == "__main__":
    unittest.main()
