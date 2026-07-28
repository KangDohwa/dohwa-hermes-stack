from pathlib import Path
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import sqlite3
import tempfile
import unittest

from reviewer.approval import (
    ReviewAttemptStatus,
    ReviewContextContent,
)
from reviewer.merge_descriptor import CIRequestInputs, MergeDescriptor
from reviewer.models import (
    CIRequestState,
    InvalidStateTransition,
    ReviewState,
    WebhookEvent,
)
from reviewer.state import StateStore


def event(
    delivery_id,
    *,
    action="opened",
    head_sha="a" * 40,
    draft=False,
    merged=False,
    merge_sha=None,
    pull_number=7,
    repository_id=42,
    base_sha="b" * 40,
):
    return WebhookEvent(
        delivery_id=delivery_id,
        event_name="pull_request",
        action=action,
        repository_id=repository_id,
        repository="example/example-repo",
        installation_id=99,
        pull_number=pull_number,
        base_sha=base_sha,
        head_sha=head_sha,
        is_draft=draft,
        is_merged=merged,
        merge_sha=merge_sha,
    )


def approval_event(
    delivery_id,
    *,
    pull_number=7,
    payload_sha256="f" * 64,
    action="labeled",
    label_id=404,
    label_node_id="LA_approval",
    label_name="hermes:merge-approved",
    sender_id=303,
    sender_type="User",
    is_draft=False,
    is_merged=False,
    merge_sha=None,
):
    return WebhookEvent(
        delivery_id=delivery_id,
        event_name="pull_request",
        action=action,
        repository_id=42,
        repository="example/example-repo",
        installation_id=99,
        pull_number=pull_number,
        base_sha="b" * 40,
        head_sha="a" * 40,
        is_draft=is_draft,
        is_merged=is_merged,
        merge_sha=merge_sha,
        label_id=label_id,
        label_node_id=label_node_id,
        label_name=label_name,
        sender_id=sender_id,
        sender_node_id=f"U_{sender_id}",
        sender_login=f"user-{sender_id}",
        sender_type=sender_type,
        pull_updated_at="2026-07-28T01:02:03Z",
        payload_sha256=payload_sha256,
    )


def record_rejected_evidence(store, signed):
    recorded_at = "2026-07-28T01:02:04+00:00"
    with store._approval_transaction() as db:
        store._record_rejected_approval_reconciliation(
            db,
            event=signed,
            reason="TEST_TERMINAL_EVIDENCE",
            affects_current=False,
            received_at=recorded_at,
            now=recorded_at,
        )


def merge_descriptor(**overrides):
    values = {
        "repository_id": 42,
        "pull_number": 7,
        "base_oid": "b" * 40,
        "head_oid": "a" * 40,
        "merge_base_oid": "c" * 40,
        "tree_oid": "d" * 40,
        "message": "Merge exact context\n",
        "author_name": "Dohwa Bot",
        "author_email": "bot@example.invalid",
        "committer_name": "Dohwa Bot",
        "committer_email": "bot@example.invalid",
        "timestamp": 1_760_000_000,
        "ci_profile": "python-v1",
        "workflow_sha": "e" * 40,
        "git_profile": "hardened-git/v1",
        "policy_version": "policy-v1",
    }
    values.update(overrides)
    return MergeDescriptor.build(**values)


def ci_inputs(value, *, request_id="f" * 64):
    return CIRequestInputs(
        request_id=request_id,
        review_context_id="review-context-7",
        repository_id=value.repository_id,
        pull_number=value.pull_number,
        descriptor_digest=value.digest,
        base_oid=value.base_oid,
        head_oid=value.head_oid,
        candidate_oid=value.candidate_oid,
        workflow_id=12345,
        workflow_path=".github/workflows/targeted-ci.yml",
        workflow_sha=value.workflow_sha,
        workflow_definition_sha256="6" * 64,
        ci_profile=value.ci_profile,
        sandbox_profile="candidate-sandbox/v1",
        expected_actor="example-reviewer[bot]",
        expected_installation_id=99,
        dispatch_not_before="2026-07-25T00:00:00Z",
    )


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary_directory.name) / "state.sqlite3"
        self.store = StateStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temporary_directory.cleanup()

    def test_delivery_and_same_sha_are_idempotent(self):
        first = self.store.ingest(event("delivery-1"))
        duplicate = self.store.ingest(event("delivery-1"))
        redelivery = self.store.ingest(event("delivery-2"))

        self.assertTrue(first.accepted_delivery)
        self.assertTrue(first.created_job)
        self.assertFalse(duplicate.accepted_delivery)
        self.assertFalse(duplicate.created_job)
        self.assertTrue(redelivery.accepted_delivery)
        self.assertFalse(redelivery.created_job)
        self.assertEqual(len(self.store.list_jobs()), 1)
        self.assertEqual(first.job.state, ReviewState.QUEUED)

    def test_draft_waits_until_ready_for_review(self):
        waiting = self.store.ingest(event("draft", draft=True)).job
        self.assertEqual(waiting.state, ReviewState.WAITING_READY)

        ready = self.store.ingest(
            event("ready", action="ready_for_review", draft=False)
        ).job
        self.assertEqual(ready.id, waiting.id)
        self.assertEqual(ready.state, ReviewState.QUEUED)

    def test_repository_id_conflict_is_quarantined_before_state_change(self):
        waiting = self.store.ingest(event("draft", draft=True)).job

        conflict = self.store.ingest(
            event(
                "ready",
                action="ready_for_review",
                draft=False,
                repository_id=777,
            )
        )

        self.assertIsNone(conflict.job)
        persisted = self.store.get_job_by_id(waiting.id)
        assert persisted is not None
        self.assertEqual(ReviewState.WAITING_READY, persisted.state)
        self.assertEqual(42, persisted.repository_id)

    def test_repository_id_conflict_with_new_head_does_not_obsolete_job(self):
        original = self.store.ingest(event("opened")).job

        conflict = self.store.ingest(
            event(
                "synchronize",
                action="synchronize",
                head_sha="c" * 40,
                repository_id=777,
            )
        )

        self.assertIsNone(conflict.job)
        persisted = self.store.get_job_by_id(original.id)
        assert persisted is not None
        self.assertEqual(ReviewState.QUEUED, persisted.state)
        self.assertEqual(42, persisted.repository_id)
        self.assertEqual([original.id], [job.id for job in self.store.list_jobs()])

    def test_recreated_repository_id_is_quarantined_across_pull_numbers(self):
        original = self.store.ingest(event("opened", pull_number=10)).job

        conflict = self.store.ingest(
            event(
                "recreated-repository",
                pull_number=11,
                repository_id=777,
            )
        )

        self.assertIsNone(conflict.job)
        self.assertEqual([original.id], [job.id for job in self.store.list_jobs()])

    def test_same_head_base_change_requeues_exact_context(self):
        job = self.store.ingest(event("opened")).job
        assert job is not None
        reviewing = self.store.transition(
            job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        self.store.transition(
            reviewing.id,
            ReviewState.OBSOLETE,
            expected=ReviewState.REVIEWING,
        )

        replacement = self.store.ingest(
            event("base-changed", action="edited", base_sha="c" * 40)
        ).job

        assert replacement is not None
        self.assertEqual(job.id, replacement.id)
        self.assertEqual("c" * 40, replacement.base_sha)
        self.assertEqual(ReviewState.QUEUED, replacement.state)
        self.assertIsNone(replacement.review_decision)

    def test_reopened_same_head_is_queued_again(self):
        opened = self.store.ingest(event("opened")).job
        closed = self.store.ingest(event("closed", action="closed")).job
        self.assertEqual(ReviewState.CLOSED, closed.state)
        self.assertIsNotNone(closed.finished_at)

        reopened = self.store.ingest(event("reopened", action="reopened")).job
        self.assertEqual(opened.id, reopened.id)
        self.assertEqual(ReviewState.QUEUED, reopened.state)
        self.assertIsNone(reopened.finished_at)

    def test_authoritative_bootstrap_requeues_missed_reopen(self):
        opened = self.store.ingest(
            event("bootstrap:first", action="bootstrap_reconcile")
        ).job
        self.store.ingest(event("closed", action="closed"))

        recovered = self.store.ingest(
            event("bootstrap:second", action="bootstrap_reconcile")
        ).job

        self.assertEqual(opened.id, recovered.id)
        self.assertEqual(ReviewState.QUEUED, recovered.state)
        self.assertIsNone(recovered.finished_at)

    def test_authoritative_bootstrap_restores_reopened_draft(self):
        opened = self.store.ingest(
            event("bootstrap:first", action="bootstrap_reconcile")
        ).job
        self.store.ingest(event("closed", action="closed"))

        recovered = self.store.ingest(
            event(
                "bootstrap:second",
                action="bootstrap_reconcile",
                draft=True,
            )
        ).job

        self.assertEqual(opened.id, recovered.id)
        self.assertEqual(ReviewState.WAITING_READY, recovered.state)
        self.assertIsNone(recovered.finished_at)

    def test_review_publication_fence_is_durable_and_idempotent(self):
        job = self.store.ingest(event("opened")).job
        marker = "<!-- exact-review-marker -->"

        self.assertTrue(
            self.store.begin_review_publication(
                job_id=job.id,
                marker=marker,
                event="COMMENT",
            )
        )
        self.assertFalse(
            self.store.begin_review_publication(
                job_id=job.id,
                marker=marker,
                event="COMMENT",
            )
        )
        self.store.confirm_review_publication(
            job_id=job.id,
            marker=marker,
            event="COMMENT",
            github_review_id=17,
        )
        self.store.confirm_review_publication(
            job_id=job.id,
            marker=marker,
            event="COMMENT",
            github_review_id=17,
        )
        with self.assertRaisesRegex(RuntimeError, "another review"):
            self.store.confirm_review_publication(
                job_id=job.id,
                marker=marker,
                event="COMMENT",
                github_review_id=18,
            )

    def test_unresolved_review_publication_blocks_pr_wide_replacement(self):
        old = self.store.ingest(event("opened")).job
        self.assertTrue(
            self.store.begin_review_publication(
                job_id=old.id,
                marker="<!-- old-marker -->",
                event="REQUEST_CHANGES",
            )
        )
        replacement = self.store.ingest(
            event("new-head", action="synchronize", head_sha="c" * 40)
        ).job

        self.assertFalse(
            self.store.begin_review_publication(
                job_id=replacement.id,
                marker="<!-- new-marker -->",
                event="COMMENT",
            )
        )
        self.assertTrue(
            self.store.has_unresolved_review_publication(
                repository_id=42,
                pull_number=7,
            )
        )
        content = self.store.store_review_context(
            ReviewContextContent(
                repository_id=42,
                pull_number=7,
                base_sha=replacement.base_sha,
                head_sha=replacement.head_sha,
                merge_base_sha="d" * 40,
                diff_sha256="e" * 64,
                policy_version="1",
            )
        )
        with self.assertRaisesRegex(RuntimeError, "generic MAYBE_SENT"):
            self.store.prepare_review_attempt(
                job_id=replacement.id,
                content_id=content.content_id,
                review_decision="pass",
            )

    def test_unresolved_pass_publication_blocks_generic_replacement(self):
        old = self.store.ingest(event("opened")).job
        content = self.store.store_review_context(
            ReviewContextContent(
                repository_id=42,
                pull_number=7,
                base_sha=old.base_sha,
                head_sha=old.head_sha,
                merge_base_sha="c" * 40,
                diff_sha256="d" * 64,
                policy_version="1",
            )
        )
        attempt = self.store.prepare_review_attempt(
            job_id=old.id,
            content_id=content.content_id,
            review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        replacement = self.store.ingest(
            event("new-head", action="synchronize", head_sha="c" * 40)
        ).job

        self.assertFalse(
            self.store.begin_review_publication(
                job_id=replacement.id,
                marker="<!-- generic-replacement -->",
                event="REQUEST_CHANGES",
            )
        )

    def test_new_head_obsoletes_active_job_and_queues_once(self):
        old = self.store.ingest(event("old")).job
        claimed = self.store.claim_next()
        self.assertEqual(claimed.id, old.id)
        self.assertEqual(claimed.state, ReviewState.REVIEWING)

        new = self.store.ingest(
            event("new", action="synchronize", head_sha="c" * 40)
        ).job
        self.assertEqual(new.state, ReviewState.QUEUED)
        self.assertEqual(
            self.store.get_job_by_id(old.id).state,
            ReviewState.OBSOLETE,
        )
        self.assertEqual(self.store.claim_next().id, new.id)
        self.assertIsNone(self.store.claim_next())

    def test_state_transition_rules_are_enforced(self):
        job = self.store.ingest(event("transition")).job
        reviewing = self.store.transition(
            job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        ready = self.store.transition(
            reviewing.id,
            ReviewState.READY_TO_MERGE,
            expected=ReviewState.REVIEWING,
        )
        merging = self.store.transition(ready.id, ReviewState.MERGING)
        merged = self.store.transition(
            merging.id,
            ReviewState.MERGED,
            merge_sha="d" * 40,
        )
        self.assertEqual(merged.state, ReviewState.MERGED)
        self.assertEqual(merged.merge_sha, "d" * 40)
        with self.assertRaises(InvalidStateTransition):
            self.store.transition(merged.id, ReviewState.QUEUED)

    def test_reviewing_can_return_to_waiting_ready_after_draft_confirmation(self):
        job = self.store.ingest(event("draft-confirmation")).job
        reviewing = self.store.transition(
            job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )

        waiting = self.store.transition(
            reviewing.id,
            ReviewState.WAITING_READY,
            expected=ReviewState.REVIEWING,
            review_decision="changes_required",
            findings_hash="f" * 64,
            github_review_id=7,
        )

        self.assertEqual(ReviewState.WAITING_READY, waiting.state)
        self.assertEqual("changes_required", waiting.review_decision)
        self.assertEqual("f" * 64, waiting.findings_hash)
        self.assertEqual(7, waiting.github_review_id)
        self.assertIsNone(waiting.last_error)

    def test_merged_webhook_records_sha_and_clears_stale_error(self):
        job = self.store.ingest(event("opened-for-manual-merge")).job
        self.store.transition(job.id, ReviewState.REVIEWING)
        self.store.transition(
            job.id,
            ReviewState.HUMAN_REVIEW,
            last_error="high-risk paths changed",
        )

        merge_sha = "d" * 40
        merged = self.store.ingest(
            event(
                "closed-as-merged",
                action="closed",
                merged=True,
                merge_sha=merge_sha,
            )
        ).job
        self.assertEqual(ReviewState.MERGED, merged.state)
        self.assertEqual(merge_sha, merged.merge_sha)
        self.assertIsNone(merged.last_error)

        redelivered = self.store.ingest(
            event(
                "closed-as-merged-redelivery",
                action="closed",
                merged=True,
                merge_sha=merge_sha,
            )
        ).job
        self.assertEqual(merge_sha, redelivered.merge_sha)
        self.assertIsNone(redelivered.last_error)

    def test_claim_is_durable_and_increments_attempt(self):
        job = self.store.ingest(event("claim")).job
        claimed = self.store.claim_next()
        self.assertEqual(claimed.id, job.id)
        self.assertEqual(claimed.state, ReviewState.REVIEWING)
        self.assertEqual(claimed.attempt_count, 1)
        self.assertIsNone(self.store.claim_next())

    def test_restart_requeues_interrupted_review_and_preserves_queue(self):
        queued = self.store.ingest(
            event("queued", head_sha="1" * 40, pull_number=8)
        ).job
        reviewing = self.store.ingest(
            event("reviewing", head_sha="2" * 40)
        ).job
        self.store.transition(reviewing.id, ReviewState.REVIEWING)
        self.store.close()

        self.store = StateStore(self.db_path)
        report = self.store.recover_after_restart()
        recovered = self.store.get_job_by_id(reviewing.id)
        persisted = self.store.get_job_by_id(queued.id)

        self.assertEqual(report.requeued_job_ids, (reviewing.id,))
        self.assertEqual(recovered.state, ReviewState.QUEUED)
        self.assertIn("restarted", recovered.last_error)
        self.assertEqual(persisted.state, ReviewState.QUEUED)

    def test_restart_marks_ci_and_merge_jobs_for_reconciliation(self):
        waiting_ci = self.store.ingest(event("ci", head_sha="3" * 40)).job
        self.store.transition(waiting_ci.id, ReviewState.REVIEWING)
        self.store.transition(waiting_ci.id, ReviewState.WAITING_CI)

        merging = self.store.ingest(
            event("merge", head_sha="4" * 40, pull_number=8)
        ).job
        self.store.transition(merging.id, ReviewState.REVIEWING)
        self.store.transition(merging.id, ReviewState.READY_TO_MERGE)
        self.store.transition(merging.id, ReviewState.MERGING)
        self.store.close()

        self.store = StateStore(self.db_path)
        report = self.store.recover_after_restart()
        self.assertEqual(
            report.reconciliation_job_ids,
            (waiting_ci.id, merging.id),
        )
        self.assertEqual(
            self.store.get_job_by_id(waiting_ci.id).state,
            ReviewState.WAITING_CI,
        )
        self.assertEqual(
            self.store.get_job_by_id(merging.id).state,
            ReviewState.MERGING,
        )

    def test_non_pull_request_delivery_is_safely_deduplicated(self):
        check_event = WebhookEvent(
            delivery_id="check-1",
            event_name="check_run",
            action="completed",
            repository_id=42,
            repository="example/example-repo",
            installation_id=99,
            pull_number=None,
            base_sha=None,
            head_sha=None,
            is_draft=None,
            is_merged=None,
            merge_sha=None,
        )
        first = self.store.ingest(check_event)
        duplicate = self.store.ingest(check_event)
        self.assertTrue(first.accepted_delivery)
        self.assertIsNone(first.job)
        self.assertFalse(duplicate.accepted_delivery)
        self.assertIsNone(duplicate.job)

    def test_converted_to_draft_stops_ready_to_merge(self):
        job = self.store.ingest(event("opened")).job
        self.store.transition(job.id, ReviewState.REVIEWING)
        self.store.transition(job.id, ReviewState.READY_TO_MERGE)
        stopped = self.store.ingest(
            event("drafted", action="converted_to_draft", draft=True)
        ).job
        self.assertEqual(stopped.state, ReviewState.WAITING_READY)

    def test_additive_foundation_schema_is_idempotent_and_old_reader_compatible(self):
        job = self.store.ingest(event("preserved-v1")).job
        self.store.close()
        with sqlite3.connect(self.db_path) as db:
            db.execute("DROP TABLE ci_requests")
            db.execute("DROP TABLE merge_descriptors")
            db.execute("UPDATE schema_metadata SET version = 1")

        self.store = StateStore(self.db_path)
        preserved = self.store.get_job_by_id(job.id)
        self.assertEqual(ReviewState.QUEUED, preserved.state)
        self.assertEqual(job.head_sha, preserved.head_sha)
        version = self.store._connection.execute(
            "SELECT version FROM schema_metadata"
        ).fetchone()["version"]
        tables = {
            row["name"]
            for row in self.store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertEqual(1, version)
        self.assertIn("merge_descriptors", tables)
        self.assertIn("ci_requests", tables)

        self.store.close()
        with sqlite3.connect(self.db_path) as old_reader:
            old_version = old_reader.execute(
                "SELECT version FROM schema_metadata"
            ).fetchone()[0]
            old_row = old_reader.execute(
                "SELECT state, head_sha FROM review_jobs WHERE id = ?", (job.id,)
            ).fetchone()
        self.assertEqual(1, old_version)
        self.assertEqual((ReviewState.QUEUED.value, job.head_sha), old_row)

        self.store = StateStore(self.db_path)
        self.assertEqual(ReviewState.QUEUED, self.store.get_job_by_id(job.id).state)

    def test_merge_descriptor_is_canonical_immutable_and_idempotent(self):
        job = self.store.ingest(event("descriptor-job")).job
        value = merge_descriptor()

        first = self.store.store_merge_descriptor(job.id, value)
        second = self.store.store_merge_descriptor(job.id, value)
        loaded = self.store.get_merge_descriptor(value.digest)

        self.assertEqual(first.id, second.id)
        self.assertEqual(value.digest, loaded.descriptor_digest)
        self.assertEqual(value.canonical_bytes, loaded.canonical_bytes)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.store._connection.execute(
                "UPDATE merge_descriptors SET policy_version = 'changed' WHERE id = ?",
                (first.id,),
            )

    def test_descriptor_must_match_existing_review_context(self):
        job = self.store.ingest(event("descriptor-mismatch")).job
        wrong = merge_descriptor(pull_number=8)
        with self.assertRaisesRegex(ValueError, "pull_number"):
            self.store.store_merge_descriptor(job.id, wrong)

    def test_ci_request_plans_are_canonical_immutable_and_limited_to_two_states(self):
        job = self.store.ingest(event("ci-plan-job")).job
        value = merge_descriptor()
        stored = self.store.store_merge_descriptor(job.id, value)
        planned_inputs = ci_inputs(value)

        planned = self.store.create_ci_request(
            descriptor_digest=value.digest,
            inputs=planned_inputs,
            state=CIRequestState.PLANNED,
        )
        same = self.store.create_ci_request(
            descriptor_digest=value.digest,
            inputs=planned_inputs,
            state=CIRequestState.PLANNED,
        )
        blocked = self.store.create_ci_request(
            descriptor_digest=value.digest,
            inputs=ci_inputs(value, request_id="9" * 64),
            state=CIRequestState.BLOCKED,
            blocked_reason="ACTIONS_WRITE_UNAVAILABLE",
        )

        self.assertEqual(planned.request_id, same.request_id)
        self.assertEqual(CIRequestState.PLANNED, planned.state)
        self.assertEqual(CIRequestState.BLOCKED, blocked.state)
        self.assertEqual(planned_inputs.review_context_id, planned.review_context_id)
        self.assertEqual(planned_inputs.expected_actor, planned.expected_actor)
        self.assertEqual(
            planned_inputs.expected_installation_id,
            planned.expected_installation_id,
        )
        self.assertEqual(
            planned_inputs.workflow_definition_sha256,
            planned.workflow_definition_sha256,
        )
        self.assertEqual(
            planned_inputs.dispatch_not_before,
            planned.dispatch_not_before,
        )
        self.assertEqual(
            planned_inputs.canonical_bytes,
            self.store.get_ci_request(planned.request_id).canonical_inputs,
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.store._connection.execute(
                "UPDATE ci_requests SET state = 'BLOCKED' WHERE request_id = ?",
                (planned.request_id,),
            )
        def insert_raw(request_id, inputs_digest, **overrides):
            fields = {
                "review_context_id": "review-context-7",
                "workflow_definition_sha256": "6" * 64,
                "expected_actor": "example-reviewer[bot]",
                "expected_installation_id": 99,
                "dispatch_not_before": "2026-07-25T00:00:00Z",
                "state": "PLANNED",
            }
            fields.update(overrides)
            self.store._connection.execute(
                """
                INSERT INTO ci_requests(
                    request_id, review_context_id, descriptor_id, workflow_id,
                    workflow_path, workflow_sha, workflow_definition_sha256,
                    ci_profile, expected_actor, expected_installation_id,
                    dispatch_not_before, canonical_inputs, inputs_digest,
                    state, blocked_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    fields["review_context_id"],
                    stored.id,
                    12345,
                    ".github/workflows/targeted-ci.yml",
                    value.workflow_sha,
                    fields["workflow_definition_sha256"],
                    value.ci_profile,
                    fields["expected_actor"],
                    fields["expected_installation_id"],
                    fields["dispatch_not_before"],
                    sqlite3.Binary(b"{}\n"),
                    inputs_digest,
                    fields["state"],
                    None,
                    planned.created_at,
                ),
            )

        invalid_rows = (
            {"state": "DISPATCHED"},
            {"review_context_id": "review context 7"},
            {"workflow_definition_sha256": "A" * 64},
            {"expected_actor": "Dohwa Bot"},
            {"expected_installation_id": 0},
            {"dispatch_not_before": "2026-07-25 00:00:00"},
        )
        for index, invalid_fields in enumerate(invalid_rows, start=1):
            with self.subTest(invalid_fields=invalid_fields):
                with self.assertRaises(sqlite3.IntegrityError):
                    insert_raw(
                        str(index) * 64,
                        format(index + 9, "x") * 64,
                        **invalid_fields,
                    )

        conflicting = replace(planned_inputs, expected_actor="other-bot[bot]")
        with self.assertRaisesRegex(RuntimeError, "already bound"):
            self.store.create_ci_request(
                descriptor_digest=value.digest,
                inputs=conflicting,
                state=CIRequestState.PLANNED,
            )

    def test_ci_request_rejects_descriptor_mismatch_and_noncanonical_path(self):
        job = self.store.ingest(event("ci-mismatch")).job
        value = merge_descriptor()
        self.store.store_merge_descriptor(job.id, value)
        wrong = CIRequestInputs(
            request_id="8" * 64,
            review_context_id="review-context-7",
            repository_id=value.repository_id,
            pull_number=value.pull_number,
            descriptor_digest="7" * 64,
            base_oid=value.base_oid,
            head_oid=value.head_oid,
            candidate_oid=value.candidate_oid,
            workflow_id=12345,
            workflow_path=".github/workflows/targeted-ci.yml",
            workflow_sha=value.workflow_sha,
            workflow_definition_sha256="6" * 64,
            ci_profile=value.ci_profile,
            sandbox_profile="candidate-sandbox/v1",
            expected_actor="example-reviewer[bot]",
            expected_installation_id=99,
            dispatch_not_before="2026-07-25T00:00:00Z",
        )
        with self.assertRaisesRegex(ValueError, "descriptor_digest mismatch"):
            self.store.create_ci_request(
                descriptor_digest=value.digest,
                inputs=wrong,
                state=CIRequestState.PLANNED,
            )
        with self.assertRaisesRegex(ValueError, "canonical workflow path"):
            CIRequestInputs(
                request_id="6" * 64,
                review_context_id="review-context-7",
                repository_id=value.repository_id,
                pull_number=value.pull_number,
                descriptor_digest=value.digest,
                base_oid=value.base_oid,
                head_oid=value.head_oid,
                candidate_oid=value.candidate_oid,
                workflow_id=12345,
                workflow_path="../targeted-ci.yml",
                workflow_sha=value.workflow_sha,
                workflow_definition_sha256="6" * 64,
                ci_profile=value.ci_profile,
                sandbox_profile="candidate-sandbox/v1",
                expected_actor="example-reviewer[bot]",
                expected_installation_id=99,
                dispatch_not_before="2026-07-25T00:00:00Z",
            )

    def test_approval_reconciliation_enqueue_is_durable_and_idempotent(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        signed = approval_event("approval-delivery")

        self.assertTrue(
            self.store.enqueue_approval_reconciliation(
                signed,
                expected_policy_version="policy-v1",
                now=received,
            )
        )
        self.assertFalse(
            self.store.enqueue_approval_reconciliation(
                signed,
                expected_policy_version="policy-v2",
                window_seconds=300,
                now=received + timedelta(minutes=1),
            )
        )

        row = self.store.list_approval_reconciliations()[0]
        self.assertEqual("policy-v1", row["expected_policy_version"])
        self.assertEqual(
            received.isoformat(timespec="microseconds"),
            row["received_at"],
        )
        self.assertEqual(
            (received + timedelta(seconds=120)).isoformat(
                timespec="microseconds"
            ),
            row["deadline_at"],
        )
        self.assertEqual(0, row["is_draft"])
        self.assertEqual(0, row["is_merged"])
        self.assertIsNone(row["merge_sha"])
        with self.assertRaisesRegex(ValueError, "policy_version is invalid"):
            self.store.enqueue_approval_reconciliation(
                approval_event("invalid-policy"),
                expected_policy_version="policy version",
                now=received,
            )

        with self.assertRaisesRegex(RuntimeError, "payload identity conflicts"):
            self.store.enqueue_approval_reconciliation(
                replace(signed, payload_sha256="e" * 64),
                expected_policy_version="policy-v1",
                now=received,
            )
        with self.assertRaisesRegex(RuntimeError, "signed identity conflicts"):
            self.store.enqueue_approval_reconciliation(
                replace(signed, sender_login="different-user"),
                expected_policy_version="policy-v1",
                now=received,
            )

        terminal = approval_event("already-terminal", payload_sha256="d" * 64)
        record_rejected_evidence(self.store, terminal)
        self.assertFalse(
            self.store.enqueue_approval_reconciliation(
                terminal,
                expected_policy_version="policy-v1",
                now=received,
            )
        )
        self.assertEqual(1, len(self.store.list_approval_reconciliations()))
        with self.assertRaisesRegex(RuntimeError, "payload identity conflicts"):
            self.store.enqueue_approval_reconciliation(
                replace(terminal, payload_sha256="c" * 64),
                expected_policy_version="policy-v1",
                now=received,
            )
        self.assertEqual(
            1,
            len(self.store.list_approval_reconciliations()),
        )

    def test_approval_reconciliation_claims_pr_wide_fifo_lanes(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        first_event = approval_event("first")
        second_event = approval_event(
            "second",
            label_id=405,
            label_node_id="LA_other",
            label_name="another-label",
        )
        other_pull_event = approval_event("other-pull", pull_number=8)
        for signed in (first_event, second_event, other_pull_event):
            self.store.enqueue_approval_reconciliation(
                signed,
                expected_policy_version="policy-v1",
                now=received,
            )

        first = self.store.claim_next_approval_reconciliation(now=received)
        other_pull = self.store.claim_next_approval_reconciliation(now=received)

        self.assertEqual("first", first["delivery_id"])
        self.assertEqual("other-pull", other_pull["delivery_id"])
        self.assertIsNone(
            self.store.claim_next_approval_reconciliation(now=received)
        )

        record_rejected_evidence(self.store, first_event)
        self.store.complete_approval_reconciliation(
            first["id"],
            claimed_at=first["claimed_at"],
            attempt_count=first["attempt_count"],
            now=received + timedelta(seconds=1),
        )
        second = self.store.claim_next_approval_reconciliation(
            now=received + timedelta(seconds=1)
        )
        self.assertEqual("second", second["delivery_id"])

    def test_approval_reconciliation_lease_and_retry_are_cas_guarded(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        signed = approval_event("leased")
        self.store.enqueue_approval_reconciliation(
            signed,
            expected_policy_version="policy-v1",
            window_seconds=3_600,
            now=received,
        )
        first = self.store.claim_next_approval_reconciliation(now=received)

        self.assertIsNone(
            self.store.claim_next_approval_reconciliation(
                now=received + timedelta(minutes=1, seconds=59)
            )
        )
        reclaimed_at = received + timedelta(minutes=2, seconds=1)
        second = self.store.claim_next_approval_reconciliation(now=reclaimed_at)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(2, second["attempt_count"])

        with self.assertRaisesRegex(RuntimeError, "ownership changed"):
            self.store.retry_approval_reconciliation(
                first["id"],
                "stale owner",
                claimed_at=first["claimed_at"],
                attempt_count=first["attempt_count"],
                now=reclaimed_at,
            )
        self.store.retry_approval_reconciliation(
            second["id"],
            "timeline pending",
            claimed_at=second["claimed_at"],
            attempt_count=second["attempt_count"],
            now=reclaimed_at,
        )
        persisted = self.store.list_approval_reconciliations()[0]
        self.assertEqual("timeline pending", persisted["last_error"])
        self.assertLessEqual(persisted["retry_at"], persisted["deadline_at"])
        self.assertIsNone(persisted["claimed_at"])
        self.assertIsNone(persisted["lease_expires_at"])
        self.assertIsNone(
            self.store.claim_next_approval_reconciliation(
                now=reclaimed_at + timedelta(seconds=3)
            )
        )
        third = self.store.claim_next_approval_reconciliation(
            now=reclaimed_at + timedelta(seconds=4)
        )
        self.assertEqual(3, third["attempt_count"])
        with self.assertRaisesRegex(RuntimeError, "ownership changed"):
            self.store.complete_approval_reconciliation(
                second["id"],
                claimed_at=second["claimed_at"],
                attempt_count=second["attempt_count"],
                now=reclaimed_at + timedelta(seconds=4),
            )

    def test_restart_releases_claim_and_preserves_pr_fifo_lane(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        first_event = approval_event("restart-reconciliation")
        later_same_pull = approval_event(
            "restart-later-same-pull",
            action="unlabeled",
        )
        other_pull = approval_event(
            "restart-other-pull",
            pull_number=8,
        )
        for signed in (first_event, later_same_pull, other_pull):
            self.store.enqueue_approval_reconciliation(
                signed,
                expected_policy_version="policy-v1",
                now=received,
            )
        first = self.store.claim_next_approval_reconciliation(now=received)
        self.store.close()

        self.store = StateStore(self.db_path)
        self.store.recover_after_restart()
        released = self.store.list_approval_reconciliations()[0]
        self.assertIsNone(released["claimed_at"])
        self.assertIsNone(released["lease_expires_at"])
        recovered = self.store.claim_next_approval_reconciliation(
            now=received + timedelta(seconds=1)
        )
        self.assertEqual(first["id"], recovered["id"])
        self.assertEqual(2, recovered["attempt_count"])
        self.store.retry_approval_reconciliation(
            recovered["id"],
            "restart retry",
            claimed_at=recovered["claimed_at"],
            attempt_count=recovered["attempt_count"],
            now=received + timedelta(seconds=1),
        )

        parallel = self.store.claim_next_approval_reconciliation(
            now=received + timedelta(seconds=1)
        )
        self.assertEqual("restart-other-pull", parallel["delivery_id"])
        self.assertIsNone(
            self.store.claim_next_approval_reconciliation(
                now=received + timedelta(seconds=1)
            )
        )
        persisted = {
            row["delivery_id"]: row
            for row in self.store.list_approval_reconciliations()
        }
        self.assertIsNone(
            persisted["restart-later-same-pull"]["claimed_at"]
        )

    def test_approval_reconciliation_completion_requires_evidence(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        signed = approval_event("completion-fence")
        self.store.enqueue_approval_reconciliation(
            signed,
            expected_policy_version="policy-v1",
            now=received,
        )
        claimed = self.store.claim_next_approval_reconciliation(now=received)

        with self.assertRaisesRegex(RuntimeError, "terminal evidence"):
            self.store.complete_approval_reconciliation(
                claimed["id"],
                claimed_at=claimed["claimed_at"],
                attempt_count=claimed["attempt_count"],
                now=received + timedelta(seconds=1),
            )
        self.assertIsNone(
            self.store.list_approval_reconciliations()[0]["completed_at"]
        )

        record_rejected_evidence(self.store, signed)
        self.store.complete_approval_reconciliation(
            claimed["id"],
            claimed_at=claimed["claimed_at"],
            attempt_count=claimed["attempt_count"],
            now=received + timedelta(seconds=2),
        )
        completed = self.store.list_approval_reconciliations()[0]
        self.assertIsNotNone(completed["completed_at"])

        with self.store._allow_approval_write():
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                self.store._connection.execute(
                    """
                    UPDATE approval_reconciliation_queue
                    SET label_name = 'mutated' WHERE id = ?
                    """,
                    (claimed["id"],),
                )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "durable"):
            self.store._connection.execute(
                "DELETE FROM approval_reconciliation_queue WHERE id = ?",
                (claimed["id"],),
            )

    def test_timed_out_reconciliation_is_terminal_and_fail_closed(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        job = self.store.ingest(event("timeout-job")).job
        self.store.transition(job.id, ReviewState.REVIEWING)
        self.store.transition(job.id, ReviewState.READY_TO_MERGE)
        signed = approval_event("timeout")
        self.store.enqueue_approval_reconciliation(
            signed,
            expected_policy_version="policy-v1",
            now=received,
        )
        claimed = self.store.claim_next_approval_reconciliation(now=received)

        with self.assertRaisesRegex(RuntimeError, "deadline has not expired"):
            self.store.reject_timed_out_approval_reconciliation(
                claimed["id"],
                reason="TIMELINE_EVENT_VISIBILITY_TIMEOUT",
                claimed_at=claimed["claimed_at"],
                attempt_count=claimed["attempt_count"],
                affects_current=True,
                now=received + timedelta(seconds=119),
            )
        result = self.store.reject_timed_out_approval_reconciliation(
            claimed["id"],
            reason="TIMELINE_EVENT_VISIBILITY_TIMEOUT",
            claimed_at=claimed["claimed_at"],
            attempt_count=claimed["attempt_count"],
            affects_current=True,
            now=received + timedelta(seconds=120),
        )

        self.assertEqual("REJECTED", result["outcome"])
        self.assertEqual("TIMELINE_EVENT_VISIBILITY_TIMEOUT", result["reason"])
        reconciled = self.store.list_approval_reconciliations()[0]
        self.assertIsNotNone(reconciled["completed_at"])
        self.assertEqual(result["reason"], reconciled["last_error"])
        evidence = self.store._connection.execute(
            """
            SELECT * FROM github_label_webhook_evidence
            WHERE delivery_id = 'timeout'
            """
        ).fetchone()
        self.assertEqual("REJECTED", evidence["outcome"])
        self.assertEqual(
            received.isoformat(timespec="microseconds"),
            evidence["received_at"],
        )
        self.assertEqual(
            ReviewState.HUMAN_REVIEW,
            self.store.get_job_by_id(job.id).state,
        )
        self.assertEqual(
            ["DISCORD_REPORT"],
            [row["action"] for row in self.store.list_approval_outbox()],
        )

    def test_bot_unlabel_timeout_fail_closes_current_job_and_attempt(self):
        received = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
        job = self.store.ingest(event("bot-timeout-job", pull_number=8)).job
        self.store.transition(
            job.id,
            ReviewState.REVIEWING,
            review_decision="pass",
        )
        context = self.store.store_review_context(
            ReviewContextContent(
                repository_id=42,
                pull_number=8,
                base_sha="b" * 40,
                head_sha="a" * 40,
                merge_base_sha="c" * 40,
                diff_sha256="d" * 64,
                policy_version="policy-v1",
            )
        )
        prepared = self.store.prepare_review_attempt(
            job_id=job.id,
            content_id=context.content_id,
            review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            prepared.review_context_id
        )
        active = self.store.activate_review_attempt(
            prepared.review_context_id,
            github_review_id=909,
            submitted_at="2026-07-28T01:01:00Z",
        )
        self.store.transition(job.id, ReviewState.READY_TO_MERGE)
        signed = approval_event(
            "bot-timeout",
            pull_number=8,
            action="unlabeled",
            sender_id=808,
            sender_type="Bot",
        )
        self.store.enqueue_approval_reconciliation(
            signed,
            expected_policy_version="policy-v1",
            now=received,
        )
        claimed = self.store.claim_next_approval_reconciliation(now=received)

        result = self.store.reject_timed_out_approval_reconciliation(
            claimed["id"],
            reason="TIMELINE_EVENT_VISIBILITY_TIMEOUT",
            claimed_at=claimed["claimed_at"],
            attempt_count=claimed["attempt_count"],
            affects_current=True,
            now=received + timedelta(seconds=120),
        )

        self.assertEqual("REJECTED", result["outcome"])
        self.assertEqual(
            ReviewState.HUMAN_REVIEW,
            self.store.get_job_by_id(job.id).state,
        )
        invalidated = self.store.get_review_attempt(active.review_context_id)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, invalidated.status)
        self.assertEqual(
            "TIMELINE_EVENT_VISIBILITY_TIMEOUT",
            invalidated.invalidation_reason,
        )
        reconciliation = self.store.list_approval_reconciliations()[0]
        self.assertIsNotNone(reconciliation["completed_at"])
        evidence = self.store._connection.execute(
            """
            SELECT * FROM github_label_webhook_evidence
            WHERE delivery_id = 'bot-timeout'
            """
        ).fetchone()
        self.assertEqual("REJECTED", evidence["outcome"])
        self.assertEqual(
            "TIMELINE_EVENT_VISIBILITY_TIMEOUT",
            evidence["rejection_reason"],
        )
        outbox = self.store.list_approval_outbox()
        self.assertEqual(1, len(outbox))
        self.assertEqual("bot-timeout", outbox[0]["delivery_id"])
        self.assertEqual("DISCORD_REPORT", outbox[0]["action"])


if __name__ == "__main__":
    unittest.main()
