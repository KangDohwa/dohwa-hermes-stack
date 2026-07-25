from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from reviewer.approval import (
    ReviewAttemptStatus,
    ReviewContextContent,
    new_uuid7,
    require_uuid7,
)
from reviewer.models import ReviewState, WebhookEvent
from reviewer.state import StateStore


def pull_event(delivery_id: str) -> WebhookEvent:
    return WebhookEvent(
        delivery_id=delivery_id,
        event_name="pull_request",
        action="opened",
        repository_id=42,
        repository="example/example-repo",
        installation_id=99,
        pull_number=7,
        base_sha="b" * 40,
        head_sha="a" * 40,
        is_draft=False,
        is_merged=False,
        merge_sha=None,
    )


def review_context(**overrides: object) -> ReviewContextContent:
    values: dict[str, object] = {
        "repository_id": 42,
        "pull_number": 7,
        "base_sha": "b" * 40,
        "head_sha": "a" * 40,
        "merge_base_sha": "c" * 40,
        "diff_sha256": "d" * 64,
        "policy_version": "phase3-v1",
    }
    values.update(overrides)
    return ReviewContextContent(**values)


class ReviewContextTests(unittest.TestCase):
    def test_golden_vector_field_order_digest_and_uuid7(self):
        value = ReviewContextContent(
            repository_id=1,
            pull_number=1,
            base_sha="1" * 40,
            head_sha="0" * 40,
            merge_base_sha="2" * 40,
            diff_sha256="3" * 64,
            policy_version="phase3-v1",
        )
        expected = (
            b'{"base_sha":"1111111111111111111111111111111111111111",'
            b'"diff_sha256":"3333333333333333333333333333333333333333333333333333333333333333",'
            b'"head_sha":"0000000000000000000000000000000000000000",'
            b'"merge_base_sha":"2222222222222222222222222222222222222222",'
            b'"policy_version":"phase3-v1","pull_number_decimal":"1",'
            b'"repository_id_decimal":"1",'
            b'"schema":"dohwa-review-context-content/v1"}'
        )
        self.assertEqual(expected, value.canonical_bytes)
        self.assertEqual(
            "912089101b1b9f74dbaef4526ec9a2e50db7ffcef7859cbcc8bffa92510b76ee",
            value.content_id,
        )
        self.assertNotEqual(
            value.content_id, replace(value, policy_version="phase3-v2").content_id
        )
        self.assertEqual(
            value,
            ReviewContextContent.from_canonical_bytes(value.canonical_bytes),
        )
        identifier = new_uuid7(timestamp_ms=1, random_bits=0)
        self.assertEqual(identifier, require_uuid7(identifier, "identifier"))

    def test_missing_extra_duplicate_and_noncanonical_order_are_rejected(self):
        value = review_context()
        payload = value.payload
        missing = dict(payload)
        missing.pop("base_sha")
        extra = dict(payload, extra="value")
        duplicate = value.canonical_bytes.replace(
            b'{"base_sha":', b'{"base_sha":"b","base_sha":', 1
        )
        reordered = json.dumps(
            dict(reversed(tuple(payload.items()))),
            separators=(",", ":"),
        ).encode()
        cases = (
            json.dumps(missing, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(extra, separators=(",", ":"), sort_keys=True).encode(),
            duplicate,
            reordered,
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    ReviewContextContent.from_canonical_bytes(raw)

    def test_decimal_policy_and_digest_validation_is_strict(self):
        value = review_context()
        for field, invalid in (
            ("repository_id_decimal", "01"),
            ("pull_number_decimal", "0"),
            ("pull_number_decimal", "+1"),
        ):
            payload = value.payload
            payload[field] = invalid
            raw = json.dumps(
                payload, separators=(",", ":"), sort_keys=True
            ).encode()
            with self.subTest(field=field, invalid=invalid):
                with self.assertRaisesRegex(ValueError, "decimal"):
                    ReviewContextContent.from_canonical_bytes(raw)
        with self.assertRaisesRegex(ValueError, "policy_version"):
            review_context(policy_version="\ud654")
        with self.assertRaisesRegex(ValueError, "diff_sha256"):
            review_context(diff_sha256="D" * 64)
        maximum = review_context(
            repository_id=2**63 - 1,
            pull_number=2**63 - 1,
        )
        self.assertEqual(maximum, ReviewContextContent.from_canonical_bytes(
            maximum.canonical_bytes
        ))
        for field in ("repository_id", "pull_number"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "signed 64-bit"):
                    review_context(**{field: 2**63})


class ReviewAttemptStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary_directory.name) / "state.sqlite3"
        self.store = StateStore(self.db_path)
        self.job = self.store.ingest(pull_event("opened")).job
        self.job = self.store.transition(
            self.job.id,
            ReviewState.QUEUED,
            expected=ReviewState.QUEUED,
            review_decision="pass",
        )
        self.context = self.store.store_review_context(review_context())

    def tearDown(self):
        self.store.close()
        self.temporary_directory.cleanup()

    def test_additive_schema_keeps_v1_old_reader_and_scope(self):
        version = self.store._connection.execute(
            "SELECT version FROM schema_metadata"
        ).fetchone()[0]
        tables = {
            row[0]
            for row in self.store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertEqual(1, version)
        self.assertIn("review_context_contents", tables)
        self.assertIn("review_attempts", tables)
        self.assertTrue(
            {
                "github_label_events",
                "github_label_webhook_evidence",
                "approvals",
                "approval_transition_audit",
                "approval_outbox",
            }.issubset(tables)
        )
        outbox_columns = {
            row[1]
            for row in self.store._connection.execute(
                "PRAGMA table_info(approval_outbox)"
            )
        }
        self.assertTrue(
            {
                "claimed_at",
                "attempt_count",
                "last_error",
                "retry_at",
            }.issubset(outbox_columns)
        )

        self.store.close()
        with sqlite3.connect(self.db_path) as old_reader:
            self.assertEqual(
                (1, ReviewState.QUEUED.value),
                old_reader.execute(
                    """
                    SELECT m.version, j.state
                    FROM schema_metadata m CROSS JOIN review_jobs j
                    WHERE j.id = ?
                    """,
                    (self.job.id,),
                ).fetchone(),
            )
        self.store = StateStore(self.db_path)

    def test_prepare_is_idempotent_per_job_and_restart_durable(self):
        first = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        same = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.assertEqual(first, same)
        self.assertEqual(ReviewAttemptStatus.PREPARED, first.status)

        other_content = self.store.store_review_context(
            review_context(diff_sha256="e" * 64)
        )
        with self.assertRaisesRegex(RuntimeError, "open review attempt"):
            self.store.prepare_review_attempt(
                job_id=self.job.id,
                content_id=other_content.content_id, review_decision="pass",
            )

        self.store.close()
        self.store = StateStore(self.db_path)
        self.assertEqual(
            first,
            self.store.get_review_attempt(first.review_context_id),
        )

    def test_prepare_requires_explicit_pass_decision(self):
        with self.assertRaisesRegex(ValueError, "requires a pass decision"):
            self.store.prepare_review_attempt(
                job_id=self.job.id,
                content_id=self.context.content_id,
                review_decision="changes_required",
            )
        self.assertEqual(
            0,
            self.store._connection.execute(
                "SELECT count(*) FROM review_attempts"
            ).fetchone()[0],
        )

    def test_unresolved_maybe_sent_blocks_replacement_after_invalidation(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        self.store.invalidate_review_attempt(
            attempt.review_context_id, reason="RECONCILIATION_REQUIRED"
        )

        with self.assertRaisesRegex(RuntimeError, "unresolved MAYBE_SENT"):
            self.store.prepare_review_attempt(
                job_id=self.job.id,
                content_id=self.context.content_id, review_decision="pass",
            )

    def test_activation_revalidates_job_context_and_state(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store._connection.execute(
            "UPDATE review_jobs SET base_sha = ? WHERE id = ?",
            ("f" * 40, self.job.id),
        )
        with self.assertRaisesRegex(RuntimeError, "no longer matches"):
            self.store.activate_review_attempt(
                attempt.review_context_id,
                github_review_id=9001,
                submitted_at="2026-07-25T00:00:00Z",
            )

        self.store._connection.execute(
            "UPDATE review_jobs SET base_sha = ?, state = 'CLOSED' WHERE id = ?",
            ("b" * 40, self.job.id),
        )
        with self.assertRaisesRegex(RuntimeError, "no longer active"):
            self.store.activate_review_attempt(
                attempt.review_context_id,
                github_review_id=9001,
                submitted_at="2026-07-25T00:00:00Z",
            )

    def test_lifecycle_updates_require_state_store_and_are_terminal(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "StateStore-managed"
        ):
            self.store._connection.execute(
                """
                UPDATE review_attempts
                SET status = 'ACTIVE', github_review_id = 9,
                    submitted_at = '2026-07-25T00:00:00Z',
                    activated_at = 'now'
                WHERE review_context_id = ?
                """,
                (attempt.review_context_id,),
            )

        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        active = self.store.activate_review_attempt(
            attempt.review_context_id,
            github_review_id=9001,
            submitted_at="2026-07-25T00:00:00Z",
        )
        self.assertEqual(ReviewAttemptStatus.ACTIVE, active.status)
        terminal = self.store.invalidate_review_attempt(
            active.review_context_id, reason="CONTEXT_CHANGED"
        )
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, terminal.status)
        with self.assertRaisesRegex(RuntimeError, "terminal"):
            self.store.activate_review_attempt(
                active.review_context_id,
                github_review_id=9001,
                submitted_at="2026-07-25T00:00:00Z",
            )

    def test_concurrent_prepare_returns_one_attempt(self):
        other = StateStore(self.db_path)

        def prepare(store):
            return store.prepare_review_attempt(
                job_id=self.job.id,
                content_id=self.context.content_id, review_decision="pass",
            )

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                attempts = list(executor.map(prepare, (self.store, other)))
        finally:
            other.close()
        self.assertEqual(
            attempts[0].review_attempt_id,
            attempts[1].review_attempt_id,
        )
        self.assertEqual(
            1,
            self.store._connection.execute(
                "SELECT COUNT(*) FROM review_attempts"
            ).fetchone()[0],
        )

    def test_direct_insert_is_blocked_for_every_lifecycle_status(self):
        for status, lifecycle in (
            ("PREPARED", (None, None, None, None, None)),
            (
                "ACTIVE",
                (
                    9001,
                    "2026-07-25T00:00:00Z",
                    "2026-07-25T00:00:01Z",
                    None,
                    None,
                ),
            ),
            (
                "INVALIDATED",
                (
                    None,
                    None,
                    None,
                    "2026-07-25T00:00:01Z",
                    "DIRECT_INJECTION",
                ),
            ),
        ):
            attempt_id = new_uuid7()
            with self.subTest(status=status):
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "StateStore-managed"
                ):
                    self.store._connection.execute(
                        """
                        INSERT INTO review_attempts(
                            review_attempt_id, review_context_id, job_id,
                            content_id, review_decision, repository_id,
                            pull_number, status,
                            github_review_id, submitted_at, prepared_at,
                            activated_at, invalidated_at, invalidation_reason
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            attempt_id,
                            f"dohwa-review-context-attempt/v1:{attempt_id}",
                            self.job.id,
                            self.context.content_id,
                            "pass",
                            42,
                            7,
                            status,
                            lifecycle[0],
                            lifecycle[1],
                            "2026-07-25T00:00:00Z",
                            lifecycle[2],
                            lifecycle[3],
                            lifecycle[4],
                        ),
                    )

    def test_arbitrary_transaction_does_not_authorize_lifecycle_update(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        with self.store._transaction() as db:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "StateStore-managed"
            ):
                db.execute(
                    """
                    UPDATE review_attempts
                    SET status = 'INVALIDATED', invalidated_at = 'now',
                        invalidation_reason = 'DIRECT_UPDATE'
                    WHERE review_context_id = ?
                    """,
                    (attempt.review_context_id,),
                )
        self.assertEqual(
            ReviewAttemptStatus.PREPARED,
            self.store.get_review_attempt(attempt.review_context_id).status,
        )

    def test_draft_and_close_events_invalidate_open_attempts(self):
        prepared = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store.ingest(
            replace(
                pull_event("draft"),
                action="converted_to_draft",
                is_draft=True,
            )
        )
        invalidated = self.store.get_review_attempt(prepared.review_context_id)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, invalidated.status)
        self.assertEqual("JOB_WAITING_READY", invalidated.invalidation_reason)
        with self.assertRaisesRegex(RuntimeError, "no longer active"):
            self.store.prepare_review_attempt(
                job_id=self.job.id,
                content_id=self.context.content_id, review_decision="pass",
            )

        reopened = self.store.ingest(
            replace(pull_event("ready"), action="ready_for_review")
        ).job
        reopened_attempt = self.store.prepare_review_attempt(
            job_id=reopened.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            reopened_attempt.review_context_id
        )
        active = self.store.activate_review_attempt(
            reopened_attempt.review_context_id,
            github_review_id=9001,
            submitted_at="2026-07-25T00:00:00Z",
        )
        self.store.ingest(
            replace(
                pull_event("closed"),
                action="closed",
                is_merged=False,
            )
        )
        closed_attempt = self.store.get_review_attempt(active.review_context_id)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, closed_attempt.status)
        self.assertEqual("JOB_CLOSED", closed_attempt.invalidation_reason)

    def test_synchronize_invalidates_old_head_and_unblocks_new_head(self):
        old_attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        new_head = "f" * 40
        discovered = self.store.ingest(
            replace(
                pull_event("discovered-new-head"),
                action="labeled",
                head_sha=new_head,
            )
        ).job
        new_job = self.store.transition(discovered.id, ReviewState.QUEUED)
        new_context = self.store.store_review_context(
            review_context(head_sha=new_head, diff_sha256="e" * 64)
        )
        with self.assertRaisesRegex(RuntimeError, "open review attempt"):
            self.store.prepare_review_attempt(
                job_id=new_job.id,
                content_id=new_context.content_id, review_decision="pass",
            )

        synchronized = self.store.ingest(
            replace(
                pull_event("synchronize"),
                action="synchronize",
                head_sha=new_head,
            )
        ).job
        self.assertEqual(new_job.id, synchronized.id)
        invalidated = self.store.get_review_attempt(old_attempt.review_context_id)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, invalidated.status)
        self.assertEqual(
            "JOB_OBSOLETE_NEW_HEAD", invalidated.invalidation_reason
        )
        replacement = self.store.prepare_review_attempt(
            job_id=new_job.id,
            content_id=new_context.content_id, review_decision="pass",
        )
        self.assertEqual(ReviewAttemptStatus.PREPARED, replacement.status)

    def test_terminal_transition_invalidates_active_attempt_in_same_transaction(self):
        reviewing = self.store.transition(
            self.job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        reviewing_attempt = self.store.prepare_review_attempt(
            job_id=reviewing.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            reviewing_attempt.review_context_id
        )
        active = self.store.activate_review_attempt(
            reviewing_attempt.review_context_id,
            github_review_id=9001,
            submitted_at="2026-07-25T00:00:00Z",
        )
        self.store.transition(
            reviewing.id,
            ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
        )
        invalidated = self.store.get_review_attempt(active.review_context_id)
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, invalidated.status)
        self.assertEqual("JOB_HUMAN_REVIEW", invalidated.invalidation_reason)

    def test_confirmed_invalidated_context_allows_new_attempt_for_same_content(self):
        reviewing = self.store.transition(
            self.job.id, ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        first = self.store.prepare_review_attempt(
            job_id=reviewing.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(first.review_context_id)
        self.store.activate_review_attempt(
            first.review_context_id,
            github_review_id=9020,
            submitted_at="2026-07-25T00:00:00Z",
        )
        self.store.transition(
            reviewing.id, ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
        )
        self.store.transition(
            reviewing.id, ReviewState.QUEUED,
            expected=ReviewState.HUMAN_REVIEW,
        )

        replacement = self.store.prepare_review_attempt(
            job_id=reviewing.id,
            content_id=self.context.content_id, review_decision="pass",
        )

        self.assertNotEqual(first.review_attempt_id, replacement.review_attempt_id)
        self.assertNotEqual(first.review_context_id, replacement.review_context_id)
        self.assertEqual(ReviewAttemptStatus.PREPARED, replacement.status)

    def test_restart_requeue_preserves_prepared_attempt(self):
        reviewing = self.store.transition(
            self.job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        attempt = self.store.prepare_review_attempt(
            job_id=reviewing.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        report = self.store.recover_after_restart()
        self.assertIn(reviewing.id, report.requeued_job_ids)
        recovered = self.store.get_review_attempt(attempt.review_context_id)
        self.assertEqual(ReviewAttemptStatus.PREPARED, recovered.status)

    def test_same_head_base_change_invalidates_attempt_and_requeues_job(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id,
            review_decision="pass",
        )

        replacement = self.store.ingest(
            replace(
                pull_event("base-change"),
                action="edited",
                base_sha="e" * 40,
            )
        ).job

        assert replacement is not None
        self.assertEqual(self.job.id, replacement.id)
        self.assertEqual("e" * 40, replacement.base_sha)
        self.assertEqual(ReviewState.QUEUED, replacement.state)
        invalidated = self.store.get_review_attempt(attempt.review_context_id)
        assert invalidated is not None
        self.assertEqual(ReviewAttemptStatus.INVALIDATED, invalidated.status)
        self.assertEqual("BASE_CONTEXT_CHANGED", invalidated.invalidation_reason)

    def test_maybe_sent_is_durable_and_cannot_be_republished(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.assertEqual(
            "NOT_SENT",
            self.store.get_review_attempt_publish_state(
                attempt.review_context_id
            ),
        )
        self.assertEqual(
            "MAYBE_SENT",
            self.store.mark_review_attempt_publish_maybe_sent(
                attempt.review_context_id
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "reconcile marker"):
            self.store.mark_review_attempt_publish_maybe_sent(
                attempt.review_context_id
            )

        self.store.close()
        self.store = StateStore(self.db_path)
        self.assertEqual(
            "MAYBE_SENT",
            self.store.get_review_attempt_publish_state(
                attempt.review_context_id
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "reconcile marker"):
            self.store.mark_review_attempt_publish_maybe_sent(
                attempt.review_context_id
            )

    def test_publish_state_direct_sql_update_is_blocked(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "StateStore-managed"
        ):
            self.store._connection.execute(
                """
                UPDATE review_attempts SET publish_state = 'MAYBE_SENT',
                    publish_started_at = 'now'
                WHERE review_context_id = ?
                """,
                (attempt.review_context_id,),
            )

    def test_legacy_style_active_update_cannot_leave_not_sent(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        with self.store._allow_review_attempt_write():
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "publish invariant"
            ):
                self.store._connection.execute(
                    """
                    UPDATE review_attempts
                    SET status = 'ACTIVE', github_review_id = 9010,
                        submitted_at = '2026-07-25T00:00:00Z',
                        activated_at = 'legacy-active'
                    WHERE review_context_id = ?
                    """,
                    (attempt.review_context_id,),
                )

    def test_existing_f1_active_row_migrates_to_confirmed_publication(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id,
            content_id=self.context.content_id, review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        self.store.activate_review_attempt(
            attempt.review_context_id,
            github_review_id=9011,
            submitted_at="2026-07-25T00:00:00Z",
        )
        self.store.close()
        with sqlite3.connect(self.db_path) as legacy:
            legacy.execute(
                "DROP TRIGGER review_attempts_lifecycle_no_direct_update"
            )
            legacy.execute(
                "DROP TRIGGER review_attempts_publish_invariant_update"
            )
            legacy.execute(
                """
                UPDATE review_attempts
                SET publish_state = 'NOT_SENT', publish_started_at = NULL,
                    publish_confirmed_at = NULL
                WHERE review_context_id = ?
                """,
                (attempt.review_context_id,),
            )

        self.store = StateStore(self.db_path)
        row = self.store._connection.execute(
            """
            SELECT publish_state, publish_started_at, publish_confirmed_at
            FROM review_attempts WHERE review_context_id = ?
            """,
            (attempt.review_context_id,),
        ).fetchone()
        self.assertEqual("CONFIRMED", row["publish_state"])
        self.assertIsNotNone(row["publish_started_at"])
        self.assertIsNotNone(row["publish_confirmed_at"])

    def test_genuine_legacy_invalidated_publication_is_attributed(self):
        legacy_path = Path(self.temporary_directory.name) / "legacy.sqlite3"
        published_id = new_uuid7()
        unpublished_id = new_uuid7()
        open_id = new_uuid7()
        with sqlite3.connect(legacy_path) as legacy:
            legacy.execute("CREATE TABLE schema_metadata(version INTEGER NOT NULL)")
            legacy.execute("INSERT INTO schema_metadata VALUES (1)")
            legacy.execute(
                """
                CREATE TABLE review_attempts (
                    review_attempt_id TEXT PRIMARY KEY,
                    review_context_id TEXT NOT NULL UNIQUE,
                    job_id INTEGER NOT NULL REFERENCES review_jobs(id),
                    content_id TEXT NOT NULL REFERENCES review_context_contents(content_id),
                    repository_id INTEGER NOT NULL,
                    pull_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    github_review_id INTEGER,
                    submitted_at TEXT,
                    prepared_at TEXT NOT NULL,
                    activated_at TEXT,
                    invalidated_at TEXT,
                    invalidation_reason TEXT
                )
                """
            )
            legacy.executemany(
                """
                INSERT INTO review_attempts(
                    review_attempt_id, review_context_id, job_id, content_id,
                    repository_id, pull_number, status, github_review_id,
                    submitted_at, prepared_at, activated_at, invalidated_at,
                    invalidation_reason
                ) VALUES (?, ?, ?, ?, 42, ?, 'INVALIDATED', ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        published_id,
                        f"dohwa-review-context-attempt/v1:{published_id}",
                        1, "a" * 64, 7, 9100,
                        "2026-07-25T00:00:00Z", "prepared-published",
                        "activated-published", "invalidated-published",
                        "JOB_HUMAN_REVIEW",
                    ),
                    (
                        unpublished_id,
                        f"dohwa-review-context-attempt/v1:{unpublished_id}",
                        2, "b" * 64, 8, None, None, "prepared-unpublished",
                        None, "invalidated-unpublished", "JOB_CLOSED",
                    ),
                ),
            )
            legacy.execute(
                """
                INSERT INTO review_attempts(
                    review_attempt_id, review_context_id, job_id, content_id,
                    repository_id, pull_number, status, prepared_at
                ) VALUES (?, ?, 3, ?, 42, 9, 'PREPARED', 'prepared-open')
                """,
                (
                    open_id,
                    f"dohwa-review-context-attempt/v1:{open_id}",
                    "c" * 64,
                ),
            )

        with StateStore(legacy_path) as migrated:
            rows = migrated._connection.execute(
                """
                SELECT review_attempt_id, review_decision, status, publish_state,
                    publish_started_at, publish_confirmed_at, invalidated_at,
                    invalidation_reason
                FROM review_attempts ORDER BY pull_number
                """
            ).fetchall()

        self.assertEqual("CONFIRMED", rows[0]["publish_state"])
        self.assertEqual("activated-published", rows[0]["publish_started_at"])
        self.assertEqual("activated-published", rows[0]["publish_confirmed_at"])
        self.assertEqual("invalidated-published", rows[0]["invalidated_at"])
        self.assertEqual("JOB_HUMAN_REVIEW", rows[0]["invalidation_reason"])
        self.assertEqual("NOT_SENT", rows[1]["publish_state"])
        self.assertIsNone(rows[1]["publish_started_at"])
        self.assertIsNone(rows[1]["publish_confirmed_at"])
        self.assertEqual("JOB_CLOSED", rows[1]["invalidation_reason"])
        self.assertIsNone(rows[2]["review_decision"])
        self.assertEqual("INVALIDATED", rows[2]["status"])
        self.assertEqual("NOT_SENT", rows[2]["publish_state"])
        self.assertIsNotNone(rows[2]["invalidated_at"])
        self.assertEqual(
            "UNBOUND_LEGACY_REVIEW_DECISION",
            rows[2]["invalidation_reason"],
        )

    def test_trusted_marker_terminal_attribution_releases_maybe_sent_lane(self):
        reviewing = self.store.transition(
            self.job.id, ReviewState.REVIEWING,
            expected=ReviewState.QUEUED,
        )
        attempt = self.store.prepare_review_attempt(
            job_id=reviewing.id, content_id=self.context.content_id,
            review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        self.store.transition(
            reviewing.id, ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
        )
        original_terminal = self.store.get_review_attempt(
            attempt.review_context_id
        )

        attributed = self.store.confirm_invalidated_review_attempt_publication(
            attempt.review_context_id,
            github_review_id=9030,
            submitted_at="2026-07-25T00:00:00Z",
        )

        self.assertEqual(ReviewAttemptStatus.INVALIDATED, attributed.status)
        self.assertEqual(9030, attributed.github_review_id)
        self.assertEqual(
            "JOB_HUMAN_REVIEW",
            attributed.invalidation_reason,
        )
        self.assertEqual(
            original_terminal.invalidated_at, attributed.invalidated_at
        )
        self.assertEqual(
            "CONFIRMED",
            self.store.get_review_attempt_publish_state(
                attempt.review_context_id
            ),
        )
        self.assertEqual(
            attributed,
            self.store.confirm_invalidated_review_attempt_publication(
                attempt.review_context_id,
                github_review_id=9030,
                submitted_at="2026-07-25T00:00:00Z",
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "not an invalidated unresolved"):
            self.store.confirm_invalidated_review_attempt_publication(
                attempt.review_context_id,
                github_review_id=9031,
                submitted_at="2026-07-25T00:00:00Z",
            )

        self.store.transition(
            reviewing.id, ReviewState.QUEUED,
            expected=ReviewState.HUMAN_REVIEW,
        )
        replacement = self.store.prepare_review_attempt(
            job_id=reviewing.id, content_id=self.context.content_id,
            review_decision="pass",
        )
        self.assertNotEqual(attempt.review_attempt_id, replacement.review_attempt_id)

    def test_terminal_attribution_rejects_arbitrary_valid_context_invalidation(self):
        attempt = self.store.prepare_review_attempt(
            job_id=self.job.id, content_id=self.context.content_id,
            review_decision="pass",
        )
        self.store.mark_review_attempt_publish_maybe_sent(
            attempt.review_context_id
        )
        self.store.invalidate_review_attempt(
            attempt.review_context_id, reason="MANUAL_INVALIDATION"
        )

        with self.assertRaisesRegex(RuntimeError, "context remains valid"):
            self.store.confirm_invalidated_review_attempt_publication(
                attempt.review_context_id,
                github_review_id=9040,
                submitted_at="2026-07-25T00:00:00Z",
            )

if __name__ == "__main__":
    unittest.main()
