from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading

from reviewer.approval import (
    APPROVAL_REVIEW_DECISION,
    APPROVAL_SOURCE_VERSION,
    Approval,
    ApprovalSource,
    ApprovalStatus,
    LabelEventDisposition,
    GithubClockObservation,
    evaluate_approval_ttl,
    REVIEW_CONTEXT_ALGORITHM,
    ReviewAttempt,
    ReviewAttemptStatus,
    ReviewContextContent,
    StoredReviewContext,
    new_uuid7,
    require_uuid7,
)
from reviewer.merge_descriptor import CIRequestInputs, MergeDescriptor
from reviewer.models import (
    ACTIVE_STATES,
    CIRequestPlan,
    CIRequestState,
    IngestResult,
    RecoveryReport,
    ReviewJob,
    ReviewState,
    StoredMergeDescriptor,
    WebhookEvent,
    validate_transition,
)


COMPATIBLE_STATE_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_APPROVAL_ATTESTATION_DOMAIN = b"dohwa-bot/approval-attestation/v1\0"
_APPROVAL_RECONCILIATION_CLAIM_LEASE = timedelta(minutes=2)


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._review_attempt_write = threading.local()
        self._approval_write = threading.local()
        self._connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.create_function(
            "state_store_review_attempt_write_allowed",
            0,
            lambda: int(
                getattr(self._review_attempt_write, "depth", 0) > 0
            ),
        )
        self._connection.create_function(
            "state_store_approval_write_allowed",
            0,
            lambda: int(getattr(self._approval_write, "depth", 0) > 0),
        )
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    @contextmanager
    def _allow_review_attempt_write(self) -> Iterator[None]:
        depth = getattr(self._review_attempt_write, "depth", 0)
        self._review_attempt_write.depth = depth + 1
        try:
            yield
        finally:
            self._review_attempt_write.depth = depth

    @contextmanager
    def _allow_approval_write(self) -> Iterator[None]:
        depth = getattr(self._approval_write, "depth", 0)
        self._approval_write.depth = depth + 1
        try:
            yield
        finally:
            self._approval_write.depth = depth

    @contextmanager
    def _approval_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._allow_approval_write():
            with self._transaction() as db:
                yield db

    def _migrate(self) -> None:
        with self._transaction() as db:
            self._create_v1_schema(db)
            row = db.execute(
                "SELECT version FROM schema_metadata LIMIT 1"
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO schema_metadata(version) VALUES (?)",
                    (1,),
                )
                version = 1
            else:
                version = row["version"]
            if version != COMPATIBLE_STATE_SCHEMA_VERSION:
                raise RuntimeError(
                    f"unsupported state schema version: {version}"
                )
            self._create_phase3_foundation_schema(db)
            with self._allow_review_attempt_write():
                self._upgrade_review_attempt_publish_schema(db)
            self._create_phase3_approval_schema(db)
            self._upgrade_approval_outbox_delivery_schema(db)
            self._create_approval_reconciliation_schema(db)

    @staticmethod
    def _create_v1_schema(db: sqlite3.Connection) -> None:
        statements = (
            "CREATE TABLE IF NOT EXISTS schema_metadata (version INTEGER NOT NULL)",
            """
            CREATE TABLE IF NOT EXISTS review_jobs (
                id INTEGER PRIMARY KEY,
                repository_id INTEGER,
                repository TEXT NOT NULL,
                pull_number INTEGER NOT NULL,
                base_sha TEXT,
                head_sha TEXT NOT NULL,
                state TEXT NOT NULL,
                queued_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                review_decision TEXT,
                findings_hash TEXT,
                github_review_id INTEGER,
                github_comment_id INTEGER,
                discord_message_id TEXT,
                discord_thread_id TEXT,
                merge_sha TEXT,
                last_error TEXT,
                retry_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(repository, pull_number, head_sha)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_review_jobs_queue
                ON review_jobs(state, retry_at, queued_at)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_review_jobs_pull
                ON review_jobs(repository, pull_number, updated_at)
            """,
            """
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                event_name TEXT NOT NULL,
                action TEXT,
                repository TEXT,
                pull_number INTEGER,
                head_sha TEXT,
                job_id INTEGER REFERENCES review_jobs(id),
                received_at TEXT NOT NULL
            )
            """,
        )
        for statement in statements:
            db.execute(statement)

    @staticmethod
    def _create_phase3_foundation_schema(db: sqlite3.Connection) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS merge_descriptors (
                id INTEGER PRIMARY KEY,
                job_id INTEGER NOT NULL REFERENCES review_jobs(id),
                repository_id INTEGER NOT NULL CHECK(repository_id > 0),
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                object_format TEXT NOT NULL CHECK(object_format = 'sha1'),
                base_oid TEXT NOT NULL
                    CHECK(length(base_oid) = 40 AND base_oid NOT GLOB '*[^0-9a-f]*'),
                head_oid TEXT NOT NULL
                    CHECK(length(head_oid) = 40 AND head_oid NOT GLOB '*[^0-9a-f]*'),
                merge_base_oid TEXT NOT NULL
                    CHECK(length(merge_base_oid) = 40 AND merge_base_oid NOT GLOB '*[^0-9a-f]*'),
                tree_oid TEXT NOT NULL
                    CHECK(length(tree_oid) = 40 AND tree_oid NOT GLOB '*[^0-9a-f]*'),
                candidate_oid TEXT NOT NULL
                    CHECK(length(candidate_oid) = 40 AND candidate_oid NOT GLOB '*[^0-9a-f]*'),
                workflow_sha TEXT NOT NULL
                    CHECK(length(workflow_sha) = 40 AND workflow_sha NOT GLOB '*[^0-9a-f]*'),
                ci_profile TEXT NOT NULL CHECK(length(ci_profile) > 0),
                git_profile TEXT NOT NULL CHECK(length(git_profile) > 0),
                policy_version TEXT NOT NULL CHECK(length(policy_version) > 0),
                canonical_bytes BLOB NOT NULL CHECK(typeof(canonical_bytes) = 'blob'),
                descriptor_digest TEXT NOT NULL UNIQUE
                    CHECK(length(descriptor_digest) = 64 AND descriptor_digest NOT GLOB '*[^0-9a-f]*'),
                created_at TEXT NOT NULL,
                UNIQUE(job_id, descriptor_digest)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_merge_descriptors_job
                ON merge_descriptors(job_id, created_at)
            """,
            """
            CREATE TABLE IF NOT EXISTS ci_requests (
                request_id TEXT PRIMARY KEY
                    CHECK(length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
                review_context_id TEXT NOT NULL
                    CHECK(
                        length(review_context_id) BETWEEN 1 AND 256
                        AND substr(review_context_id, 1, 1) GLOB '[A-Za-z0-9]'
                        AND review_context_id NOT GLOB '*[^A-Za-z0-9._:/-]*'
                    ),
                descriptor_id INTEGER NOT NULL REFERENCES merge_descriptors(id),
                workflow_id INTEGER NOT NULL CHECK(workflow_id > 0),
                workflow_path TEXT NOT NULL CHECK(length(workflow_path) > 0),
                workflow_sha TEXT NOT NULL
                    CHECK(length(workflow_sha) = 40 AND workflow_sha NOT GLOB '*[^0-9a-f]*'),
                workflow_definition_sha256 TEXT NOT NULL
                    CHECK(
                        length(workflow_definition_sha256) = 64
                        AND workflow_definition_sha256 NOT GLOB '*[^0-9a-f]*'
                    ),
                ci_profile TEXT NOT NULL CHECK(length(ci_profile) > 0),
                expected_actor TEXT NOT NULL
                    CHECK(
                        expected_actor = lower(expected_actor)
                        AND length(expected_actor) BETWEEN 1 AND 44
                        AND (
                            (
                                substr(expected_actor, -5) != '[bot]'
                                AND expected_actor NOT GLOB '*[^a-z0-9-]*'
                                AND substr(expected_actor, 1, 1) != '-'
                                AND substr(expected_actor, -1) != '-'
                                AND instr(expected_actor, '--') = 0
                            )
                            OR (
                                substr(expected_actor, -5) = '[bot]'
                                AND length(expected_actor) BETWEEN 6 AND 44
                                AND substr(expected_actor, 1, length(expected_actor) - 5)
                                    NOT GLOB '*[^a-z0-9-]*'
                                AND substr(expected_actor, 1, 1) != '-'
                                AND substr(expected_actor, length(expected_actor) - 5, 1) != '-'
                                AND instr(
                                    substr(expected_actor, 1, length(expected_actor) - 5),
                                    '--'
                                ) = 0
                            )
                        )
                    ),
                expected_installation_id INTEGER NOT NULL
                    CHECK(expected_installation_id > 0),
                dispatch_not_before TEXT NOT NULL
                    CHECK(
                        length(dispatch_not_before) = 20
                        AND dispatch_not_before GLOB
                            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
                    ),
                canonical_inputs BLOB NOT NULL CHECK(typeof(canonical_inputs) = 'blob'),
                inputs_digest TEXT NOT NULL UNIQUE
                    CHECK(length(inputs_digest) = 64 AND inputs_digest NOT GLOB '*[^0-9a-f]*'),
                state TEXT NOT NULL CHECK(state IN ('PLANNED', 'BLOCKED')),
                blocked_reason TEXT,
                created_at TEXT NOT NULL,
                CHECK(
                    (state = 'PLANNED' AND blocked_reason IS NULL)
                    OR (state = 'BLOCKED' AND length(blocked_reason) > 0)
                ),
                UNIQUE(descriptor_id, request_id)
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_ci_requests_descriptor
                ON ci_requests(descriptor_id, created_at)
            """,
            """
            CREATE TABLE IF NOT EXISTS review_context_contents (
                content_id TEXT PRIMARY KEY
                    CHECK(length(content_id) = 64 AND content_id NOT GLOB '*[^0-9a-f]*'),
                algorithm_id TEXT NOT NULL
                    CHECK(algorithm_id = 'dohwa-bot/review-context-content/v1'),
                canonical_payload BLOB NOT NULL CHECK(typeof(canonical_payload) = 'blob'),
                repository_id INTEGER NOT NULL CHECK(repository_id > 0),
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                base_sha TEXT NOT NULL
                    CHECK(length(base_sha) = 40 AND base_sha NOT GLOB '*[^0-9a-f]*'),
                head_sha TEXT NOT NULL
                    CHECK(length(head_sha) = 40 AND head_sha NOT GLOB '*[^0-9a-f]*'),
                merge_base_sha TEXT NOT NULL
                    CHECK(length(merge_base_sha) = 40 AND merge_base_sha NOT GLOB '*[^0-9a-f]*'),
                diff_sha256 TEXT NOT NULL
                    CHECK(length(diff_sha256) = 64 AND diff_sha256 NOT GLOB '*[^0-9a-f]*'),
                policy_version TEXT NOT NULL CHECK(length(policy_version) BETWEEN 1 AND 64),
                created_at TEXT NOT NULL,
                UNIQUE(algorithm_id, canonical_payload)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS review_publications (
                marker TEXT PRIMARY KEY CHECK(length(marker) BETWEEN 1 AND 1000),
                job_id INTEGER NOT NULL REFERENCES review_jobs(id),
                event TEXT NOT NULL CHECK(event IN ('COMMENT', 'REQUEST_CHANGES')),
                publish_state TEXT NOT NULL
                    CHECK(publish_state IN ('MAYBE_SENT', 'CONFIRMED')),
                github_review_id INTEGER,
                publish_started_at TEXT NOT NULL,
                publish_confirmed_at TEXT,
                CHECK(
                    (publish_state = 'MAYBE_SENT'
                        AND github_review_id IS NULL
                        AND publish_confirmed_at IS NULL)
                    OR (publish_state = 'CONFIRMED'
                        AND github_review_id > 0
                        AND publish_confirmed_at IS NOT NULL)
                )
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS review_attempts (
                review_attempt_id TEXT PRIMARY KEY,
                review_context_id TEXT NOT NULL UNIQUE,
                job_id INTEGER NOT NULL REFERENCES review_jobs(id),
                content_id TEXT NOT NULL REFERENCES review_context_contents(content_id),
                review_decision TEXT NOT NULL
                    CHECK(review_decision = 'pass'),
                repository_id INTEGER NOT NULL CHECK(repository_id > 0),
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                status TEXT NOT NULL CHECK(status IN ('PREPARED', 'ACTIVE', 'INVALIDATED')),
                publish_state TEXT NOT NULL DEFAULT 'NOT_SENT'
                    CHECK(publish_state IN ('NOT_SENT', 'MAYBE_SENT', 'CONFIRMED')),
                publish_started_at TEXT,
                publish_confirmed_at TEXT,
                github_review_id INTEGER,
                submitted_at TEXT,
                prepared_at TEXT NOT NULL,
                activated_at TEXT,
                invalidated_at TEXT,
                invalidation_reason TEXT,
                UNIQUE(review_context_id, content_id),
                CHECK(
                    (status = 'PREPARED'
                        AND github_review_id IS NULL AND submitted_at IS NULL
                        AND activated_at IS NULL AND invalidated_at IS NULL
                        AND invalidation_reason IS NULL)
                    OR (status = 'ACTIVE'
                        AND github_review_id > 0 AND submitted_at IS NOT NULL
                        AND activated_at IS NOT NULL AND invalidated_at IS NULL
                        AND invalidation_reason IS NULL)
                    OR (status = 'INVALIDATED'
                        AND invalidated_at IS NOT NULL AND length(invalidation_reason) > 0)
                )
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_review_attempts_open_pull
                ON review_attempts(repository_id, pull_number)
                WHERE status IN ('PREPARED', 'ACTIVE')
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_review_attempts_open_job
                ON review_attempts(job_id)
                WHERE status IN ('PREPARED', 'ACTIVE')
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_review_attempts_github_review
                ON review_attempts(repository_id, github_review_id)
                WHERE github_review_id IS NOT NULL
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_context_contents_no_update
            BEFORE UPDATE ON review_context_contents BEGIN
                SELECT RAISE(ABORT, 'review context content is immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_context_contents_no_delete
            BEFORE DELETE ON review_context_contents BEGIN
                SELECT RAISE(ABORT, 'review context content is immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_attempts_no_direct_insert
            BEFORE INSERT ON review_attempts
            WHEN state_store_review_attempt_write_allowed() != 1
            BEGIN
                SELECT RAISE(ABORT, 'review attempt insert is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_attempts_identity_no_update
            BEFORE UPDATE OF review_attempt_id, review_context_id, job_id, content_id,
                review_decision, repository_id, pull_number, prepared_at
            ON review_attempts BEGIN
                SELECT RAISE(ABORT, 'review attempt identity is immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_attempts_lifecycle_no_direct_update
            BEFORE UPDATE OF status, publish_state, publish_started_at,
                publish_confirmed_at, github_review_id, submitted_at,
                activated_at, invalidated_at, invalidation_reason ON review_attempts
            WHEN state_store_review_attempt_write_allowed() != 1
            BEGIN
                SELECT RAISE(ABORT, 'review attempt lifecycle is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_attempts_transition_guard
            BEFORE UPDATE OF status ON review_attempts
            WHEN NOT (
                (OLD.status = 'PREPARED' AND NEW.status IN ('ACTIVE', 'INVALIDATED'))
                OR (OLD.status = 'ACTIVE' AND NEW.status = 'INVALIDATED')
            ) BEGIN
                SELECT RAISE(ABORT, 'invalid review attempt transition');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS review_attempts_no_delete
            BEFORE DELETE ON review_attempts BEGIN
                SELECT RAISE(ABORT, 'review attempt is durable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS merge_descriptors_no_update
            BEFORE UPDATE ON merge_descriptors
            BEGIN
                SELECT RAISE(ABORT, 'merge descriptors are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS merge_descriptors_no_delete
            BEFORE DELETE ON merge_descriptors
            BEGIN
                SELECT RAISE(ABORT, 'merge descriptors are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS ci_requests_no_update
            BEFORE UPDATE ON ci_requests
            BEGIN
                SELECT RAISE(ABORT, 'CI requests are immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS ci_requests_no_delete
            BEFORE DELETE ON ci_requests
            BEGIN
                SELECT RAISE(ABORT, 'CI requests are immutable');
            END
            """,
        )
        for statement in statements:
            db.execute(statement)

    @staticmethod
    def _upgrade_review_attempt_publish_schema(db: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(review_attempts)").fetchall()
        }
        if "publish_state" not in columns:
            db.execute(
                """
                ALTER TABLE review_attempts ADD COLUMN publish_state TEXT NOT NULL
                    DEFAULT 'NOT_SENT'
                    CHECK(publish_state IN ('NOT_SENT', 'MAYBE_SENT', 'CONFIRMED'))
                """
            )
        if "publish_started_at" not in columns:
            db.execute(
                "ALTER TABLE review_attempts ADD COLUMN publish_started_at TEXT"
            )
        if "publish_confirmed_at" not in columns:
            db.execute(
                "ALTER TABLE review_attempts ADD COLUMN publish_confirmed_at TEXT"
            )
        if "review_decision" not in columns:
            db.execute(
                """
                ALTER TABLE review_attempts ADD COLUMN review_decision TEXT
                """
            )
        db.execute(
            """
            UPDATE review_attempts
            SET publish_state = 'CONFIRMED',
                publish_started_at = COALESCE(
                    publish_started_at, activated_at, invalidated_at, prepared_at
                ),
                publish_confirmed_at = COALESCE(
                    publish_confirmed_at, activated_at, invalidated_at, prepared_at
                )
            WHERE publish_state = 'NOT_SENT'
              AND github_review_id IS NOT NULL
              AND submitted_at IS NOT NULL
            """
        )
        db.execute(
            """
            UPDATE review_attempts
            SET status = 'INVALIDATED',
                invalidated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                invalidation_reason = 'UNBOUND_LEGACY_REVIEW_DECISION'
            WHERE status IN ('PREPARED', 'ACTIVE')
              AND review_decision IS NOT 'pass'
            """
        )
        db.execute("DROP TRIGGER IF EXISTS review_attempts_identity_no_update")
        db.execute(
            """
            CREATE TRIGGER review_attempts_identity_no_update
            BEFORE UPDATE OF review_attempt_id, review_context_id, job_id, content_id,
                review_decision, repository_id, pull_number, prepared_at
            ON review_attempts BEGIN
                SELECT RAISE(ABORT, 'review attempt identity is immutable');
            END
            """
        )
        db.execute("DROP TRIGGER IF EXISTS review_attempts_lifecycle_no_direct_update")
        db.execute(
            """
            CREATE TRIGGER review_attempts_lifecycle_no_direct_update
            BEFORE UPDATE OF status, publish_state, publish_started_at,
                publish_confirmed_at, github_review_id, submitted_at,
                activated_at, invalidated_at, invalidation_reason ON review_attempts
            WHEN state_store_review_attempt_write_allowed() != 1
            BEGIN
                SELECT RAISE(ABORT, 'review attempt lifecycle is StateStore-managed');
            END
            """
        )
        db.execute("DROP TRIGGER IF EXISTS review_attempts_publish_invariant_insert")
        db.execute("DROP TRIGGER IF EXISTS review_attempts_publish_invariant_update")
        invariant = """
            NOT (
                (NEW.status = 'PREPARED' AND (
                    (NEW.publish_state = 'NOT_SENT'
                        AND NEW.publish_started_at IS NULL
                        AND NEW.publish_confirmed_at IS NULL)
                    OR (NEW.publish_state = 'MAYBE_SENT'
                        AND NEW.publish_started_at IS NOT NULL
                        AND NEW.publish_confirmed_at IS NULL)
                ))
                OR (NEW.status = 'ACTIVE'
                    AND NEW.publish_state = 'CONFIRMED'
                    AND NEW.publish_started_at IS NOT NULL
                    AND NEW.publish_confirmed_at IS NOT NULL)
                OR (NEW.status = 'INVALIDATED' AND (
                    (NEW.publish_state = 'NOT_SENT'
                        AND NEW.publish_started_at IS NULL
                        AND NEW.publish_confirmed_at IS NULL)
                    OR (NEW.publish_state = 'MAYBE_SENT'
                        AND NEW.publish_started_at IS NOT NULL
                        AND NEW.publish_confirmed_at IS NULL)
                    OR (NEW.publish_state = 'CONFIRMED'
                        AND NEW.publish_started_at IS NOT NULL
                        AND NEW.publish_confirmed_at IS NOT NULL)
                ))
            )
        """
        db.execute(
            f"""
            CREATE TRIGGER review_attempts_publish_invariant_insert
            BEFORE INSERT ON review_attempts
            WHEN state_store_review_attempt_write_allowed() = 1
                AND {invariant}
            BEGIN
                SELECT RAISE(ABORT, 'review attempt publish invariant violated');
            END
            """
        )
        db.execute("DROP TRIGGER IF EXISTS review_attempts_decision_invariant_insert")
        db.execute("DROP TRIGGER IF EXISTS review_attempts_decision_invariant_update")
        decision_invariant = """
            NEW.status IN ('PREPARED', 'ACTIVE')
                AND NEW.review_decision IS NOT 'pass'
        """
        db.execute(
            f"""
            CREATE TRIGGER review_attempts_decision_invariant_insert
            BEFORE INSERT ON review_attempts
            WHEN {decision_invariant}
            BEGIN
                SELECT RAISE(ABORT, 'open review attempt must bind a pass decision');
            END
            """
        )
        db.execute(
            f"""
            CREATE TRIGGER review_attempts_decision_invariant_update
            BEFORE UPDATE OF status, review_decision ON review_attempts
            WHEN {decision_invariant}
            BEGIN
                SELECT RAISE(ABORT, 'open review attempt must bind a pass decision');
            END
            """
        )
        db.execute(
            f"""
            CREATE TRIGGER review_attempts_publish_invariant_update
            BEFORE UPDATE OF status, publish_state, publish_started_at,
                publish_confirmed_at ON review_attempts
            WHEN state_store_review_attempt_write_allowed() = 1
                AND {invariant}
            BEGIN
                SELECT RAISE(ABORT, 'review attempt publish invariant violated');
            END
            """
        )

    @staticmethod
    def _create_phase3_approval_schema(db: sqlite3.Connection) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS github_label_events (
                event_id TEXT PRIMARY KEY,
                repository_id INTEGER NOT NULL CHECK(repository_id > 0),
                repository TEXT NOT NULL,
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                label_node_id TEXT NOT NULL,
                label_name TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('LABELED', 'UNLABELED')),
                actor_type TEXT,
                actor_github_user_id INTEGER,
                actor_node_id TEXT,
                actor_login TEXT,
                created_at TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal > 0),
                predecessor_event_id TEXT,
                generation INTEGER NOT NULL CHECK(generation >= 0),
                disposition TEXT NOT NULL CHECK(disposition IN (
                    'ORDER_ONLY_NO_APPROVAL', 'SIGNED_APPROVAL_CANDIDATE',
                    'REJECTED_AMBIGUOUS'
                )),
                recorded_at TEXT NOT NULL,
                UNIQUE(repository_id, pull_number, ordinal)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS github_label_webhook_evidence (
                delivery_id TEXT PRIMARY KEY,
                payload_sha256 TEXT NOT NULL
                    CHECK(length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
                event_id TEXT REFERENCES github_label_events(event_id),
                review_context_id TEXT REFERENCES review_attempts(review_context_id),
                repository_id INTEGER,
                repository TEXT,
                installation_id INTEGER,
                pull_number INTEGER,
                action TEXT,
                label_id INTEGER,
                label_node_id TEXT,
                label_name TEXT,
                sender_type TEXT,
                sender_github_user_id INTEGER,
                sender_node_id TEXT,
                sender_login TEXT,
                signed_base_sha TEXT,
                signed_head_sha TEXT,
                pull_updated_at TEXT,
                outcome TEXT NOT NULL CHECK(outcome IN ('ACCEPTED', 'REJECTED')),
                rejection_reason TEXT,
                received_at TEXT NOT NULL,
                CHECK(
                    (outcome = 'ACCEPTED' AND event_id IS NOT NULL AND rejection_reason IS NULL)
                    OR (outcome = 'REJECTED' AND rejection_reason IS NOT NULL)
                )
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_github_label_evidence_event
                ON github_label_webhook_evidence(event_id)
                WHERE event_id IS NOT NULL
            """,
            """
            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                source TEXT NOT NULL CHECK(source = 'github_label'),
                source_version TEXT NOT NULL CHECK(source_version = 'approval-ttl/v1'),
                status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACTIVE', 'CONSUMED', 'INVALIDATED')),
                repository_id INTEGER NOT NULL CHECK(repository_id > 0),
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                review_context_id TEXT NOT NULL REFERENCES review_attempts(review_context_id),
                review_attempt_id TEXT NOT NULL REFERENCES review_attempts(review_attempt_id),
                content_id TEXT NOT NULL REFERENCES review_context_contents(content_id),
                label_event_id TEXT NOT NULL UNIQUE REFERENCES github_label_events(event_id),
                webhook_delivery_id TEXT NOT NULL UNIQUE REFERENCES github_label_webhook_evidence(delivery_id),
                approver_github_user_id INTEGER NOT NULL CHECK(approver_github_user_id > 0),
                generation INTEGER NOT NULL CHECK(generation > 0),
                event_created_at TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attestation_digest TEXT NOT NULL UNIQUE
                    CHECK(length(attestation_digest) = 64
                        AND attestation_digest NOT GLOB '*[^0-9a-f]*'),
                invalidated_at TEXT,
                invalidation_reason TEXT,
                CHECK(
                    (status = 'INVALIDATED' AND invalidated_at IS NOT NULL AND invalidation_reason IS NOT NULL)
                    OR (status != 'INVALIDATED' AND invalidated_at IS NULL AND invalidation_reason IS NULL)
                )
            )
            """,
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_open_context
                ON approvals(review_context_id)
                WHERE status IN ('PENDING', 'ACTIVE')
            """,
            """
            CREATE TABLE IF NOT EXISTS approval_transition_audit (
                id INTEGER PRIMARY KEY,
                approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
                sequence INTEGER NOT NULL CHECK(sequence > 0),
                from_status TEXT,
                to_status TEXT NOT NULL,
                reason TEXT,
                recorded_at TEXT NOT NULL,
                UNIQUE(approval_id, sequence)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS github_label_events_no_direct_insert
            BEFORE INSERT ON github_label_events
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'label event insert is StateStore-managed');
            END
            """,
            """
            CREATE TABLE IF NOT EXISTS approval_outbox (
                id INTEGER PRIMARY KEY,
                approval_id TEXT REFERENCES approvals(approval_id),
                delivery_id TEXT NOT NULL REFERENCES github_label_webhook_evidence(delivery_id),
                action TEXT NOT NULL CHECK(action IN ('REMOVE_LABEL', 'DISCORD_REPORT')),
                repository TEXT NOT NULL,
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                label_name TEXT,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                delivered_at TEXT,
                claimed_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0
                    CHECK(attempt_count >= 0),
                last_error TEXT,
                retry_at TEXT,
                UNIQUE(delivery_id, action)
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS github_label_evidence_no_direct_insert
            BEFORE INSERT ON github_label_webhook_evidence
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'webhook evidence insert is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS github_label_events_no_update
            BEFORE UPDATE ON github_label_events BEGIN
                SELECT RAISE(ABORT, 'label event ledger is immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_audit_no_direct_insert
            BEFORE INSERT ON approval_transition_audit
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'approval audit insert is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS github_label_events_no_delete
            BEFORE DELETE ON github_label_events BEGIN
                SELECT RAISE(ABORT, 'label event ledger is append-only');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_outbox_no_direct_insert
            BEFORE INSERT ON approval_outbox
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'approval outbox insert is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_outbox_no_direct_update
            BEFORE UPDATE ON approval_outbox
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'approval outbox lifecycle is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS github_label_evidence_no_update
            BEFORE UPDATE ON github_label_webhook_evidence BEGIN
                SELECT RAISE(ABORT, 'webhook evidence is terminal');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS github_label_evidence_no_delete
            BEFORE DELETE ON github_label_webhook_evidence BEGIN
                SELECT RAISE(ABORT, 'webhook evidence is durable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approvals_no_direct_insert
            BEFORE INSERT ON approvals
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'approval insert is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approvals_identity_no_update
            BEFORE UPDATE OF approval_id, source, source_version, repository_id,
                pull_number, review_context_id, review_attempt_id, content_id,
                label_event_id, webhook_delivery_id, approver_github_user_id,
                generation, event_created_at, accepted_at, expires_at
                , attestation_digest
            ON approvals BEGIN
                SELECT RAISE(ABORT, 'approval identity is immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approvals_no_direct_lifecycle_update
            BEFORE UPDATE OF status, invalidated_at, invalidation_reason ON approvals
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(ABORT, 'approval lifecycle is StateStore-managed');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approvals_transition_guard
            BEFORE UPDATE OF status ON approvals
            WHEN NOT (
                (OLD.status = 'PENDING' AND NEW.status IN ('ACTIVE', 'INVALIDATED'))
                OR (OLD.status = 'ACTIVE' AND NEW.status IN ('CONSUMED', 'INVALIDATED'))
            ) BEGIN
                SELECT RAISE(ABORT, 'invalid approval transition');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approvals_no_delete
            BEFORE DELETE ON approvals BEGIN
                SELECT RAISE(ABORT, 'approval is durable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_audit_no_update
            BEFORE UPDATE ON approval_transition_audit BEGIN
                SELECT RAISE(ABORT, 'approval audit is append-only');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_audit_no_delete
            BEFORE DELETE ON approval_transition_audit BEGIN
                SELECT RAISE(ABORT, 'approval audit is append-only');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_outbox_identity_no_update
            BEFORE UPDATE OF id, approval_id, delivery_id, action, repository,
                pull_number, label_name, payload, created_at ON approval_outbox BEGIN
                SELECT RAISE(ABORT, 'approval outbox action is immutable');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_outbox_no_delete
            BEFORE DELETE ON approval_outbox BEGIN
                SELECT RAISE(ABORT, 'approval outbox is durable');
            END
            """,
        )
        for statement in statements:
            db.execute(statement)

    @staticmethod
    def _upgrade_approval_outbox_delivery_schema(
        db: sqlite3.Connection,
    ) -> None:
        columns = {
            row["name"]
            for row in db.execute("PRAGMA table_info(approval_outbox)").fetchall()
        }
        if "claimed_at" not in columns:
            db.execute("ALTER TABLE approval_outbox ADD COLUMN claimed_at TEXT")
        if "attempt_count" not in columns:
            db.execute(
                """
                ALTER TABLE approval_outbox ADD COLUMN attempt_count INTEGER
                    NOT NULL DEFAULT 0 CHECK(attempt_count >= 0)
                """
            )
        if "last_error" not in columns:
            db.execute("ALTER TABLE approval_outbox ADD COLUMN last_error TEXT")
        if "retry_at" not in columns:
            db.execute("ALTER TABLE approval_outbox ADD COLUMN retry_at TEXT")

    @staticmethod
    def _create_approval_reconciliation_schema(
        db: sqlite3.Connection,
    ) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS approval_reconciliation_queue (
                id INTEGER PRIMARY KEY,
                delivery_id TEXT NOT NULL UNIQUE CHECK(length(delivery_id) > 0),
                payload_sha256 TEXT NOT NULL
                    CHECK(length(payload_sha256) = 64
                        AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
                event_name TEXT NOT NULL CHECK(length(event_name) > 0),
                action TEXT NOT NULL CHECK(action IN ('labeled', 'unlabeled')),
                repository_id INTEGER NOT NULL CHECK(repository_id > 0),
                repository TEXT NOT NULL CHECK(length(repository) > 0),
                installation_id INTEGER NOT NULL CHECK(installation_id > 0),
                pull_number INTEGER NOT NULL CHECK(pull_number > 0),
                signed_base_sha TEXT NOT NULL
                    CHECK(length(signed_base_sha) = 40
                        AND signed_base_sha NOT GLOB '*[^0-9a-f]*'),
                signed_head_sha TEXT NOT NULL
                    CHECK(length(signed_head_sha) = 40
                        AND signed_head_sha NOT GLOB '*[^0-9a-f]*'),
                is_draft INTEGER CHECK(is_draft IN (0, 1)),
                is_merged INTEGER CHECK(is_merged IN (0, 1)),
                merge_sha TEXT
                    CHECK(merge_sha IS NULL OR (
                        length(merge_sha) = 40
                        AND merge_sha NOT GLOB '*[^0-9a-f]*'
                    )),
                label_id INTEGER NOT NULL CHECK(label_id > 0),
                label_node_id TEXT NOT NULL CHECK(length(label_node_id) > 0),
                label_name TEXT NOT NULL CHECK(length(label_name) > 0),
                sender_github_user_id INTEGER NOT NULL
                    CHECK(sender_github_user_id > 0),
                sender_node_id TEXT NOT NULL CHECK(length(sender_node_id) > 0),
                sender_login TEXT NOT NULL CHECK(length(sender_login) > 0),
                sender_type TEXT NOT NULL CHECK(length(sender_type) > 0),
                pull_updated_at TEXT NOT NULL
                    CHECK(
                        length(pull_updated_at) = 20
                        AND pull_updated_at GLOB (
                            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T'
                            || '[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
                        )
                    ),
                expected_policy_version TEXT NOT NULL
                    CHECK(
                        length(expected_policy_version) BETWEEN 1 AND 64
                        AND expected_policy_version NOT GLOB '*[^A-Za-z0-9._-]*'
                    ),
                received_at TEXT NOT NULL,
                deadline_at TEXT NOT NULL,
                retry_at TEXT,
                claimed_at TEXT,
                lease_expires_at TEXT,
                attempt_count INTEGER NOT NULL DEFAULT 0
                    CHECK(attempt_count >= 0),
                last_error TEXT,
                completed_at TEXT,
                CHECK(deadline_at > received_at),
                CHECK(
                    (claimed_at IS NULL AND lease_expires_at IS NULL)
                    OR (claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL)
                ),
                CHECK(
                    completed_at IS NULL
                    OR (
                        claimed_at IS NULL
                        AND lease_expires_at IS NULL
                        AND retry_at IS NULL
                    )
                )
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_approval_reconciliation_claim
                ON approval_reconciliation_queue(
                    completed_at, retry_at, lease_expires_at, id
                )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_approval_reconciliation_lane
                ON approval_reconciliation_queue(
                    repository_id, pull_number, id, completed_at
                )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_reconciliation_no_direct_insert
            BEFORE INSERT ON approval_reconciliation_queue
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(
                    ABORT,
                    'approval reconciliation insert is StateStore-managed'
                );
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_reconciliation_no_direct_update
            BEFORE UPDATE ON approval_reconciliation_queue
            WHEN state_store_approval_write_allowed() != 1 BEGIN
                SELECT RAISE(
                    ABORT,
                    'approval reconciliation lifecycle is StateStore-managed'
                );
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_reconciliation_identity_no_update
            BEFORE UPDATE OF id, delivery_id, payload_sha256, event_name, action,
                repository_id, repository, installation_id, pull_number,
                signed_base_sha, signed_head_sha, is_draft, is_merged, merge_sha,
                label_id, label_node_id, label_name, sender_github_user_id,
                sender_node_id, sender_login, sender_type, pull_updated_at,
                expected_policy_version, received_at, deadline_at
            ON approval_reconciliation_queue BEGIN
                SELECT RAISE(
                    ABORT,
                    'approval reconciliation identity is immutable'
                );
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_reconciliation_completion_fence
            BEFORE UPDATE OF completed_at ON approval_reconciliation_queue
            WHEN NEW.completed_at IS NOT NULL
              AND OLD.completed_at IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM github_label_webhook_evidence AS evidence
                  WHERE evidence.delivery_id = NEW.delivery_id
              )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'approval reconciliation requires terminal evidence'
                );
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_reconciliation_no_reopen
            BEFORE UPDATE OF completed_at ON approval_reconciliation_queue
            WHEN OLD.completed_at IS NOT NULL
              AND NEW.completed_at IS NOT OLD.completed_at
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'approval reconciliation completion is terminal'
                );
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS approval_reconciliation_no_delete
            BEFORE DELETE ON approval_reconciliation_queue BEGIN
                SELECT RAISE(ABORT, 'approval reconciliation is durable');
            END
            """,
        )
        for statement in statements:
            db.execute(statement)

    def ingest(self, event: WebhookEvent) -> IngestResult:
        now = _timestamp()
        with self._transaction() as db:
            inserted = db.execute(
                """
                INSERT OR IGNORE INTO webhook_deliveries(
                    delivery_id, event_name, action, repository,
                    pull_number, head_sha, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.delivery_id,
                    event.event_name,
                    event.action,
                    event.repository,
                    event.pull_number,
                    event.head_sha,
                    now,
                ),
            )
            if inserted.rowcount == 0:
                row = db.execute(
                    """
                    SELECT j.*
                    FROM webhook_deliveries d
                    LEFT JOIN review_jobs j ON j.id = d.job_id
                    WHERE d.delivery_id = ?
                    """,
                    (event.delivery_id,),
                ).fetchone()
                job = (
                    _job_from_row(row)
                    if row is not None and row["id"] is not None
                    else None
                )
                return IngestResult(False, False, job)

            if not event.has_pull_request or event.event_name != "pull_request":
                return IngestResult(True, False, None)

            target = _initial_state(event)
            assert event.repository is not None
            assert event.pull_number is not None
            assert event.head_sha is not None

            repository_identities = {
                row["repository_id"]
                for row in db.execute(
                    """
                    SELECT DISTINCT repository_id
                    FROM review_jobs
                    WHERE repository = ?
                      AND repository_id IS NOT NULL
                    """,
                    (event.repository,),
                ).fetchall()
            }
            if repository_identities and (
                event.repository_id is None
                or repository_identities != {event.repository_id}
            ):
                return IngestResult(True, False, None)

            if event.action in {
                "opened",
                "reopened",
                "ready_for_review",
                "synchronize",
            }:
                self._obsolete_other_heads(
                    db,
                    event.repository,
                    event.pull_number,
                    event.head_sha,
                    event.repository_id,
                    now,
                )

            existing = db.execute(
                """
                SELECT * FROM review_jobs
                WHERE repository = ? AND pull_number = ? AND head_sha = ?
                """,
                (event.repository, event.pull_number, event.head_sha),
            ).fetchone()
            created = existing is None
            if existing is None:
                queued_at = now if target is ReviewState.QUEUED else None
                finished_at = now if target in {
                    ReviewState.CLOSED,
                    ReviewState.MERGED,
                } else None
                cursor = db.execute(
                    """
                    INSERT INTO review_jobs(
                        repository_id, repository, pull_number, base_sha,
                        head_sha, state, queued_at, finished_at, merge_sha,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.repository_id,
                        event.repository,
                        event.pull_number,
                        event.base_sha,
                        event.head_sha,
                        target.value,
                        queued_at,
                        finished_at,
                        event.merge_sha if target is ReviewState.MERGED else None,
                        now,
                        now,
                    ),
                )
                job_id = cursor.lastrowid
            else:
                job_id = existing["id"]
                current = ReviewState(existing["state"])
                if (
                    existing["repository_id"] is not None
                    and event.repository_id is not None
                    and existing["repository_id"] != event.repository_id
                ):
                    return IngestResult(True, False, None)
                base_changed = (
                    event.base_sha is not None
                    and event.base_sha != existing["base_sha"]
                    and (
                        current not in {ReviewState.CLOSED, ReviewState.MERGED}
                        or event.action in {"reopened", "bootstrap_reconcile"}
                    )
                )
                if base_changed:
                    self._invalidate_job_attempts(
                        db,
                        (job_id,),
                        reason="BASE_CONTEXT_CHANGED",
                        now=now,
                    )
                    replacement = (
                        target
                        if target is not ReviewState.DISCOVERED
                        else ReviewState.QUEUED
                    )
                    queued_at = now if replacement is ReviewState.QUEUED else None
                    finished_at = (
                        now
                        if replacement in {ReviewState.CLOSED, ReviewState.MERGED}
                        else None
                    )
                    db.execute(
                        """
                        UPDATE review_jobs
                        SET state = ?, base_sha = ?,
                            repository_id = COALESCE(repository_id, ?),
                            queued_at = ?, started_at = NULL, finished_at = ?,
                            review_decision = NULL, findings_hash = NULL,
                            github_review_id = NULL, github_comment_id = NULL,
                            discord_message_id = NULL, discord_thread_id = NULL,
                            merge_sha = NULL, last_error = NULL, retry_at = NULL,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            replacement.value,
                            event.base_sha,
                            event.repository_id,
                            queued_at,
                            finished_at,
                            now,
                            job_id,
                        ),
                    )
                    target = replacement
                elif current != target and _event_may_transition(
                    event.action, current, target
                ):
                    validate_transition(current, target)
                    db.execute(
                        """
                        UPDATE review_jobs
                        SET state = ?,
                            base_sha = COALESCE(?, base_sha),
                            repository_id = COALESCE(repository_id, ?),
                            queued_at = CASE WHEN ? = 'QUEUED' THEN ? ELSE queued_at END,
                            finished_at = CASE
                                WHEN ? IN ('CLOSED', 'MERGED') THEN ?
                                WHEN ? IN ('QUEUED', 'WAITING_READY') THEN NULL
                                ELSE finished_at
                            END,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            target.value,
                            event.base_sha,
                            event.repository_id,
                            target.value,
                            now,
                            target.value,
                            now,
                            target.value,
                            now,
                            job_id,
                        ),
                    )

            if target is ReviewState.MERGED:
                db.execute(
                    """
                    UPDATE review_jobs
                    SET merge_sha = COALESCE(?, merge_sha),
                        last_error = NULL,
                        finished_at = COALESCE(finished_at, ?),
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (event.merge_sha, now, now, job_id),
                )

            persisted = db.execute(
                "SELECT state FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            self._invalidate_if_job_left_review_context(
                db,
                job_id,
                ReviewState(persisted["state"]),
                now=now,
            )
            db.execute(
                "UPDATE webhook_deliveries SET job_id = ? WHERE delivery_id = ?",
                (job_id, event.delivery_id),
            )
            row = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            return IngestResult(True, created, _job_from_row(row))

    def archive_webhook_delivery(self, event: WebhookEvent) -> bool:
        now = _timestamp()
        with self._transaction() as db:
            inserted = db.execute(
                """
                INSERT OR IGNORE INTO webhook_deliveries(
                    delivery_id, event_name, action, repository,
                    pull_number, head_sha, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.delivery_id,
                    event.event_name,
                    event.action,
                    event.repository,
                    event.pull_number,
                    event.head_sha,
                    now,
                ),
            )
        return inserted.rowcount == 1

    def get_job(
        self, repository: str, pull_number: int, head_sha: str
    ) -> ReviewJob | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM review_jobs
                WHERE repository = ? AND pull_number = ? AND head_sha = ?
                """,
                (repository, pull_number, head_sha),
            ).fetchone()
        return _job_from_row(row) if row else None

    def get_job_by_id(self, job_id: int) -> ReviewJob | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job_from_row(row) if row else None

    def bind_job_repository_id(
        self,
        job_id: int,
        repository_id: int,
    ) -> ReviewJob:
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            raise ValueError("repository_id must be a positive integer")
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown review job: {job_id}")
            if row["repository_id"] not in {None, repository_id}:
                raise RuntimeError("review job repository identity changed")
            if row["repository_id"] is None:
                db.execute(
                    """
                    UPDATE review_jobs SET repository_id = ?, updated_at = ?
                    WHERE id = ? AND repository_id IS NULL
                    """,
                    (repository_id, now, job_id),
                )
            persisted = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job_from_row(persisted)

    def store_merge_descriptor(
        self,
        job_id: int,
        descriptor: MergeDescriptor,
    ) -> StoredMergeDescriptor:
        canonical_bytes = descriptor.canonical_bytes
        digest = descriptor.digest
        MergeDescriptor.from_canonical_bytes(canonical_bytes)
        now = _timestamp()
        with self._transaction() as db:
            job = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if job is None:
                raise KeyError(f"unknown review job: {job_id}")
            if job["repository_id"] != descriptor.repository_id:
                raise ValueError("descriptor repository_id does not match review job")
            if job["pull_number"] != descriptor.pull_number:
                raise ValueError("descriptor pull_number does not match review job")
            if job["base_sha"] != descriptor.base_oid:
                raise ValueError("descriptor base_oid does not match review job")
            if job["head_sha"] != descriptor.head_oid:
                raise ValueError("descriptor head_oid does not match review job")
            inserted = db.execute(
                """
                INSERT OR IGNORE INTO merge_descriptors(
                    job_id, repository_id, pull_number, object_format,
                    base_oid, head_oid, merge_base_oid, tree_oid,
                    candidate_oid, workflow_sha, ci_profile, git_profile,
                    policy_version, canonical_bytes, descriptor_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    descriptor.repository_id,
                    descriptor.pull_number,
                    descriptor.object_format,
                    descriptor.base_oid,
                    descriptor.head_oid,
                    descriptor.merge_base_oid,
                    descriptor.tree_oid,
                    descriptor.candidate_oid,
                    descriptor.workflow_sha,
                    descriptor.ci_profile,
                    descriptor.git_profile,
                    descriptor.policy_version,
                    sqlite3.Binary(canonical_bytes),
                    digest,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM merge_descriptors WHERE descriptor_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise RuntimeError("merge descriptor insert did not persist")
            if inserted.rowcount == 0 and (
                row["job_id"] != job_id or bytes(row["canonical_bytes"]) != canonical_bytes
            ):
                raise RuntimeError("descriptor digest collision or context mismatch")
        return _stored_descriptor_from_row(row)

    def get_merge_descriptor(self, descriptor_digest: str) -> StoredMergeDescriptor | None:
        if _SHA256.fullmatch(descriptor_digest) is None:
            raise ValueError("descriptor_digest must be a lowercase SHA-256")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM merge_descriptors WHERE descriptor_digest = ?",
                (descriptor_digest,),
            ).fetchone()
        if row is None:
            return None
        descriptor = MergeDescriptor.from_canonical_bytes(bytes(row["canonical_bytes"]))
        if descriptor.digest != row["descriptor_digest"]:
            raise RuntimeError("stored merge descriptor digest mismatch")
        return _stored_descriptor_from_row(row)

    def create_ci_request(
        self,
        *,
        descriptor_digest: str,
        inputs: CIRequestInputs,
        state: CIRequestState,
        blocked_reason: str | None = None,
    ) -> CIRequestPlan:
        if _SHA256.fullmatch(descriptor_digest) is None:
            raise ValueError("descriptor_digest must be a lowercase SHA-256")
        if not isinstance(state, CIRequestState):
            raise ValueError("state must be a CIRequestState")
        if state is CIRequestState.PLANNED and blocked_reason is not None:
            raise ValueError("PLANNED request cannot have blocked_reason")
        if state is CIRequestState.BLOCKED and not blocked_reason:
            raise ValueError("BLOCKED request requires blocked_reason")

        canonical_inputs = inputs.canonical_bytes
        inputs_digest = inputs.digest
        CIRequestInputs.from_canonical_bytes(canonical_inputs)
        now = _timestamp()
        with self._transaction() as db:
            descriptor_row = db.execute(
                "SELECT * FROM merge_descriptors WHERE descriptor_digest = ?",
                (descriptor_digest,),
            ).fetchone()
            if descriptor_row is None:
                raise KeyError(f"unknown merge descriptor: {descriptor_digest}")
            descriptor = MergeDescriptor.from_canonical_bytes(
                bytes(descriptor_row["canonical_bytes"])
            )
            if inputs.descriptor_digest != descriptor_digest:
                raise ValueError("CI inputs descriptor_digest mismatch")
            if (
                inputs.repository_id != descriptor.repository_id
                or inputs.pull_number != descriptor.pull_number
                or inputs.base_oid != descriptor.base_oid
                or inputs.head_oid != descriptor.head_oid
                or inputs.candidate_oid != descriptor.candidate_oid
                or inputs.workflow_sha != descriptor.workflow_sha
                or inputs.ci_profile != descriptor.ci_profile
            ):
                raise ValueError("CI inputs do not match merge descriptor")
            inserted = db.execute(
                """
                INSERT OR IGNORE INTO ci_requests(
                    request_id, review_context_id, descriptor_id, workflow_id,
                    workflow_path, workflow_sha, workflow_definition_sha256,
                    ci_profile, expected_actor, expected_installation_id,
                    dispatch_not_before, canonical_inputs, inputs_digest,
                    state, blocked_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inputs.request_id,
                    inputs.review_context_id,
                    descriptor_row["id"],
                    inputs.workflow_id,
                    inputs.workflow_path,
                    inputs.workflow_sha,
                    inputs.workflow_definition_sha256,
                    inputs.ci_profile,
                    inputs.expected_actor,
                    inputs.expected_installation_id,
                    inputs.dispatch_not_before,
                    sqlite3.Binary(canonical_inputs),
                    inputs_digest,
                    state.value,
                    blocked_reason,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM ci_requests WHERE request_id = ?",
                (inputs.request_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("CI request insert did not persist")
            if inserted.rowcount == 0 and (
                row["descriptor_id"] != descriptor_row["id"]
                or bytes(row["canonical_inputs"]) != canonical_inputs
                or row["inputs_digest"] != inputs_digest
                or row["review_context_id"] != inputs.review_context_id
                or row["workflow_id"] != inputs.workflow_id
                or row["workflow_path"] != inputs.workflow_path
                or row["workflow_definition_sha256"]
                    != inputs.workflow_definition_sha256
                or row["expected_actor"] != inputs.expected_actor
                or row["expected_installation_id"]
                    != inputs.expected_installation_id
                or row["dispatch_not_before"] != inputs.dispatch_not_before
                or row["state"] != state.value
                or row["blocked_reason"] != blocked_reason
            ):
                raise RuntimeError("request_id is already bound to another immutable plan")
        return _ci_request_from_row(row)

    def get_ci_request(self, request_id: str) -> CIRequestPlan | None:
        if not isinstance(request_id, str) or _SHA256.fullmatch(request_id) is None:
            raise ValueError("request_id must be 64 lowercase hexadecimal characters")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM ci_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            return None
        inputs = CIRequestInputs.from_canonical_bytes(bytes(row["canonical_inputs"]))
        if inputs.digest != row["inputs_digest"]:
            raise RuntimeError("stored CI input digest mismatch")
        if (
            inputs.request_id != row["request_id"]
            or inputs.review_context_id != row["review_context_id"]
            or inputs.workflow_id != row["workflow_id"]
            or inputs.workflow_path != row["workflow_path"]
            or inputs.workflow_sha != row["workflow_sha"]
            or inputs.workflow_definition_sha256
                != row["workflow_definition_sha256"]
            or inputs.ci_profile != row["ci_profile"]
            or inputs.expected_actor != row["expected_actor"]
            or inputs.expected_installation_id != row["expected_installation_id"]
            or inputs.dispatch_not_before != row["dispatch_not_before"]
        ):
            raise RuntimeError("stored CI request identity mismatch")
        return _ci_request_from_row(row)

    def store_review_context(
        self, value: ReviewContextContent
    ) -> StoredReviewContext:
        canonical_bytes = value.canonical_bytes
        parsed = ReviewContextContent.from_canonical_bytes(canonical_bytes)
        if parsed.content_id != value.content_id:
            raise ValueError("review context digest mismatch")
        now = _timestamp()
        with self._transaction() as db:
            inserted = db.execute(
                """
                INSERT OR IGNORE INTO review_context_contents(
                    content_id, algorithm_id, canonical_payload, repository_id,
                    pull_number, base_sha, head_sha, merge_base_sha,
                    diff_sha256, policy_version, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    value.content_id,
                    REVIEW_CONTEXT_ALGORITHM,
                    sqlite3.Binary(canonical_bytes),
                    value.repository_id,
                    value.pull_number,
                    value.base_sha,
                    value.head_sha,
                    value.merge_base_sha,
                    value.diff_sha256,
                    value.policy_version,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM review_context_contents WHERE content_id = ?",
                (value.content_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("review context insert did not persist")
            if inserted.rowcount == 0 and (
                row["algorithm_id"] != REVIEW_CONTEXT_ALGORITHM
                or bytes(row["canonical_payload"]) != canonical_bytes
            ):
                raise RuntimeError("review context digest collision")
        return _stored_review_context_from_row(row)

    def get_review_context(self, content_id: str) -> StoredReviewContext | None:
        if _SHA256.fullmatch(content_id) is None:
            raise ValueError("content_id must be a lowercase SHA-256")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM review_context_contents WHERE content_id = ?",
                (content_id,),
            ).fetchone()
        return _stored_review_context_from_row(row) if row else None

    def begin_review_publication(
        self,
        *,
        job_id: int,
        marker: str,
        event: str,
    ) -> bool:
        if not marker or len(marker) > 1_000:
            raise ValueError("review publication marker is invalid")
        if event not in {"COMMENT", "REQUEST_CHANGES"}:
            raise ValueError("review publication event is invalid")
        now = _timestamp()
        with self._transaction() as db:
            job = db.execute(
                """
                SELECT id, repository_id, pull_number
                FROM review_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
            if job is None:
                raise KeyError(f"unknown review job: {job_id}")
            if job["repository_id"] is None:
                raise RuntimeError("review job has no repository identity")
            unresolved = db.execute(
                """
                SELECT p.marker
                FROM review_publications p
                JOIN review_jobs j ON j.id = p.job_id
                WHERE j.repository_id = ? AND j.pull_number = ?
                  AND p.publish_state = 'MAYBE_SENT'
                ORDER BY p.publish_started_at, p.marker
                LIMIT 1
                """,
                (job["repository_id"], job["pull_number"]),
            ).fetchone()
            if unresolved is not None and unresolved["marker"] != marker:
                return False
            unresolved_pass = db.execute(
                """
                SELECT 1 FROM review_attempts
                WHERE repository_id = ? AND pull_number = ?
                  AND publish_state = 'MAYBE_SENT'
                LIMIT 1
                """,
                (job["repository_id"], job["pull_number"]),
            ).fetchone()
            if unresolved_pass is not None:
                return False
            inserted = db.execute(
                """
                INSERT OR IGNORE INTO review_publications(
                    marker, job_id, event, publish_state, publish_started_at
                ) VALUES (?, ?, ?, 'MAYBE_SENT', ?)
                """,
                (marker, job_id, event, now),
            )
            row = db.execute(
                "SELECT * FROM review_publications WHERE marker = ?",
                (marker,),
            ).fetchone()
            if row["job_id"] != job_id or row["event"] != event:
                raise RuntimeError("review publication marker identity collision")
            return inserted.rowcount == 1

    def has_unresolved_review_publication(
        self,
        *,
        repository_id: int,
        pull_number: int,
    ) -> bool:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1
                FROM review_publications p
                JOIN review_jobs j ON j.id = p.job_id
                WHERE j.repository_id = ? AND j.pull_number = ?
                  AND p.publish_state = 'MAYBE_SENT'
                LIMIT 1
                """,
                (repository_id, pull_number),
            ).fetchone()
        return row is not None

    def confirm_review_publication(
        self,
        *,
        job_id: int,
        marker: str,
        event: str,
        github_review_id: int,
    ) -> None:
        if (
            isinstance(github_review_id, bool)
            or not isinstance(github_review_id, int)
            or github_review_id <= 0
        ):
            raise ValueError("github_review_id must be a positive integer")
        if event not in {"COMMENT", "REQUEST_CHANGES"}:
            raise ValueError("review publication event is invalid")
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_publications WHERE marker = ?",
                (marker,),
            ).fetchone()
            if row is None:
                db.execute(
                    """
                    INSERT INTO review_publications(
                        marker, job_id, event, publish_state, github_review_id,
                        publish_started_at, publish_confirmed_at
                    ) VALUES (?, ?, ?, 'CONFIRMED', ?, ?, ?)
                    """,
                    (marker, job_id, event, github_review_id, now, now),
                )
                return
            if row["job_id"] != job_id or row["event"] != event:
                raise RuntimeError("review publication marker identity collision")
            if row["publish_state"] == "CONFIRMED":
                if row["github_review_id"] != github_review_id:
                    raise RuntimeError("review publication is bound to another review")
                return
            updated = db.execute(
                """
                UPDATE review_publications
                SET publish_state = 'CONFIRMED', github_review_id = ?,
                    publish_confirmed_at = ?
                WHERE marker = ? AND publish_state = 'MAYBE_SENT'
                """,
                (github_review_id, now, marker),
            ).rowcount
            if updated != 1:
                raise RuntimeError("review publication confirmation CAS failed")

    def prepare_review_attempt(
        self,
        *,
        job_id: int,
        content_id: str,
        review_decision: str,
    ) -> ReviewAttempt:
        if _SHA256.fullmatch(content_id) is None:
            raise ValueError("content_id must be a lowercase SHA-256")
        if review_decision != APPROVAL_REVIEW_DECISION:
            raise ValueError(
                "approval-capable review attempt requires a pass decision"
            )
        with self._transaction() as db:
            job = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            content = db.execute(
                "SELECT * FROM review_context_contents WHERE content_id = ?",
                (content_id,),
            ).fetchone()
            if job is None:
                raise KeyError(f"unknown review job: {job_id}")
            if content is None:
                raise KeyError(f"unknown review context content: {content_id}")
            _validate_review_job_context(job, content)
            unresolved_generic = db.execute(
                """
                SELECT 1
                FROM review_publications p
                JOIN review_jobs j ON j.id = p.job_id
                WHERE j.repository_id = ? AND j.pull_number = ?
                  AND p.publish_state = 'MAYBE_SENT'
                LIMIT 1
                """,
                (content["repository_id"], content["pull_number"]),
            ).fetchone()
            if unresolved_generic is not None:
                raise RuntimeError(
                    "pull request has an unresolved generic MAYBE_SENT review"
                )
            existing = db.execute(
                """
                SELECT * FROM review_attempts
                WHERE repository_id = ? AND pull_number = ?
                  AND status IN ('PREPARED', 'ACTIVE')
                """,
                (content["repository_id"], content["pull_number"]),
            ).fetchone()
            if existing is not None:
                if (
                    existing["job_id"] == job_id
                    and existing["content_id"] == content_id
                ):
                    return _review_attempt_from_row(existing)
                raise RuntimeError(
                    "pull request already has an open review attempt"
                )
            unresolved_publish = db.execute(
                """
                SELECT review_context_id FROM review_attempts
                WHERE repository_id = ? AND pull_number = ?
                  AND publish_state = 'MAYBE_SENT'
                ORDER BY prepared_at LIMIT 1
                """,
                (content["repository_id"], content["pull_number"]),
            ).fetchone()
            if unresolved_publish is not None:
                raise RuntimeError(
                    "pull request has an unresolved MAYBE_SENT review; "
                    "reconcile its marker before preparing a replacement"
                )
            attempt_id = new_uuid7()
            context_id = f"dohwa-review-context-attempt/v1:{attempt_id}"
            prepared_at = _timestamp()
            with self._allow_review_attempt_write():
                db.execute(
                    """
                    INSERT INTO review_attempts(
                        review_attempt_id, review_context_id, job_id, content_id,
                        review_decision, repository_id, pull_number, status,
                        prepared_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?)
                    """,
                    (
                        attempt_id,
                        context_id,
                        job_id,
                        content_id,
                        review_decision,
                        content["repository_id"],
                        content["pull_number"],
                        prepared_at,
                    ),
                )
            row = db.execute(
                "SELECT * FROM review_attempts WHERE review_attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        return _review_attempt_from_row(row)

    def get_review_attempt(self, review_context_id: str) -> ReviewAttempt | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
        return _review_attempt_from_row(row) if row else None

    def get_review_attempt_publish_state(self, review_context_id: str) -> str:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT publish_state FROM review_attempts
                WHERE review_context_id = ?
                """,
                (review_context_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown review context: {review_context_id}")
        return str(row["publish_state"])

    def mark_review_attempt_publish_maybe_sent(
        self, review_context_id: str
    ) -> str:
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown review context: {review_context_id}")
            if row["status"] != ReviewAttemptStatus.PREPARED.value:
                raise RuntimeError("only a prepared review attempt can be published")
            if row["publish_state"] != "NOT_SENT":
                raise RuntimeError(
                    "review publish may already have been sent; reconcile marker instead"
                )
            with self._allow_review_attempt_write():
                updated = db.execute(
                    """
                    UPDATE review_attempts
                    SET publish_state = 'MAYBE_SENT', publish_started_at = ?
                    WHERE review_context_id = ? AND status = 'PREPARED'
                      AND publish_state = 'NOT_SENT'
                    """,
                    (now, review_context_id),
                ).rowcount
            if updated != 1:
                raise RuntimeError("review publish state CAS failed")
        return "MAYBE_SENT"

    def activate_review_attempt(
        self,
        review_context_id: str,
        *,
        github_review_id: int,
        submitted_at: str,
    ) -> ReviewAttempt:
        if (
            isinstance(github_review_id, bool)
            or not isinstance(github_review_id, int)
            or github_review_id <= 0
        ):
            raise ValueError("github_review_id must be a positive integer")
        _require_github_timestamp(submitted_at, "submitted_at")
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown review context: {review_context_id}")
            job = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (row["job_id"],)
            ).fetchone()
            content = db.execute(
                "SELECT * FROM review_context_contents WHERE content_id = ?",
                (row["content_id"],),
            ).fetchone()
            if job is None or content is None:
                raise RuntimeError("review attempt dependencies are missing")
            _validate_review_job_context(job, content)
            if row["review_decision"] != APPROVAL_REVIEW_DECISION:
                raise RuntimeError("review attempt is not bound to a pass decision")
            if job["review_decision"] != APPROVAL_REVIEW_DECISION:
                raise RuntimeError("review job decision is not pass")
            if row["status"] == ReviewAttemptStatus.ACTIVE.value:
                if (
                    row["github_review_id"] == github_review_id
                    and row["submitted_at"] == submitted_at
                ):
                    return _review_attempt_from_row(row)
                raise RuntimeError("active review attempt is bound to another review")
            if row["status"] != ReviewAttemptStatus.PREPARED.value:
                raise RuntimeError("review attempt is terminal")
            if row["publish_state"] != "MAYBE_SENT":
                raise RuntimeError(
                    "review publish must be MAYBE_SENT before confirmation"
                )
            with self._allow_review_attempt_write():
                updated_count = db.execute(
                    """
                    UPDATE review_attempts
                    SET status = 'ACTIVE', publish_state = 'CONFIRMED',
                        publish_confirmed_at = ?, github_review_id = ?,
                        submitted_at = ?, activated_at = ?
                    WHERE review_context_id = ? AND status = 'PREPARED'
                      AND publish_state = 'MAYBE_SENT'
                    """,
                    (now, github_review_id, submitted_at, now, review_context_id),
                ).rowcount
            if updated_count != 1:
                raise RuntimeError("review attempt activation CAS failed")
            updated = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
        return _review_attempt_from_row(updated)

    def confirm_invalidated_review_attempt_publication(
        self,
        review_context_id: str,
        *,
        github_review_id: int,
        submitted_at: str,
    ) -> ReviewAttempt:
        if (
            isinstance(github_review_id, bool)
            or not isinstance(github_review_id, int)
            or github_review_id <= 0
        ):
            raise ValueError("github_review_id must be a positive integer")
        _require_github_timestamp(submitted_at, "submitted_at")
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown review context: {review_context_id}")
            if (
                row["status"] == ReviewAttemptStatus.INVALIDATED.value
                and row["publish_state"] == "CONFIRMED"
                and row["github_review_id"] == github_review_id
                and row["submitted_at"] == submitted_at
            ):
                return _review_attempt_from_row(row)
            if (
                row["status"] != ReviewAttemptStatus.INVALIDATED.value
                or row["publish_state"] != "MAYBE_SENT"
                or row["github_review_id"] is not None
                or row["submitted_at"] is not None
            ):
                raise RuntimeError(
                    "review attempt is not an invalidated unresolved publication"
                )
            job = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (row["job_id"],)
            ).fetchone()
            content = db.execute(
                "SELECT * FROM review_context_contents WHERE content_id = ?",
                (row["content_id"],),
            ).fetchone()
            if job is None or content is None:
                raise RuntimeError("review attempt dependencies are missing")
            try:
                _validate_review_job_context(job, content)
            except RuntimeError:
                pass
            else:
                raise RuntimeError(
                    "review context remains valid; terminal attribution is forbidden"
                )
            with self._allow_review_attempt_write():
                updated_count = db.execute(
                    """
                    UPDATE review_attempts
                    SET publish_state = 'CONFIRMED', publish_confirmed_at = ?,
                        github_review_id = ?, submitted_at = ?
                    WHERE review_context_id = ? AND status = 'INVALIDATED'
                      AND publish_state = 'MAYBE_SENT'
                      AND github_review_id IS NULL AND submitted_at IS NULL
                    """,
                    (
                        now, github_review_id, submitted_at, review_context_id,
                    ),
                ).rowcount
            if updated_count != 1:
                raise RuntimeError("review publication attribution CAS failed")
            updated = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
        return _review_attempt_from_row(updated)

    def invalidate_review_attempt(
        self, review_context_id: str, *, reason: str
    ) -> ReviewAttempt:
        if not reason:
            raise ValueError("invalidation reason is required")
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown review context: {review_context_id}")
            if row["status"] == ReviewAttemptStatus.INVALIDATED.value:
                if row["invalidation_reason"] == reason:
                    return _review_attempt_from_row(row)
                raise RuntimeError("review attempt is already terminal")
            with self._allow_review_attempt_write():
                updated_count = db.execute(
                    """
                    UPDATE review_attempts
                    SET status = 'INVALIDATED', invalidated_at = ?,
                        invalidation_reason = ?
                    WHERE review_context_id = ?
                      AND status IN ('PREPARED', 'ACTIVE')
                    """,
                    (now, reason, review_context_id),
                ).rowcount
            if updated_count != 1:
                raise RuntimeError("review attempt invalidation CAS failed")
            updated = db.execute(
                "SELECT * FROM review_attempts WHERE review_context_id = ?",
                (review_context_id,),
            ).fetchone()
        return _review_attempt_from_row(updated)

    def _apply_github_label_approval(
        self,
        *,
        timeline: tuple[dict[str, object], ...],
        snapshot_repository_id: int,
        snapshot_repository: str,
        snapshot_pull_number: int,
        snapshot_total_count: int,
        webhook: WebhookEvent,
        allowed_approver_ids: frozenset[int],
        expected_installation_id: int,
        expected_policy_version: str,
        target_label: str,
        clock: GithubClockObservation,
        monotonic_ns: Callable[[], int],
        evidence_received_at: str | None = None,
        reconciliation_id: int | None = None,
        reconciliation_claimed_at: str | None = None,
        reconciliation_attempt_count: int | None = None,
    ) -> dict[str, object]:
        """Persist one signed label decision and all fail-closed effects atomically."""
        if snapshot_total_count != len(timeline):
            raise ValueError("timeline count does not match its immutable snapshot")
        if evidence_received_at is not None:
            _require_reconciliation_storage_timestamp(evidence_received_at)
        reconciliation_claim = (
            reconciliation_id,
            reconciliation_claimed_at,
            reconciliation_attempt_count,
        )
        if any(value is not None for value in reconciliation_claim):
            if not all(value is not None for value in reconciliation_claim):
                raise ValueError(
                    "approval reconciliation claim fields must be provided together"
                )
            if (
                isinstance(reconciliation_id, bool)
                or not isinstance(reconciliation_id, int)
                or reconciliation_id <= 0
            ):
                raise ValueError(
                    "reconciliation_id must be a positive integer"
                )
            if (
                not isinstance(reconciliation_claimed_at, str)
                or not reconciliation_claimed_at
            ):
                raise ValueError(
                    "reconciliation_claimed_at must be a non-empty string"
                )
            if (
                isinstance(reconciliation_attempt_count, bool)
                or not isinstance(reconciliation_attempt_count, int)
                or reconciliation_attempt_count <= 0
            ):
                raise ValueError(
                    "reconciliation_attempt_count must be a positive integer"
                )
        with self._approval_transaction() as db:
            now = _timestamp()
            reconciliation: sqlite3.Row | None = None
            if reconciliation_id is not None:
                reconciliation = db.execute(
                    """
                    SELECT * FROM approval_reconciliation_queue
                    WHERE id = ?
                    """,
                    (reconciliation_id,),
                ).fetchone()
                if reconciliation is None:
                    raise KeyError(
                        "unknown approval reconciliation row: "
                        f"{reconciliation_id}"
                    )
                if reconciliation["completed_at"] is not None:
                    raise RuntimeError(
                        "approval reconciliation is already terminal"
                    )
                self._require_approval_reconciliation_claim(
                    reconciliation,
                    claimed_at=reconciliation_claimed_at,
                    attempt_count=reconciliation_attempt_count,
                )
                identity = _approval_reconciliation_identity(webhook)
                if any(
                    reconciliation[field] != value
                    for field, value in identity.items()
                ):
                    raise RuntimeError(
                        "approval reconciliation signed identity conflicts"
                    )
                current = datetime.fromisoformat(now)
                deadline = datetime.fromisoformat(
                    str(reconciliation["deadline_at"])
                )
                lease_expires = datetime.fromisoformat(
                    str(reconciliation["lease_expires_at"])
                )
                if current >= deadline:
                    raise RuntimeError(
                        "approval reconciliation deadline expired"
                    )
                if current >= lease_expires:
                    raise RuntimeError(
                        "approval reconciliation claim lease expired"
                    )

            def complete_reconciliation() -> None:
                if reconciliation is None:
                    return
                assert reconciliation_claimed_at is not None
                assert reconciliation_attempt_count is not None
                self._complete_approval_reconciliation_in_transaction(
                    db,
                    reconciliation,
                    completed_at=now,
                    claimed_at=reconciliation_claimed_at,
                    attempt_count=reconciliation_attempt_count,
                )

            previous = db.execute(
                """
                SELECT e.*, a.approval_id, a.attestation_digest,
                    a.invalidation_reason AS approval_reason
                FROM github_label_webhook_evidence e
                LEFT JOIN approvals a ON a.webhook_delivery_id = e.delivery_id
                WHERE e.delivery_id = ?
                LIMIT 1
                """,
                (webhook.delivery_id,),
            ).fetchone()
            if previous is not None:
                if (
                    previous["payload_sha256"] != webhook.payload_sha256
                ):
                    raise RuntimeError("webhook delivery or payload identity conflicts")
                complete_reconciliation()
                generation = None
                if previous["event_id"] is not None:
                    event_row = db.execute(
                        "SELECT generation FROM github_label_events WHERE event_id = ?",
                        (previous["event_id"],),
                    ).fetchone()
                    generation = event_row["generation"] if event_row else None
                return {
                    "delivery_id": webhook.delivery_id,
                    "outcome": previous["outcome"],
                    "reason": (
                        previous["rejection_reason"]
                        or previous["approval_reason"]
                    ),
                    "event_id": previous["event_id"],
                    "approval_id": previous["approval_id"],
                    "generation": generation,
                    "attestation_digest": previous["attestation_digest"],
                    "duplicate": True,
                }

            def move_job_to_human(reason: str) -> None:
                job = db.execute(
                    """
                    SELECT * FROM review_jobs
                    WHERE repository_id = ? AND repository = ? AND pull_number = ?
                      AND head_sha = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (
                        webhook.repository_id,
                        webhook.repository,
                        webhook.pull_number,
                        webhook.head_sha,
                    ),
                ).fetchone()
                if job is None:
                    return
                current = ReviewState(job["state"])
                if current is ReviewState.HUMAN_REVIEW:
                    return
                try:
                    validate_transition(current, ReviewState.HUMAN_REVIEW)
                except ValueError:
                    return
                db.execute(
                    """
                    UPDATE review_jobs
                    SET state = 'HUMAN_REVIEW', finished_at = ?, last_error = ?,
                        retry_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, reason, now, job["id"]),
                )
                self._invalidate_job_attempts(
                    db, (job["id"],), reason=reason, now=now
                )

            def record_evidence(
                *, event_id: str | None, review_context_id: str | None,
                outcome: str, reason: str | None
            ) -> None:
                db.execute(
                    """
                    INSERT INTO github_label_webhook_evidence(
                        delivery_id, payload_sha256, event_id, review_context_id,
                        repository_id,
                        repository, installation_id, pull_number, action,
                        label_id, label_node_id, label_name,
                        sender_type, sender_github_user_id, sender_node_id,
                        sender_login, signed_base_sha, signed_head_sha,
                        pull_updated_at, outcome, rejection_reason, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        webhook.delivery_id,
                        webhook.payload_sha256,
                        event_id,
                        review_context_id,
                        webhook.repository_id,
                        webhook.repository,
                        webhook.installation_id,
                        webhook.pull_number,
                        webhook.action,
                        webhook.label_id,
                        webhook.label_node_id,
                        webhook.label_name,
                        webhook.sender_type,
                        webhook.sender_id,
                        webhook.sender_node_id,
                        webhook.sender_login,
                        webhook.base_sha,
                        webhook.head_sha,
                        webhook.pull_updated_at,
                        outcome,
                        reason,
                        evidence_received_at or now,
                    ),
                )
                complete_reconciliation()

            def reject(reason: str, *, event_id: str | None = None,
                       generation: int | None = None,
                       affects_current: bool = True) -> dict[str, object]:
                record_evidence(
                    event_id=event_id, review_context_id=None,
                    outcome="REJECTED", reason=reason
                )
                db.execute(
                    """
                    INSERT INTO approval_outbox(
                        approval_id, delivery_id, action, repository, pull_number,
                        label_name, payload, created_at
                    ) VALUES (NULL, ?, 'DISCORD_REPORT', ?, ?, ?, ?, ?)
                    """,
                    (
                        webhook.delivery_id, webhook.repository,
                        webhook.pull_number, webhook.label_name,
                        json.dumps(
                            {
                                "reason": reason,
                                "sender_type": webhook.sender_type,
                                "webhook_action": webhook.action,
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        ), now,
                    ),
                )
                if affects_current:
                    move_job_to_human(reason)
                return {
                    "delivery_id": webhook.delivery_id,
                    "outcome": "REJECTED",
                    "reason": reason,
                    "event_id": event_id,
                    "approval_id": None,
                    "generation": generation,
                    "attestation_digest": None,
                    "duplicate": False,
                }

            if (
                webhook.repository_id != snapshot_repository_id
                or webhook.repository != snapshot_repository
                or webhook.pull_number != snapshot_pull_number
            ):
                return reject("SNAPSHOT_IDENTITY_MISMATCH")

            stored = db.execute(
                """
                SELECT * FROM github_label_events
                WHERE repository_id = ? AND pull_number = ?
                ORDER BY ordinal
                """,
                (snapshot_repository_id, snapshot_pull_number),
            ).fetchall()
            if len(stored) > len(timeline):
                return reject("TIMELINE_PREFIX_ROLLBACK")
            immutable_fields = (
                "event_id", "repository_id", "repository", "pull_number",
                "label_node_id", "label_name", "action", "actor_type",
                "actor_github_user_id", "actor_node_id", "actor_login",
                "created_at", "ordinal", "predecessor_event_id",
            )
            for row, item in zip(stored, timeline):
                if any(row[field] != item[field] for field in immutable_fields):
                    return reject("TIMELINE_PREFIX_MISMATCH")

            stored_ids = {row["event_id"] for row in stored}
            matches = [
                item for item in timeline
                if item["repository_id"] == webhook.repository_id
                and item["repository"] == webhook.repository
                and item["pull_number"] == webhook.pull_number
                and str(item["action"]).lower() == webhook.action
                and item["label_node_id"] == webhook.label_node_id
                and item["label_name"] == webhook.label_name
                and item["actor_type"] == webhook.sender_type
                and item["actor_github_user_id"] == webhook.sender_id
                and item["actor_node_id"] == webhook.sender_node_id
                and item["actor_login"] == webhook.sender_login
                and item["created_at"] == webhook.pull_updated_at
            ]
            if len(matches) == 1 and matches[0]["event_id"] in stored_ids:
                recorded = db.execute(
                    "SELECT generation FROM github_label_events WHERE event_id = ?",
                    (matches[0]["event_id"],),
                ).fetchone()
                return reject(
                    "TIMELINE_EVENT_ALREADY_RECORDED",
                    generation=recorded["generation"] if recorded else None,
                    affects_current=False,
                )
            candidates = [
                item for item in matches if item["event_id"] not in stored_ids
            ]
            if len(matches) != 1 or len(candidates) != 1:
                return reject("TIMELINE_EVENT_MATCH_NOT_UNIQUE")
            candidate = candidates[0]
            candidate_index = int(candidate["ordinal"]) - 1

            generations: dict[str, int] = {}
            active: dict[str, bool] = {}
            active_node: dict[str, str] = {}
            event_generation: dict[str, int] = {}
            malformed = False
            previous_id: str | None = None
            for expected_ordinal, item in enumerate(timeline, start=1):
                if (
                    item["ordinal"] != expected_ordinal
                    or item["predecessor_event_id"] != previous_id
                ):
                    malformed = True
                    break
                label = str(item["label_name"])
                generation = generations.get(label, 0)
                is_active = active.get(label, False)
                if item["action"] == "LABELED":
                    if is_active:
                        malformed = True
                        break
                    generation += 1
                    is_active = True
                    active_node[label] = str(item["label_node_id"])
                elif item["action"] == "UNLABELED":
                    if (
                        not is_active
                        or active_node.get(label) != item["label_node_id"]
                    ):
                        malformed = True
                        break
                    is_active = False
                    active_node.pop(label, None)
                else:
                    malformed = True
                    break
                generations[label] = generation
                active[label] = is_active
                event_generation[str(item["event_id"])] = generation
                previous_id = str(item["event_id"])
            if malformed:
                return reject("TIMELINE_ORDER_AMBIGUOUS")
            generation = event_generation[str(candidate["event_id"])]

            reason: str | None = None
            if webhook.action == "labeled" and candidate["actor_type"] != "User":
                reason = "ACTOR_NOT_USER"
            elif candidate["label_name"] != target_label:
                reason = "NON_TARGET_LABEL"
            elif webhook.installation_id != expected_installation_id:
                reason = "INSTALLATION_ID_MISMATCH"
            elif any(
                item["label_name"] == target_label
                for item in timeline[candidate_index + 1 :]
            ):
                reason = "NON_CURRENT_LABEL_EVENT"
            elif webhook.action == "labeled" and not active.get(target_label, False):
                reason = "LABEL_NOT_CURRENTLY_ACTIVE"

            attempt = None
            content = None
            job = None
            ttl = None
            if reason is None and webhook.action == "labeled":
                attempt = db.execute(
                    """
                    SELECT * FROM review_attempts
                    WHERE repository_id = ? AND pull_number = ? AND status = 'ACTIVE'
                    """,
                    (snapshot_repository_id, snapshot_pull_number),
                ).fetchone()
                if attempt is None:
                    prepared = db.execute(
                        """
                        SELECT 1 FROM review_attempts
                        WHERE repository_id = ? AND pull_number = ?
                          AND status = 'PREPARED'
                        LIMIT 1
                        """,
                        (snapshot_repository_id, snapshot_pull_number),
                    ).fetchone()
                    reason = (
                        "LABEL_BEFORE_REVIEW"
                        if prepared is not None
                        else "NO_ACTIVE_REVIEW_ATTEMPT"
                    )
                else:
                    if attempt["review_decision"] != APPROVAL_REVIEW_DECISION:
                        reason = "REVIEW_DECISION_NOT_PASS"
                    else:
                        content = db.execute(
                            "SELECT * FROM review_context_contents WHERE content_id = ?",
                            (attempt["content_id"],),
                        ).fetchone()
                        job = db.execute(
                            "SELECT * FROM review_jobs WHERE id = ?",
                            (attempt["job_id"],),
                        ).fetchone()
                    if reason is None and (content is None or job is None):
                        reason = "REVIEW_CONTEXT_DEPENDENCY_MISSING"
                    elif (
                        reason is None
                        and job["review_decision"] != APPROVAL_REVIEW_DECISION
                    ):
                        reason = "REVIEW_JOB_DECISION_NOT_PASS"
                    elif reason is None and (
                        content["repository_id"] != snapshot_repository_id
                        or content["pull_number"] != snapshot_pull_number
                        or content["base_sha"] != webhook.base_sha
                        or content["head_sha"] != webhook.head_sha
                        or job["base_sha"] != webhook.base_sha
                        or job["head_sha"] != webhook.head_sha
                    ):
                        reason = "SIGNED_REVIEW_CONTEXT_MISMATCH"
                    elif content["policy_version"] != expected_policy_version:
                        reason = "POLICY_VERSION_MISMATCH"
                    elif str(candidate["created_at"]) <= attempt["submitted_at"]:
                        reason = "LABEL_NOT_AFTER_REVIEW"
                    elif webhook.sender_id not in allowed_approver_ids:
                        reason = "APPROVER_NOT_ALLOWED"
                    else:
                        created = datetime.strptime(
                            str(candidate["created_at"]), "%Y-%m-%dT%H:%M:%SZ"
                        ).replace(tzinfo=timezone.utc)
                        transaction_now_ns = monotonic_ns()
                        if (
                            isinstance(transaction_now_ns, bool)
                            or not isinstance(transaction_now_ns, int)
                            or transaction_now_ns < 0
                        ):
                            raise ValueError(
                                "monotonic_ns must return a non-negative integer"
                            )
                        ttl = evaluate_approval_ttl(
                            event_created_at=created,
                            clock=clock,
                            now_monotonic_ns=transaction_now_ns,
                        )
                        if not ttl.is_valid:
                            reason = ttl.decision.value

            disposition = (
                LabelEventDisposition.SIGNED_APPROVAL_CANDIDATE.value
                if reason is None
                else LabelEventDisposition.REJECTED_AMBIGUOUS.value
            )
            for item in timeline[len(stored) : candidate_index + 1]:
                item_disposition = (
                    disposition
                    if item["event_id"] == candidate["event_id"]
                    else LabelEventDisposition.ORDER_ONLY_NO_APPROVAL.value
                )
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
                    tuple(item[field] for field in immutable_fields)
                    + (
                        event_generation[str(item["event_id"])],
                        item_disposition,
                        now,
                    ),
                )
                if (
                    item["label_name"] == target_label
                    and item["action"] == "UNLABELED"
                ):
                    self._invalidate_open_approvals(
                        db,
                        db.execute(
                            """
                            SELECT * FROM approvals
                            WHERE repository_id = ? AND pull_number = ?
                              AND generation = ? AND status = 'ACTIVE'
                            ORDER BY approval_id
                            """,
                            (
                                snapshot_repository_id,
                                snapshot_pull_number,
                                event_generation[str(item["event_id"])],
                            ),
                        ).fetchall(),
                        reason="LABEL_REMOVED",
                        now=now,
                    )

            if reason is not None:
                return reject(
                    reason,
                    event_id=str(candidate["event_id"]),
                    generation=generation,
                    affects_current=reason not in {
                        "NON_CURRENT_LABEL_EVENT", "LABEL_BEFORE_REVIEW",
                    },
                )

            record_evidence(
                event_id=str(candidate["event_id"]),
                review_context_id=(
                    attempt["review_context_id"] if attempt is not None else None
                ),
                outcome="ACCEPTED", reason=None
            )
            if webhook.action == "unlabeled":
                return {
                    "delivery_id": webhook.delivery_id,
                    "outcome": "ACCEPTED",
                    "reason": None,
                    "event_id": candidate["event_id"],
                    "approval_id": None,
                    "generation": generation,
                    "attestation_digest": None,
                    "duplicate": False,
                }

            assert attempt is not None and content is not None and job is not None
            assert ttl is not None
            approval_id = new_uuid7()
            accepted_datetime = datetime.strptime(
                str(candidate["created_at"]), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            accepted_at = accepted_datetime.isoformat(timespec="microseconds")
            event_created_at = str(candidate["created_at"])
            expires_at = ttl.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            approval = Approval(
                approval_id=approval_id,
                source=ApprovalSource.GITHUB_LABEL,
                source_version=APPROVAL_SOURCE_VERSION,
                status=ApprovalStatus.PENDING,
                repository_id=snapshot_repository_id,
                pull_number=snapshot_pull_number,
                review_context_id=attempt["review_context_id"],
                review_attempt_id=attempt["review_attempt_id"],
                content_id=attempt["content_id"],
                label_event_id=str(candidate["event_id"]),
                webhook_delivery_id=webhook.delivery_id,
                approver_github_user_id=webhook.sender_id,
                generation=generation,
                event_created_at=accepted_datetime,
                accepted_at=accepted_datetime,
                expires_at=ttl.expires_at,
            )
            attestation_digest = _approval_attestation_digest(
                approval_id=approval_id,
                repository_id=snapshot_repository_id,
                pull_number=snapshot_pull_number,
                review_context_id=attempt["review_context_id"],
                review_attempt_id=attempt["review_attempt_id"],
                content_id=attempt["content_id"],
                label_event_id=str(candidate["event_id"]),
                webhook_delivery_id=webhook.delivery_id,
                approver_github_user_id=webhook.sender_id,
                generation=generation,
                event_created_at=event_created_at,
                accepted_at=accepted_at,
                expires_at=expires_at,
            )
            with self._allow_approval_write():
                db.execute(
                    """
                    INSERT INTO approvals(
                        approval_id, source, source_version, status, repository_id,
                        pull_number, review_context_id, review_attempt_id, content_id,
                        label_event_id, webhook_delivery_id, approver_github_user_id,
                        generation, event_created_at, accepted_at, expires_at
                        , attestation_digest
                    ) VALUES (?, 'github_label', ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id, APPROVAL_SOURCE_VERSION, snapshot_repository_id,
                        snapshot_pull_number, attempt["review_context_id"],
                        attempt["review_attempt_id"], attempt["content_id"],
                        candidate["event_id"], webhook.delivery_id, webhook.sender_id,
                        generation, event_created_at, accepted_at, expires_at,
                        attestation_digest,
                    ),
                )
            db.execute(
                """
                INSERT INTO approval_transition_audit(
                    approval_id, sequence, from_status, to_status, reason, recorded_at
                ) VALUES (?, 1, NULL, 'PENDING', NULL, ?)
                """,
                (approval_id, now),
            )
            with self._allow_approval_write():
                db.execute(
                    """
                    UPDATE approvals SET status = 'ACTIVE'
                    WHERE approval_id = ? AND status = 'PENDING'
                    """,
                    (approval_id,),
                )
            db.execute(
                """
                INSERT INTO approval_transition_audit(
                    approval_id, sequence, from_status, to_status, reason, recorded_at
                ) VALUES (?, 2, 'PENDING', 'ACTIVE', NULL, ?)
                """,
                (approval_id, now),
            )
            with self._allow_approval_write():
                db.execute(
                    """
                    UPDATE approvals SET status = 'INVALIDATED', invalidated_at = ?,
                        invalidation_reason = 'ATOMIC_SERVER_GATES_UNAVAILABLE'
                    WHERE approval_id = ? AND status = 'ACTIVE'
                    """,
                    (now, approval_id),
                )
            db.execute(
                """
                INSERT INTO approval_transition_audit(
                    approval_id, sequence, from_status, to_status, reason, recorded_at
                ) VALUES (?, 3, 'ACTIVE', 'INVALIDATED',
                    'ATOMIC_SERVER_GATES_UNAVAILABLE', ?)
                """,
                (approval_id, now),
            )
            db.execute(
                """
                UPDATE review_jobs SET state = 'HUMAN_REVIEW', finished_at = ?,
                    last_error = 'ATOMIC_SERVER_GATES_UNAVAILABLE', retry_at = NULL,
                    updated_at = ? WHERE id = ?
                """,
                (now, now, job["id"]),
            )
            outbox_payload = json.dumps(
                {
                    "approval_id": approval_id,
                    "generation": generation,
                    "label_event_id": candidate["event_id"],
                    "reason": "ATOMIC_SERVER_GATES_UNAVAILABLE",
                    "repository_id": snapshot_repository_id,
                    "review_context_id": attempt["review_context_id"],
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            db.executemany(
                """
                INSERT INTO approval_outbox(
                    approval_id, delivery_id, action, repository, pull_number,
                    label_name, payload, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        approval_id, webhook.delivery_id, "REMOVE_LABEL",
                        snapshot_repository, snapshot_pull_number, target_label,
                        outbox_payload, now,
                    ),
                    (
                        approval_id, webhook.delivery_id, "DISCORD_REPORT",
                        snapshot_repository, snapshot_pull_number, None,
                        outbox_payload, now,
                    ),
                ),
            )
            return {
                "delivery_id": webhook.delivery_id,
                "outcome": "ACCEPTED",
                "reason": "ATOMIC_SERVER_GATES_UNAVAILABLE",
                "event_id": candidate["event_id"],
                "approval_id": approval_id,
                "generation": generation,
                "attestation_digest": attestation_digest,
                "duplicate": False,
            }

    def enqueue_approval_reconciliation(
        self,
        event: WebhookEvent,
        expected_policy_version: str,
        *,
        window_seconds: int = 120,
        now: datetime | None = None,
    ) -> bool:
        _require_approval_reconciliation_event(event)
        if not isinstance(expected_policy_version, str) or re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", expected_policy_version
        ) is None:
            raise ValueError("expected_policy_version is invalid")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, int)
            or not 1 <= window_seconds <= 3_600
        ):
            raise ValueError("window_seconds must be an integer from 1 to 3600")
        received = _reconciliation_datetime(now)
        received_at = received.isoformat(timespec="microseconds")
        deadline_at = (
            received + timedelta(seconds=window_seconds)
        ).isoformat(timespec="microseconds")
        identity = _approval_reconciliation_identity(event)
        with self._approval_transaction() as db:
            previous = db.execute(
                """
                SELECT * FROM approval_reconciliation_queue
                WHERE delivery_id = ?
                """,
                (event.delivery_id,),
            ).fetchone()
            if previous is not None:
                if previous["payload_sha256"] != event.payload_sha256:
                    raise RuntimeError(
                        "webhook delivery or payload identity conflicts"
                    )
                if any(previous[field] != value for field, value in identity.items()):
                    raise RuntimeError("webhook delivery signed identity conflicts")
                return False
            terminal = db.execute(
                """
                SELECT payload_sha256
                FROM github_label_webhook_evidence
                WHERE delivery_id = ?
                """,
                (event.delivery_id,),
            ).fetchone()
            if terminal is not None:
                if terminal["payload_sha256"] != event.payload_sha256:
                    raise RuntimeError(
                        "webhook delivery or payload identity conflicts"
                    )
                return False
            db.execute(
                """
                INSERT INTO approval_reconciliation_queue(
                    delivery_id, payload_sha256, event_name, action,
                    repository_id, repository, installation_id, pull_number,
                    signed_base_sha, signed_head_sha, is_draft, is_merged,
                    merge_sha, label_id, label_node_id, label_name,
                    sender_github_user_id, sender_node_id, sender_login,
                    sender_type, pull_updated_at, expected_policy_version,
                    received_at, deadline_at, retry_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    event.delivery_id,
                    event.payload_sha256,
                    event.event_name,
                    event.action,
                    event.repository_id,
                    event.repository,
                    event.installation_id,
                    event.pull_number,
                    event.base_sha,
                    event.head_sha,
                    _optional_bool_database_value(event.is_draft),
                    _optional_bool_database_value(event.is_merged),
                    event.merge_sha,
                    event.label_id,
                    event.label_node_id,
                    event.label_name,
                    event.sender_id,
                    event.sender_node_id,
                    event.sender_login,
                    event.sender_type,
                    event.pull_updated_at,
                    expected_policy_version,
                    received_at,
                    deadline_at,
                    received_at,
                ),
            )
        return True

    def list_approval_reconciliations(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._connection.execute(
                "SELECT * FROM approval_reconciliation_queue ORDER BY id"
            ).fetchall()

    def claim_next_approval_reconciliation(
        self,
        *,
        now: datetime | None = None,
    ) -> sqlite3.Row | None:
        claimed = _reconciliation_datetime(now)
        claimed_at = claimed.isoformat(timespec="microseconds")
        lease_expires_at = (
            claimed + _APPROVAL_RECONCILIATION_CLAIM_LEASE
        ).isoformat(timespec="microseconds")
        with self._approval_transaction() as db:
            row = db.execute(
                """
                SELECT current.*
                FROM approval_reconciliation_queue AS current
                WHERE current.completed_at IS NULL
                  AND current.retry_at IS NOT NULL
                  AND current.retry_at <= ?
                  AND (
                      current.lease_expires_at IS NULL
                      OR current.lease_expires_at <= ?
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM approval_reconciliation_queue AS prior
                      WHERE prior.repository_id = current.repository_id
                        AND prior.pull_number = current.pull_number
                        AND prior.id < current.id
                        AND prior.completed_at IS NULL
                  )
                ORDER BY current.id
                LIMIT 1
                """,
                (claimed_at, claimed_at),
            ).fetchone()
            if row is None:
                return None
            updated = db.execute(
                """
                UPDATE approval_reconciliation_queue
                SET claimed_at = ?, lease_expires_at = ?,
                    attempt_count = attempt_count + 1
                WHERE id = ? AND completed_at IS NULL
                  AND (
                      lease_expires_at IS NULL
                      OR lease_expires_at <= ?
                  )
                """,
                (claimed_at, lease_expires_at, row["id"], claimed_at),
            ).rowcount
            if updated != 1:
                return None
            return db.execute(
                "SELECT * FROM approval_reconciliation_queue WHERE id = ?",
                (row["id"],),
            ).fetchone()

    def retry_approval_reconciliation(
        self,
        reconciliation_id: int,
        error: str,
        *,
        claimed_at: str,
        attempt_count: int,
        now: datetime | None = None,
    ) -> None:
        message = str(error or "approval reconciliation failed")[:2_000]
        current = _reconciliation_datetime(now)
        with self._approval_transaction() as db:
            row = db.execute(
                "SELECT * FROM approval_reconciliation_queue WHERE id = ?",
                (reconciliation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown approval reconciliation row: {reconciliation_id}"
                )
            if row["completed_at"] is not None:
                return
            self._require_approval_reconciliation_claim(
                row,
                claimed_at=claimed_at,
                attempt_count=attempt_count,
            )
            delay = min(2 ** min(int(row["attempt_count"]), 5), 30)
            deadline = datetime.fromisoformat(str(row["deadline_at"]))
            retry = min(current + timedelta(seconds=delay), deadline)
            retry_at = retry.isoformat(timespec="microseconds")
            updated = db.execute(
                """
                UPDATE approval_reconciliation_queue
                SET claimed_at = NULL, lease_expires_at = NULL,
                    last_error = ?, retry_at = ?
                WHERE id = ? AND completed_at IS NULL
                  AND claimed_at = ? AND attempt_count = ?
                """,
                (
                    message,
                    retry_at,
                    reconciliation_id,
                    claimed_at,
                    attempt_count,
                ),
            ).rowcount
            if updated != 1:
                raise RuntimeError("approval reconciliation retry CAS failed")

    def complete_approval_reconciliation(
        self,
        reconciliation_id: int,
        *,
        claimed_at: str,
        attempt_count: int,
        now: datetime | None = None,
    ) -> None:
        completed_at = _reconciliation_datetime(now).isoformat(
            timespec="microseconds"
        )
        with self._approval_transaction() as db:
            row = db.execute(
                "SELECT * FROM approval_reconciliation_queue WHERE id = ?",
                (reconciliation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown approval reconciliation row: {reconciliation_id}"
                )
            if row["completed_at"] is not None:
                return
            self._complete_approval_reconciliation_in_transaction(
                db,
                row,
                completed_at=completed_at,
                claimed_at=claimed_at,
                attempt_count=attempt_count,
            )

    def _complete_approval_reconciliation_in_transaction(
        self,
        db: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        completed_at: str,
        claimed_at: str,
        attempt_count: int,
        last_error: str | None = None,
    ) -> None:
        self._require_approval_reconciliation_claim(
            row,
            claimed_at=claimed_at,
            attempt_count=attempt_count,
        )
        evidence = db.execute(
            """
            SELECT * FROM github_label_webhook_evidence
            WHERE delivery_id = ?
            """,
            (row["delivery_id"],),
        ).fetchone()
        evidence_identity = (
            ("payload_sha256", "payload_sha256"),
            ("repository_id", "repository_id"),
            ("repository", "repository"),
            ("installation_id", "installation_id"),
            ("pull_number", "pull_number"),
            ("action", "action"),
            ("label_id", "label_id"),
            ("label_node_id", "label_node_id"),
            ("label_name", "label_name"),
            ("sender_type", "sender_type"),
            ("sender_github_user_id", "sender_github_user_id"),
            ("sender_node_id", "sender_node_id"),
            ("sender_login", "sender_login"),
            ("signed_base_sha", "signed_base_sha"),
            ("signed_head_sha", "signed_head_sha"),
            ("pull_updated_at", "pull_updated_at"),
        )
        if evidence is None or any(
            evidence[evidence_field] != row[queue_field]
            for evidence_field, queue_field in evidence_identity
        ):
            raise RuntimeError(
                "approval reconciliation requires matching terminal evidence"
            )
        updated = db.execute(
            """
            UPDATE approval_reconciliation_queue
            SET completed_at = ?, claimed_at = NULL,
                lease_expires_at = NULL, retry_at = NULL, last_error = ?
            WHERE id = ? AND completed_at IS NULL
              AND claimed_at = ? AND attempt_count = ?
            """,
            (
                completed_at,
                last_error,
                row["id"],
                claimed_at,
                attempt_count,
            ),
        ).rowcount
        if updated != 1:
            raise RuntimeError("approval reconciliation completion CAS failed")

    def reject_timed_out_approval_reconciliation(
        self,
        reconciliation_id: int,
        *,
        reason: str,
        claimed_at: str,
        attempt_count: int,
        affects_current: bool,
        now: datetime | None = None,
    ) -> dict[str, object]:
        reason = _require_reconciliation_reason(reason)
        if reason not in {
            "TIMELINE_EVENT_VISIBILITY_TIMEOUT",
            "RECONCILIATION_DEADLINE_EXCEEDED",
        }:
            raise ValueError("unsupported reconciliation timeout reason")
        if not isinstance(affects_current, bool):
            raise ValueError("affects_current must be a boolean")
        completed = _reconciliation_datetime(now)
        completed_at = completed.isoformat(timespec="microseconds")
        with self._approval_transaction() as db:
            row = db.execute(
                "SELECT * FROM approval_reconciliation_queue WHERE id = ?",
                (reconciliation_id,),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown approval reconciliation row: {reconciliation_id}"
                )
            if row["completed_at"] is not None:
                return self._approval_evidence_result(
                    db, row["delivery_id"], duplicate=True
                )
            self._require_approval_reconciliation_claim(
                row,
                claimed_at=claimed_at,
                attempt_count=attempt_count,
            )
            deadline = datetime.fromisoformat(str(row["deadline_at"]))
            if completed < deadline:
                raise RuntimeError(
                    "approval reconciliation deadline has not expired"
                )
            event = _approval_reconciliation_event_from_row(row)
            result = self._record_rejected_approval_reconciliation(
                db,
                event=event,
                reason=reason,
                affects_current=affects_current,
                received_at=str(row["received_at"]),
                now=completed_at,
            )
            self._complete_approval_reconciliation_in_transaction(
                db,
                row,
                completed_at=completed_at,
                claimed_at=claimed_at,
                attempt_count=attempt_count,
                last_error=reason,
            )
            return result

    @staticmethod
    def _require_approval_reconciliation_claim(
        row: sqlite3.Row,
        *,
        claimed_at: str,
        attempt_count: int,
    ) -> None:
        if (
            row["claimed_at"] != claimed_at
            or row["attempt_count"] != attempt_count
        ):
            raise RuntimeError("approval reconciliation claim ownership changed")

    def _record_rejected_approval_reconciliation(
        self,
        db: sqlite3.Connection,
        *,
        event: WebhookEvent,
        reason: str,
        affects_current: bool,
        received_at: str,
        now: str,
    ) -> dict[str, object]:
        previous = db.execute(
            """
            SELECT e.*, a.approval_id, a.attestation_digest,
                a.invalidation_reason AS approval_reason
            FROM github_label_webhook_evidence AS e
            LEFT JOIN approvals AS a
              ON a.webhook_delivery_id = e.delivery_id
            WHERE e.delivery_id = ?
            LIMIT 1
            """,
            (event.delivery_id,),
        ).fetchone()
        if previous is not None:
            if previous["payload_sha256"] != event.payload_sha256:
                raise RuntimeError("webhook delivery or payload identity conflicts")
            return self._approval_evidence_result(
                db, event.delivery_id, duplicate=True
            )

        db.execute(
            """
            INSERT INTO github_label_webhook_evidence(
                delivery_id, payload_sha256, event_id, review_context_id,
                repository_id, repository, installation_id, pull_number,
                action, label_id, label_node_id, label_name, sender_type,
                sender_github_user_id, sender_node_id, sender_login,
                signed_base_sha, signed_head_sha, pull_updated_at, outcome,
                rejection_reason, received_at
            ) VALUES (
                ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                'REJECTED', ?, ?
            )
            """,
            (
                event.delivery_id,
                event.payload_sha256,
                event.repository_id,
                event.repository,
                event.installation_id,
                event.pull_number,
                event.action,
                event.label_id,
                event.label_node_id,
                event.label_name,
                event.sender_type,
                event.sender_id,
                event.sender_node_id,
                event.sender_login,
                event.base_sha,
                event.head_sha,
                event.pull_updated_at,
                reason,
                received_at,
            ),
        )
        db.execute(
            """
            INSERT INTO approval_outbox(
                approval_id, delivery_id, action, repository, pull_number,
                label_name, payload, created_at
            ) VALUES (NULL, ?, 'DISCORD_REPORT', ?, ?, ?, ?, ?)
            """,
            (
                event.delivery_id,
                event.repository,
                event.pull_number,
                event.label_name,
                json.dumps(
                    {
                        "reason": reason,
                        "sender_type": event.sender_type,
                        "webhook_action": event.action,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                now,
            ),
        )
        if affects_current:
            job = db.execute(
                """
                SELECT * FROM review_jobs
                WHERE repository_id = ? AND repository = ? AND pull_number = ?
                  AND head_sha = ?
                ORDER BY id DESC LIMIT 1
                """,
                (
                    event.repository_id,
                    event.repository,
                    event.pull_number,
                    event.head_sha,
                ),
            ).fetchone()
            if job is not None:
                current = ReviewState(job["state"])
                if current is not ReviewState.HUMAN_REVIEW:
                    try:
                        validate_transition(current, ReviewState.HUMAN_REVIEW)
                    except ValueError:
                        pass
                    else:
                        db.execute(
                            """
                            UPDATE review_jobs
                            SET state = 'HUMAN_REVIEW', finished_at = ?,
                                last_error = ?, retry_at = NULL, updated_at = ?
                            WHERE id = ?
                            """,
                            (now, reason, now, job["id"]),
                        )
                        self._invalidate_job_attempts(
                            db, (job["id"],), reason=reason, now=now
                        )
        return {
            "delivery_id": event.delivery_id,
            "outcome": "REJECTED",
            "reason": reason,
            "event_id": None,
            "approval_id": None,
            "generation": None,
            "attestation_digest": None,
            "duplicate": False,
        }

    @staticmethod
    def _approval_evidence_result(
        db: sqlite3.Connection,
        delivery_id: str,
        *,
        duplicate: bool,
    ) -> dict[str, object]:
        previous = db.execute(
            """
            SELECT e.*, a.approval_id, a.attestation_digest,
                a.invalidation_reason AS approval_reason
            FROM github_label_webhook_evidence AS e
            LEFT JOIN approvals AS a
              ON a.webhook_delivery_id = e.delivery_id
            WHERE e.delivery_id = ?
            LIMIT 1
            """,
            (delivery_id,),
        ).fetchone()
        if previous is None:
            raise RuntimeError(
                "completed approval reconciliation has no terminal evidence"
            )
        generation = None
        if previous["event_id"] is not None:
            event_row = db.execute(
                "SELECT generation FROM github_label_events WHERE event_id = ?",
                (previous["event_id"],),
            ).fetchone()
            generation = event_row["generation"] if event_row else None
        return {
            "delivery_id": delivery_id,
            "outcome": previous["outcome"],
            "reason": previous["rejection_reason"] or previous["approval_reason"],
            "event_id": previous["event_id"],
            "approval_id": previous["approval_id"],
            "generation": generation,
            "attestation_digest": previous["attestation_digest"],
            "duplicate": duplicate,
        }

    def list_approval_outbox(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._connection.execute(
                "SELECT * FROM approval_outbox ORDER BY id"
            ).fetchall()

    def claim_next_approval_outbox(self) -> sqlite3.Row | None:
        now_datetime = datetime.now(timezone.utc)
        now = now_datetime.isoformat(timespec="seconds")
        lease_before = (now_datetime - timedelta(minutes=5)).isoformat(
            timespec="seconds"
        )
        with self._approval_transaction() as db:
            row = db.execute(
                """
                SELECT current.* FROM approval_outbox AS current
                WHERE current.delivered_at IS NULL
                  AND (current.retry_at IS NULL OR current.retry_at <= ?)
                  AND (current.claimed_at IS NULL OR current.claimed_at <= ?)
                  AND NOT EXISTS (
                      SELECT 1 FROM approval_outbox AS prior
                      WHERE prior.id < current.id
                        AND prior.delivered_at IS NULL
                        AND (
                            prior.delivery_id = current.delivery_id
                            OR (
                                current.action = 'REMOVE_LABEL'
                                AND prior.action = 'REMOVE_LABEL'
                                AND prior.repository = current.repository
                                AND prior.pull_number = current.pull_number
                                AND prior.label_name = current.label_name
                            )
                        )
                  )
                ORDER BY current.id LIMIT 1
                """,
                (now, lease_before),
            ).fetchone()
            if row is None:
                return None
            updated = db.execute(
                """
                UPDATE approval_outbox
                SET claimed_at = ?, attempt_count = attempt_count + 1
                WHERE id = ? AND delivered_at IS NULL
                  AND (claimed_at IS NULL OR claimed_at <= ?)
                """,
                (now, row["id"], lease_before),
            ).rowcount
            if updated != 1:
                return None
            claimed = db.execute(
                "SELECT * FROM approval_outbox WHERE id = ?", (row["id"],)
            ).fetchone()
        return claimed

    def complete_approval_outbox(
        self,
        outbox_id: int,
        *,
        claimed_at: str,
        attempt_count: int,
    ) -> None:
        now = _timestamp()
        with self._approval_transaction() as db:
            row = db.execute(
                "SELECT * FROM approval_outbox WHERE id = ?", (outbox_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown approval outbox row: {outbox_id}")
            if row["delivered_at"] is not None:
                return
            if (
                row["claimed_at"] != claimed_at
                or row["attempt_count"] != attempt_count
            ):
                raise RuntimeError("approval outbox claim ownership changed")
            updated = db.execute(
                """
                UPDATE approval_outbox
                SET delivered_at = ?, claimed_at = NULL,
                    last_error = NULL, retry_at = NULL
                WHERE id = ? AND delivered_at IS NULL
                  AND claimed_at = ? AND attempt_count = ?
                """,
                (now, outbox_id, claimed_at, attempt_count),
            ).rowcount
            if updated != 1:
                raise RuntimeError("approval outbox completion CAS failed")

    def retry_approval_outbox(
        self,
        outbox_id: int,
        error: str,
        *,
        claimed_at: str,
        attempt_count: int,
    ) -> None:
        message = str(error or "approval outbox delivery failed")[:2_000]
        with self._approval_transaction() as db:
            row = db.execute(
                "SELECT * FROM approval_outbox WHERE id = ?", (outbox_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown approval outbox row: {outbox_id}")
            if row["delivered_at"] is not None:
                return
            if (
                row["claimed_at"] != claimed_at
                or row["attempt_count"] != attempt_count
            ):
                raise RuntimeError("approval outbox claim ownership changed")
            delay = min(2 ** min(int(row["attempt_count"]), 8), 300)
            retry_at = (
                datetime.now(timezone.utc) + timedelta(seconds=delay)
            ).isoformat(timespec="seconds")
            updated = db.execute(
                """
                UPDATE approval_outbox
                SET claimed_at = NULL, last_error = ?, retry_at = ?
                WHERE id = ? AND delivered_at IS NULL
                  AND claimed_at = ? AND attempt_count = ?
                """,
                (
                    message,
                    retry_at,
                    outbox_id,
                    claimed_at,
                    attempt_count,
                ),
            ).rowcount
            if updated != 1:
                raise RuntimeError("approval outbox retry CAS failed")

    def get_approval_record(self, approval_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()

    def _expire_github_label_approvals(
        self,
        *,
        repository_id: int,
        repository: str,
        pull_number: int,
        clock: GithubClockObservation,
        monotonic_ns: Callable[[], int],
    ) -> tuple[tuple[str, str], ...]:
        now = _timestamp()
        invalidated: list[tuple[str, str]] = []
        with self._approval_transaction() as db:
            rows = db.execute(
                """
                SELECT a.* FROM approvals a
                JOIN review_attempts r
                  ON r.review_attempt_id = a.review_attempt_id
                JOIN review_jobs j ON j.id = r.job_id
                WHERE a.repository_id = ? AND a.pull_number = ?
                  AND j.repository = ? AND a.status IN ('PENDING', 'ACTIVE')
                ORDER BY a.approval_id
                """,
                (repository_id, pull_number, repository),
            ).fetchall()
            for row in rows:
                event_created_at = datetime.strptime(
                    row["event_created_at"], "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)
                transaction_now_ns = monotonic_ns()
                if (
                    isinstance(transaction_now_ns, bool)
                    or not isinstance(transaction_now_ns, int)
                    or transaction_now_ns < 0
                ):
                    raise ValueError(
                        "monotonic_ns must return a non-negative integer"
                    )
                evaluation = evaluate_approval_ttl(
                    event_created_at=event_created_at,
                    clock=clock,
                    now_monotonic_ns=transaction_now_ns,
                )
                if evaluation.is_valid:
                    continue
                reason = (
                    "EXPIRED"
                    if evaluation.decision.value
                    == "EXPIRED_OR_WITHIN_SAFETY_MARGIN"
                    else evaluation.decision.value
                )
                self._invalidate_open_approvals(
                    db, (row,), reason=reason, now=now
                )
                invalidated.append((row["approval_id"], reason))
        return tuple(invalidated)

    def list_jobs(
        self,
        states: set[ReviewState] | frozenset[ReviewState] | None = None,
    ) -> list[ReviewJob]:
        with self._lock:
            if states:
                values = sorted(state.value for state in states)
                placeholders = ", ".join("?" for _ in values)
                rows = self._connection.execute(
                    f"""
                    SELECT * FROM review_jobs
                    WHERE state IN ({placeholders})
                    ORDER BY id
                    """,
                    values,
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT * FROM review_jobs ORDER BY id"
                ).fetchall()
        return [_job_from_row(row) for row in rows]

    def transition(
        self,
        job_id: int,
        target: ReviewState,
        *,
        expected: ReviewState | None = None,
        review_decision: str | None = None,
        findings_hash: str | None = None,
        github_review_id: int | None = None,
        github_comment_id: int | None = None,
        discord_message_id: str | None = None,
        discord_thread_id: str | None = None,
        merge_sha: str | None = None,
        last_error: str | None = None,
        retry_at: str | None = None,
    ) -> ReviewJob:
        now = _timestamp()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown review job: {job_id}")
            current = ReviewState(row["state"])
            if expected is not None and current is not expected:
                raise RuntimeError(
                    f"job {job_id} is {current}, expected {expected}"
                )
            validate_transition(current, target)
            queued_at = now if target is ReviewState.QUEUED else row["queued_at"]
            started_at = now if target is ReviewState.REVIEWING else row["started_at"]
            finished_at = (
                now
                if target
                in {
                    ReviewState.CHANGES_REQUIRED,
                    ReviewState.HUMAN_REVIEW,
                    ReviewState.FAILED,
                    ReviewState.MERGED,
                    ReviewState.OBSOLETE,
                    ReviewState.CLOSED,
                }
                else row["finished_at"]
            )
            db.execute(
                """
                UPDATE review_jobs SET
                    state = ?, queued_at = ?, started_at = ?, finished_at = ?,
                    review_decision = COALESCE(?, review_decision),
                    findings_hash = COALESCE(?, findings_hash),
                    github_review_id = COALESCE(?, github_review_id),
                    github_comment_id = COALESCE(?, github_comment_id),
                    discord_message_id = COALESCE(?, discord_message_id),
                    discord_thread_id = COALESCE(?, discord_thread_id),
                    merge_sha = COALESCE(?, merge_sha),
                    last_error = ?,
                    retry_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    target.value,
                    queued_at,
                    started_at,
                    finished_at,
                    review_decision,
                    findings_hash,
                    github_review_id,
                    github_comment_id,
                    discord_message_id,
                    discord_thread_id,
                    merge_sha,
                    last_error,
                    retry_at,
                    now,
                    job_id,
                ),
            )
            self._invalidate_if_job_left_review_context(
                db,
                job_id,
                target,
                now=now,
            )
            updated = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return _job_from_row(updated)

    def claim_next(self, *, now: str | None = None) -> ReviewJob | None:
        current_time = now or _timestamp()
        with self._transaction() as db:
            row = db.execute(
                """
                SELECT * FROM review_jobs
                WHERE state = 'QUEUED'
                  AND (retry_at IS NULL OR retry_at <= ?)
                ORDER BY queued_at, id
                LIMIT 1
                """,
                (current_time,),
            ).fetchone()
            if row is None:
                return None
            updated = db.execute(
                """
                UPDATE review_jobs
                SET state = 'REVIEWING',
                    started_at = ?,
                    attempt_count = attempt_count + 1,
                    retry_at = NULL,
                    updated_at = ?
                WHERE id = ? AND state = 'QUEUED'
                """,
                (current_time, current_time, row["id"]),
            )
            if updated.rowcount != 1:
                return None
            claimed = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (row["id"],)
            ).fetchone()
        return _job_from_row(claimed)

    def recover_after_restart(self) -> RecoveryReport:
        now = _timestamp()
        with self._transaction() as db:
            with self._allow_approval_write():
                db.execute(
                    """
                    UPDATE approval_outbox SET claimed_at = NULL
                    WHERE delivered_at IS NULL AND claimed_at IS NOT NULL
                    """
                )
                db.execute(
                    """
                    UPDATE approval_reconciliation_queue
                    SET claimed_at = NULL, lease_expires_at = NULL
                    WHERE completed_at IS NULL AND claimed_at IS NOT NULL
                    """
                )
            interrupted = db.execute(
                "SELECT id FROM review_jobs WHERE state = 'REVIEWING' ORDER BY id"
            ).fetchall()
            requeued_ids = tuple(row["id"] for row in interrupted)
            if requeued_ids:
                db.execute(
                    """
                    UPDATE review_jobs
                    SET state = 'QUEUED',
                        queued_at = ?,
                        started_at = NULL,
                        retry_at = NULL,
                        last_error = 'orchestrator restarted during review',
                        updated_at = ?
                    WHERE state = 'REVIEWING'
                    """,
                    (now, now),
                )
            reconciliation = db.execute(
                """
                SELECT id FROM review_jobs
                WHERE state IN ('WAITING_CI', 'MERGING')
                ORDER BY id
                """
            ).fetchall()
        return RecoveryReport(
            requeued_job_ids=requeued_ids,
            reconciliation_job_ids=tuple(row["id"] for row in reconciliation),
        )

    def has_delivery(self, delivery_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM webhook_deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        return row is not None

    def _invalidate_job_attempts(
        self,
        db: sqlite3.Connection,
        job_ids: tuple[int, ...],
        *,
        reason: str,
        now: str,
    ) -> None:
        if not job_ids:
            return
        placeholders = ", ".join("?" for _ in job_ids)
        approval_rows = db.execute(
            f"""
            SELECT a.* FROM approvals a
            JOIN review_attempts r
              ON r.review_attempt_id = a.review_attempt_id
            WHERE r.job_id IN ({placeholders})
              AND a.status IN ('PENDING', 'ACTIVE')
            ORDER BY a.approval_id
            """,
            job_ids,
        ).fetchall()
        self._invalidate_open_approvals(
            db, approval_rows, reason=reason, now=now
        )
        with self._allow_review_attempt_write():
            db.execute(
                f"""
                UPDATE review_attempts
                SET status = 'INVALIDATED', invalidated_at = ?,
                    invalidation_reason = ?
                WHERE job_id IN ({placeholders})
                  AND status IN ('PREPARED', 'ACTIVE')
                """,
                (now, reason, *job_ids),
            )

    def _invalidate_open_approvals(
        self,
        db: sqlite3.Connection,
        rows: tuple[sqlite3.Row, ...] | list[sqlite3.Row],
        *,
        reason: str,
        now: str,
    ) -> None:
        for row in rows:
            current = ApprovalStatus(row["status"])
            if current not in {ApprovalStatus.PENDING, ApprovalStatus.ACTIVE}:
                continue
            sequence = db.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) + 1
                FROM approval_transition_audit WHERE approval_id = ?
                """,
                (row["approval_id"],),
            ).fetchone()[0]
            with self._allow_approval_write():
                updated = db.execute(
                    """
                    UPDATE approvals
                    SET status = 'INVALIDATED', invalidated_at = ?,
                        invalidation_reason = ?
                    WHERE approval_id = ? AND status = ?
                    """,
                    (now, reason, row["approval_id"], current.value),
                ).rowcount
                if updated != 1:
                    raise RuntimeError("approval invalidation CAS failed")
                db.execute(
                    """
                    INSERT INTO approval_transition_audit(
                        approval_id, sequence, from_status, to_status, reason,
                        recorded_at
                    ) VALUES (?, ?, ?, 'INVALIDATED', ?, ?)
                    """,
                    (row["approval_id"], sequence, current.value, reason, now),
                )

    def _invalidate_if_job_left_review_context(
        self,
        db: sqlite3.Connection,
        job_id: int,
        state: ReviewState,
        *,
        now: str,
    ) -> None:
        if state in {
            ReviewState.WAITING_READY,
            ReviewState.CHANGES_REQUIRED,
            ReviewState.HUMAN_REVIEW,
            ReviewState.FAILED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
            ReviewState.CLOSED,
        }:
            self._invalidate_job_attempts(
                db,
                (job_id,),
                reason=f"JOB_{state.value}",
                now=now,
            )

    def _obsolete_other_heads(
        self,
        db: sqlite3.Connection,
        repository: str,
        pull_number: int,
        current_head_sha: str,
        repository_id: int | None,
        now: str,
    ) -> None:
        active_values = sorted(state.value for state in ACTIVE_STATES)
        placeholders = ", ".join("?" for _ in active_values)
        rows = db.execute(
            f"""
            SELECT id FROM review_jobs
            WHERE repository = ?
              AND pull_number = ?
              AND head_sha != ?
              AND (repository_id = ? OR repository_id IS NULL)
              AND state IN ({placeholders})
            ORDER BY id
            """,
            (
                repository,
                pull_number,
                current_head_sha,
                repository_id,
                *active_values,
            ),
        ).fetchall()
        job_ids = tuple(row["id"] for row in rows)
        self._invalidate_job_attempts(
            db,
            job_ids,
            reason="JOB_OBSOLETE_NEW_HEAD",
            now=now,
        )
        if not job_ids:
            return
        job_placeholders = ", ".join("?" for _ in job_ids)
        db.execute(
            f"""
            UPDATE review_jobs
            SET state = 'OBSOLETE',
                finished_at = ?,
                updated_at = ?
            WHERE id IN ({job_placeholders})
            """,
            (now, now, *job_ids),
        )


def _require_approval_reconciliation_event(event: WebhookEvent) -> None:
    required_strings = (
        event.delivery_id,
        event.repository,
        event.base_sha,
        event.head_sha,
        event.label_node_id,
        event.label_name,
        event.sender_node_id,
        event.sender_login,
        event.sender_type,
        event.pull_updated_at,
        event.payload_sha256,
    )
    required_positive_integers = (
        event.repository_id,
        event.installation_id,
        event.pull_number,
        event.label_id,
        event.sender_id,
    )
    if (
        event.event_name != "pull_request"
        or event.action not in {"labeled", "unlabeled"}
        or any(not isinstance(value, str) or not value for value in required_strings)
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            for value in required_positive_integers
        )
        or _SHA256.fullmatch(event.payload_sha256 or "") is None
        or re.fullmatch(r"[0-9a-f]{40}", event.base_sha or "") is None
        or re.fullmatch(r"[0-9a-f]{40}", event.head_sha or "") is None
        or (
            event.is_draft is not None
            and not isinstance(event.is_draft, bool)
        )
        or (
            event.is_merged is not None
            and not isinstance(event.is_merged, bool)
        )
        or (
            event.merge_sha is not None
            and re.fullmatch(r"[0-9a-f]{40}", event.merge_sha) is None
        )
    ):
        raise ValueError(
            "webhook lacks complete signed approval reconciliation evidence"
        )
    try:
        updated = datetime.strptime(
            event.pull_updated_at or "", "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(
            "pull_updated_at must be a canonical GitHub timestamp"
        ) from exc
    if updated.strftime("%Y-%m-%dT%H:%M:%SZ") != event.pull_updated_at:
        raise ValueError("pull_updated_at must be a canonical GitHub timestamp")


def _approval_reconciliation_identity(
    event: WebhookEvent,
) -> dict[str, object]:
    return {
        "payload_sha256": event.payload_sha256,
        "event_name": event.event_name,
        "action": event.action,
        "repository_id": event.repository_id,
        "repository": event.repository,
        "installation_id": event.installation_id,
        "pull_number": event.pull_number,
        "signed_base_sha": event.base_sha,
        "signed_head_sha": event.head_sha,
        "is_draft": _optional_bool_database_value(event.is_draft),
        "is_merged": _optional_bool_database_value(event.is_merged),
        "merge_sha": event.merge_sha,
        "label_id": event.label_id,
        "label_node_id": event.label_node_id,
        "label_name": event.label_name,
        "sender_github_user_id": event.sender_id,
        "sender_node_id": event.sender_node_id,
        "sender_login": event.sender_login,
        "sender_type": event.sender_type,
        "pull_updated_at": event.pull_updated_at,
    }


def _approval_reconciliation_event_from_row(row: sqlite3.Row) -> WebhookEvent:
    return WebhookEvent(
        delivery_id=str(row["delivery_id"]),
        event_name=str(row["event_name"]),
        action=str(row["action"]),
        repository_id=int(row["repository_id"]),
        repository=str(row["repository"]),
        installation_id=int(row["installation_id"]),
        pull_number=int(row["pull_number"]),
        base_sha=str(row["signed_base_sha"]),
        head_sha=str(row["signed_head_sha"]),
        is_draft=(
            None if row["is_draft"] is None else bool(row["is_draft"])
        ),
        is_merged=(
            None if row["is_merged"] is None else bool(row["is_merged"])
        ),
        merge_sha=row["merge_sha"],
        label_id=int(row["label_id"]),
        label_node_id=str(row["label_node_id"]),
        label_name=str(row["label_name"]),
        sender_id=int(row["sender_github_user_id"]),
        sender_node_id=str(row["sender_node_id"]),
        sender_login=str(row["sender_login"]),
        sender_type=str(row["sender_type"]),
        pull_updated_at=str(row["pull_updated_at"]),
        payload_sha256=str(row["payload_sha256"]),
    )


def _optional_bool_database_value(value: bool | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError("signed webhook boolean fields must be booleans")
    return int(value)


def _reconciliation_datetime(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if (
        not isinstance(current, datetime)
        or current.tzinfo is None
        or current.utcoffset() != timedelta(0)
    ):
        raise ValueError("approval reconciliation clock must be timezone-aware UTC")
    return current.astimezone(timezone.utc)


def _require_reconciliation_storage_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("evidence_received_at must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("evidence_received_at must be UTC")
    return value


def _require_reconciliation_reason(reason: str) -> str:
    if not isinstance(reason, str) or not reason or len(reason) > 2_000:
        raise ValueError("reconciliation rejection reason is required")
    return reason


def _initial_state(event: WebhookEvent) -> ReviewState:
    if event.action == "closed":
        return ReviewState.MERGED if event.is_merged else ReviewState.CLOSED
    if event.action == "converted_to_draft" or event.is_draft:
        return ReviewState.WAITING_READY
    if event.action in {
        "opened",
        "reopened",
        "ready_for_review",
        "synchronize",
        "bootstrap_reconcile",
    }:
        return ReviewState.QUEUED
    return ReviewState.DISCOVERED


def _event_may_transition(
    action: str | None,
    current: ReviewState,
    target: ReviewState,
) -> bool:
    if action == "ready_for_review":
        return current is ReviewState.WAITING_READY and target is ReviewState.QUEUED
    if action == "reopened":
        return current is ReviewState.CLOSED and target is ReviewState.QUEUED
    if action == "bootstrap_reconcile":
        return current is ReviewState.CLOSED and target in {
            ReviewState.QUEUED,
            ReviewState.WAITING_READY,
        }
    if action == "converted_to_draft":
        return current in ACTIVE_STATES and current is not ReviewState.WAITING_READY
    if action == "closed":
        return current is not ReviewState.MERGED
    return current is ReviewState.DISCOVERED


def _job_from_row(row: sqlite3.Row) -> ReviewJob:
    return ReviewJob(
        id=row["id"],
        repository_id=row["repository_id"],
        repository=row["repository"],
        pull_number=row["pull_number"],
        base_sha=row["base_sha"],
        head_sha=row["head_sha"],
        state=ReviewState(row["state"]),
        queued_at=row["queued_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        attempt_count=row["attempt_count"],
        review_decision=row["review_decision"],
        findings_hash=row["findings_hash"],
        github_review_id=row["github_review_id"],
        github_comment_id=row["github_comment_id"],
        discord_message_id=row["discord_message_id"],
        discord_thread_id=row["discord_thread_id"],
        merge_sha=row["merge_sha"],
        last_error=row["last_error"],
        retry_at=row["retry_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _stored_descriptor_from_row(row: sqlite3.Row) -> StoredMergeDescriptor:
    return StoredMergeDescriptor(
        id=row["id"],
        job_id=row["job_id"],
        descriptor_digest=row["descriptor_digest"],
        canonical_bytes=bytes(row["canonical_bytes"]),
        created_at=row["created_at"],
    )


def _ci_request_from_row(row: sqlite3.Row) -> CIRequestPlan:
    return CIRequestPlan(
        request_id=row["request_id"],
        review_context_id=row["review_context_id"],
        descriptor_id=row["descriptor_id"],
        workflow_id=row["workflow_id"],
        workflow_path=row["workflow_path"],
        workflow_sha=row["workflow_sha"],
        workflow_definition_sha256=row["workflow_definition_sha256"],
        ci_profile=row["ci_profile"],
        expected_actor=row["expected_actor"],
        expected_installation_id=row["expected_installation_id"],
        dispatch_not_before=row["dispatch_not_before"],
        canonical_inputs=bytes(row["canonical_inputs"]),
        inputs_digest=row["inputs_digest"],
        state=CIRequestState(row["state"]),
        blocked_reason=row["blocked_reason"],
        created_at=row["created_at"],
    )


def _validate_review_job_context(
    job: sqlite3.Row,
    content: sqlite3.Row,
) -> None:
    if ReviewState(job["state"]) not in {
        ReviewState.QUEUED,
        ReviewState.REVIEWING,
        ReviewState.WAITING_CI,
        ReviewState.READY_TO_MERGE,
    }:
        raise RuntimeError("review job is no longer active")
    if (
        job["repository_id"] != content["repository_id"]
        or job["pull_number"] != content["pull_number"]
        or job["base_sha"] != content["base_sha"]
        or job["head_sha"] != content["head_sha"]
    ):
        raise RuntimeError("review context no longer matches review job")


def _stored_review_context_from_row(row: sqlite3.Row) -> StoredReviewContext:
    canonical_bytes = bytes(row["canonical_payload"])
    value = ReviewContextContent.from_canonical_bytes(canonical_bytes)
    if (
        value.content_id != row["content_id"]
        or row["algorithm_id"] != REVIEW_CONTEXT_ALGORITHM
        or value.repository_id != row["repository_id"]
        or value.pull_number != row["pull_number"]
        or value.base_sha != row["base_sha"]
        or value.head_sha != row["head_sha"]
        or value.merge_base_sha != row["merge_base_sha"]
        or value.diff_sha256 != row["diff_sha256"]
        or value.policy_version != row["policy_version"]
    ):
        raise RuntimeError("stored review context identity mismatch")
    return StoredReviewContext(
        content_id=row["content_id"],
        algorithm_id=row["algorithm_id"],
        canonical_bytes=canonical_bytes,
        value=value,
        created_at=row["created_at"],
    )


def _review_attempt_from_row(row: sqlite3.Row) -> ReviewAttempt:
    require_uuid7(row["review_attempt_id"], "review_attempt_id")
    expected_context_id = (
        f"dohwa-review-context-attempt/v1:{row['review_attempt_id']}"
    )
    if row["review_context_id"] != expected_context_id:
        raise RuntimeError("stored review context ID mismatch")
    return ReviewAttempt(
        review_attempt_id=row["review_attempt_id"],
        review_context_id=row["review_context_id"],
        job_id=row["job_id"],
        content_id=row["content_id"],
        review_decision=row["review_decision"],
        status=ReviewAttemptStatus(row["status"]),
        github_review_id=row["github_review_id"],
        submitted_at=row["submitted_at"],
        prepared_at=row["prepared_at"],
        activated_at=row["activated_at"],
        invalidated_at=row["invalidated_at"],
        invalidation_reason=row["invalidation_reason"],
    )


def _require_github_timestamp(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != 20:
        raise ValueError(f"{field} must be a canonical UTC second timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(f"{field} must be a canonical UTC second timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError(f"{field} must be a canonical UTC second timestamp")
    return value


def _approval_attestation_digest(
    *,
    approval_id: str,
    repository_id: int,
    pull_number: int,
    review_context_id: str,
    review_attempt_id: str,
    content_id: str,
    label_event_id: str,
    webhook_delivery_id: str,
    approver_github_user_id: int,
    generation: int,
    event_created_at: str,
    accepted_at: str,
    expires_at: str,
) -> str:
    payload = {
        "accepted_at": accepted_at,
        "approval_id": approval_id,
        "approver_github_user_id_decimal": str(approver_github_user_id),
        "content_id": content_id,
        "event_created_at": event_created_at,
        "expires_at": expires_at,
        "generation_decimal": str(generation),
        "label_event_id": label_event_id,
        "pull_number_decimal": str(pull_number),
        "repository_id_decimal": str(repository_id),
        "review_attempt_id": review_attempt_id,
        "review_context_id": review_context_id,
        "schema": "dohwa-approval-attestation/v1",
        "source": "github_label",
        "source_version": APPROVAL_SOURCE_VERSION,
        "webhook_delivery_id": webhook_delivery_id,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(_APPROVAL_ATTESTATION_DOMAIN + canonical).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")
