from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
import threading

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


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
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
                if current != target and _event_may_transition(
                    event.action, current, target
                ):
                    validate_transition(current, target)
                    db.execute(
                        """
                        UPDATE review_jobs
                        SET state = ?,
                            base_sha = COALESCE(?, base_sha),
                            repository_id = COALESCE(?, repository_id),
                            queued_at = CASE WHEN ? = 'QUEUED' THEN ? ELSE queued_at END,
                            finished_at = CASE
                                WHEN ? IN ('CLOSED', 'MERGED') THEN ?
                                WHEN ? = 'QUEUED' THEN NULL
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

            db.execute(
                "UPDATE webhook_deliveries SET job_id = ? WHERE delivery_id = ?",
                (job_id, event.delivery_id),
            )
            row = db.execute(
                "SELECT * FROM review_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            return IngestResult(True, created, _job_from_row(row))

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

    @staticmethod
    def _obsolete_other_heads(
        db: sqlite3.Connection,
        repository: str,
        pull_number: int,
        current_head_sha: str,
        now: str,
    ) -> None:
        active_values = sorted(state.value for state in ACTIVE_STATES)
        placeholders = ", ".join("?" for _ in active_values)
        db.execute(
            f"""
            UPDATE review_jobs
            SET state = 'OBSOLETE',
                finished_at = ?,
                updated_at = ?
            WHERE repository = ?
              AND pull_number = ?
              AND head_sha != ?
              AND state IN ({placeholders})
            """,
            (
                now,
                now,
                repository,
                pull_number,
                current_head_sha,
                *active_values,
            ),
        )


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


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")
