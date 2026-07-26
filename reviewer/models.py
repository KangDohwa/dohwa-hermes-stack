from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


class ReviewState(StrEnum):
    DISCOVERED = "DISCOVERED"
    WAITING_READY = "WAITING_READY"
    QUEUED = "QUEUED"
    REVIEWING = "REVIEWING"
    WAITING_CI = "WAITING_CI"
    CHANGES_REQUIRED = "CHANGES_REQUIRED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    FAILED = "FAILED"
    READY_TO_MERGE = "READY_TO_MERGE"
    MERGING = "MERGING"
    MERGED = "MERGED"
    OBSOLETE = "OBSOLETE"
    CLOSED = "CLOSED"


class CIRequestState(StrEnum):
    PLANNED = "PLANNED"
    BLOCKED = "BLOCKED"


ALLOWED_TRANSITIONS: Mapping[ReviewState, frozenset[ReviewState]] = {
    ReviewState.DISCOVERED: frozenset(
        {
            ReviewState.WAITING_READY,
            ReviewState.QUEUED,
            ReviewState.HUMAN_REVIEW,
            ReviewState.CLOSED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.WAITING_READY: frozenset(
        {
            ReviewState.QUEUED,
            ReviewState.CLOSED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.QUEUED: frozenset(
        {
            ReviewState.REVIEWING,
            ReviewState.WAITING_READY,
            ReviewState.FAILED,
            ReviewState.CLOSED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.REVIEWING: frozenset(
        {
            ReviewState.WAITING_READY,
            ReviewState.QUEUED,
            ReviewState.WAITING_CI,
            ReviewState.CHANGES_REQUIRED,
            ReviewState.HUMAN_REVIEW,
            ReviewState.FAILED,
            ReviewState.READY_TO_MERGE,
            ReviewState.CLOSED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.WAITING_CI: frozenset(
        {
            ReviewState.WAITING_READY,
            ReviewState.CHANGES_REQUIRED,
            ReviewState.HUMAN_REVIEW,
            ReviewState.FAILED,
            ReviewState.READY_TO_MERGE,
            ReviewState.CLOSED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.CHANGES_REQUIRED: frozenset(
        {ReviewState.CLOSED, ReviewState.MERGED, ReviewState.OBSOLETE}
    ),
    ReviewState.HUMAN_REVIEW: frozenset(
        {ReviewState.QUEUED, ReviewState.CLOSED, ReviewState.MERGED, ReviewState.OBSOLETE}
    ),
    ReviewState.FAILED: frozenset(
        {ReviewState.QUEUED, ReviewState.CLOSED, ReviewState.MERGED, ReviewState.OBSOLETE}
    ),
    ReviewState.READY_TO_MERGE: frozenset(
        {
            ReviewState.WAITING_READY,
            ReviewState.HUMAN_REVIEW,
            ReviewState.MERGING,
            ReviewState.FAILED,
            ReviewState.CLOSED,
            ReviewState.MERGED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.MERGING: frozenset(
        {
            ReviewState.WAITING_READY,
            ReviewState.MERGED,
            ReviewState.FAILED,
            ReviewState.HUMAN_REVIEW,
            ReviewState.CLOSED,
            ReviewState.OBSOLETE,
        }
    ),
    ReviewState.MERGED: frozenset(),
    ReviewState.OBSOLETE: frozenset({ReviewState.CLOSED, ReviewState.MERGED}),
    ReviewState.CLOSED: frozenset(
        {ReviewState.WAITING_READY, ReviewState.QUEUED}
    ),
}


ACTIVE_STATES = frozenset(
    {
        ReviewState.DISCOVERED,
        ReviewState.WAITING_READY,
        ReviewState.QUEUED,
        ReviewState.REVIEWING,
        ReviewState.WAITING_CI,
        ReviewState.READY_TO_MERGE,
        ReviewState.MERGING,
    }
)


class InvalidStateTransition(ValueError):
    pass


def validate_transition(current: ReviewState, target: ReviewState) -> None:
    if current == target:
        return
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidStateTransition(f"cannot transition {current} -> {target}")


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    delivery_id: str
    event_name: str
    action: str | None
    repository_id: int | None
    repository: str | None
    installation_id: int | None
    pull_number: int | None
    base_sha: str | None
    head_sha: str | None
    is_draft: bool | None
    is_merged: bool | None
    merge_sha: str | None
    label_id: int | None = None
    label_node_id: str | None = None
    label_name: str | None = None
    sender_id: int | None = None
    sender_node_id: str | None = None
    sender_login: str | None = None
    sender_type: str | None = None
    pull_updated_at: str | None = None
    payload_sha256: str | None = None

    @property
    def has_pull_request(self) -> bool:
        return bool(self.repository and self.pull_number and self.head_sha)

    @property
    def idempotency_key(self) -> str | None:
        if not self.has_pull_request:
            return None
        return f"{self.repository}/{self.pull_number}/{self.head_sha}"


@dataclass(frozen=True, slots=True)
class ReviewJob:
    id: int
    repository_id: int | None
    repository: str
    pull_number: int
    base_sha: str | None
    head_sha: str
    state: ReviewState
    queued_at: str | None
    started_at: str | None
    finished_at: str | None
    attempt_count: int
    review_decision: str | None
    findings_hash: str | None
    github_review_id: int | None
    github_comment_id: int | None
    discord_message_id: str | None
    discord_thread_id: str | None
    merge_sha: str | None
    last_error: str | None
    retry_at: str | None
    created_at: str
    updated_at: str

    @property
    def idempotency_key(self) -> str:
        return f"{self.repository}/{self.pull_number}/{self.head_sha}"


@dataclass(frozen=True, slots=True)
class IngestResult:
    accepted_delivery: bool
    created_job: bool
    job: ReviewJob | None


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    requeued_job_ids: tuple[int, ...]
    reconciliation_job_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class StoredMergeDescriptor:
    id: int
    job_id: int
    descriptor_digest: str
    canonical_bytes: bytes
    created_at: str


@dataclass(frozen=True, slots=True)
class CIRequestPlan:
    request_id: str
    review_context_id: str
    descriptor_id: int
    workflow_id: int
    workflow_path: str
    workflow_sha: str
    workflow_definition_sha256: str
    ci_profile: str
    expected_actor: str
    expected_installation_id: int
    dispatch_not_before: str
    canonical_inputs: bytes
    inputs_digest: str
    state: CIRequestState
    blocked_reason: str | None
    created_at: str
