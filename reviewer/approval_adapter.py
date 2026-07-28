from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import re
import time
from typing import Callable, Iterable, TYPE_CHECKING

from reviewer.approval import GithubClockObservation, github_clock_observation
from reviewer.github_client import (
    GitHubClockDateStatus,
    LabelTimelineSnapshot,
)
from reviewer.models import WebhookEvent

if TYPE_CHECKING:
    from reviewer.state import StateStore


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ApprovalTransactionResult:
    delivery_id: str
    outcome: str
    reason: str | None
    event_id: str | None
    approval_id: str | None
    generation: int | None
    attestation_digest: str | None = None
    duplicate: bool = False


@dataclass(frozen=True, slots=True)
class ApprovalExpiryResult:
    invalidated: tuple[tuple[str, str], ...]


def process_github_label_approval(
    store: StateStore,
    *,
    snapshot: LabelTimelineSnapshot,
    webhook: WebhookEvent,
    allowed_approver_ids: Iterable[int],
    expected_installation_id: int,
    expected_policy_version: str,
    target_label: str,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    evidence_received_at: str | None = None,
    reconciliation_id: int | None = None,
    reconciliation_claimed_at: str | None = None,
    reconciliation_attempt_count: int | None = None,
) -> ApprovalTransactionResult:
    """Reconcile one signed label delivery against an authoritative timeline.

    The adapter deliberately has no merge-capable client.  All durable effects are
    committed by StateStore in one BEGIN IMMEDIATE transaction.
    """
    if not isinstance(snapshot, LabelTimelineSnapshot):
        raise TypeError("snapshot must be a LabelTimelineSnapshot")
    if not isinstance(webhook, WebhookEvent):
        raise TypeError("webhook must be a WebhookEvent")
    if (
        not isinstance(target_label, str)
        or not target_label
        or len(target_label) > 128
    ):
        raise ValueError("target_label must be non-empty and at most 128 characters")
    allowlist = frozenset(allowed_approver_ids)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in allowlist
    ):
        raise ValueError("allowed approver IDs must be positive integers")
    if (
        isinstance(expected_installation_id, bool)
        or not isinstance(expected_installation_id, int)
        or expected_installation_id <= 0
    ):
        raise ValueError("expected_installation_id must be a positive integer")
    if (
        not isinstance(expected_policy_version, str)
        or re.fullmatch(r"[A-Za-z0-9._-]{1,64}", expected_policy_version) is None
    ):
        raise ValueError("expected_policy_version must be canonical ASCII")
    if not callable(monotonic_ns):
        raise TypeError("monotonic_ns must be callable")
    require_signed_label_webhook(webhook)

    clock = _approval_clock(snapshot)

    timeline = tuple(
        {
            "event_id": item.event_id,
            "repository_id": snapshot.repository_database_id,
            "repository": snapshot.repository,
            "pull_number": snapshot.pull_number,
            "label_node_id": item.label_node_id,
            "label_name": item.label_name,
            "action": item.action.upper(),
            "actor_type": item.actor_type,
            "actor_github_user_id": item.actor_database_id,
            "actor_node_id": item.actor_node_id,
            "actor_login": item.actor_login,
            "created_at": item.created_at,
            "ordinal": item.ordinal,
            "predecessor_event_id": item.predecessor_event_id,
        }
        for item in snapshot.events
    )
    result = store._apply_github_label_approval(  # noqa: SLF001 - sole adapter boundary
        timeline=timeline,
        snapshot_repository_id=snapshot.repository_database_id,
        snapshot_repository=snapshot.repository,
        snapshot_pull_number=snapshot.pull_number,
        snapshot_total_count=snapshot.total_count,
        webhook=webhook,
        allowed_approver_ids=allowlist,
        expected_installation_id=expected_installation_id,
        expected_policy_version=expected_policy_version,
        target_label=target_label,
        clock=clock,
        monotonic_ns=monotonic_ns,
        evidence_received_at=evidence_received_at,
        reconciliation_id=reconciliation_id,
        reconciliation_claimed_at=reconciliation_claimed_at,
        reconciliation_attempt_count=reconciliation_attempt_count,
    )
    return ApprovalTransactionResult(**result)


def expire_github_label_approvals(
    store: StateStore,
    *,
    snapshot: LabelTimelineSnapshot,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> ApprovalExpiryResult:
    if not isinstance(snapshot, LabelTimelineSnapshot):
        raise TypeError("snapshot must be a LabelTimelineSnapshot")
    if not callable(monotonic_ns):
        raise TypeError("monotonic_ns must be callable")
    invalidated = store._expire_github_label_approvals(  # noqa: SLF001
        repository_id=snapshot.repository_database_id,
        repository=snapshot.repository,
        pull_number=snapshot.pull_number,
        clock=_approval_clock(snapshot),
        monotonic_ns=monotonic_ns,
    )
    return ApprovalExpiryResult(invalidated=invalidated)


def _approval_clock(snapshot: LabelTimelineSnapshot) -> GithubClockObservation:
    observed = snapshot.clock
    date_header = (
        observed.response_date
        if observed.date_status is GitHubClockDateStatus.VALID
        else None
    )
    return github_clock_observation(
        date_header=date_header,
        request_started_monotonic_ns=math.floor(
            observed.request_started_monotonic * 1_000_000_000
        ),
        response_received_monotonic_ns=math.ceil(
            observed.response_received_monotonic * 1_000_000_000
        ),
    )


def require_signed_label_webhook(event: WebhookEvent) -> None:
    required_strings = (
        event.delivery_id,
        event.repository,
        event.label_node_id,
        event.label_name,
        event.sender_node_id,
        event.sender_login,
        event.sender_type,
        event.base_sha,
        event.head_sha,
        event.pull_updated_at,
        event.payload_sha256,
    )
    if (
        event.event_name != "pull_request"
        or event.action not in {"labeled", "unlabeled"}
        or any(not isinstance(value, str) or not value for value in required_strings)
        or not isinstance(event.repository_id, int)
        or isinstance(event.repository_id, bool)
        or event.repository_id <= 0
        or not isinstance(event.installation_id, int)
        or isinstance(event.installation_id, bool)
        or event.installation_id <= 0
        or not isinstance(event.pull_number, int)
        or isinstance(event.pull_number, bool)
        or event.pull_number <= 0
        or not isinstance(event.label_id, int)
        or isinstance(event.label_id, bool)
        or event.label_id <= 0
        or not isinstance(event.sender_id, int)
        or isinstance(event.sender_id, bool)
        or event.sender_id <= 0
        or _SHA256.fullmatch(event.payload_sha256 or "") is None
    ):
        raise ValueError("webhook lacks complete signed label evidence")
    try:
        parsed = datetime.strptime(
            event.pull_updated_at or "", "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("pull_updated_at must be a canonical GitHub timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != event.pull_updated_at:
        raise ValueError("pull_updated_at must be a canonical GitHub timestamp")
