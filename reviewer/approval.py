from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from enum import StrEnum
import hashlib
import json
import re
import secrets
import time
import uuid
from typing import Any, Iterable, Mapping


REVIEW_CONTEXT_SCHEMA = "dohwa-review-context-content/v1"
REVIEW_CONTEXT_ALGORITHM = "dohwa-bot/review-context-content/v1"
REVIEW_CONTEXT_DOMAIN = b"dohwa-bot/review-context-content/v1\0"
REVIEW_CONTEXT_ID_PREFIX = "dohwa-review-context-attempt/v1:"
APPROVAL_SOURCE_VERSION = "approval-ttl/v1"
APPROVAL_TTL = timedelta(minutes=10)
APPROVAL_TTL_SAFETY_MARGIN = timedelta(seconds=30)
GITHUB_DATE_RESOLUTION = timedelta(seconds=1)
MAX_GITHUB_REQUEST_RTT_NS = 2_000_000_000

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POLICY_VERSION = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_FIELDS = frozenset(
    {
        "base_sha",
        "diff_sha256",
        "head_sha",
        "merge_base_sha",
        "policy_version",
        "pull_number_decimal",
        "repository_id_decimal",
        "schema",
    }
)


class ReviewAttemptStatus(StrEnum):
    PREPARED = "PREPARED"
    ACTIVE = "ACTIVE"
    INVALIDATED = "INVALIDATED"


class LabelAction(StrEnum):
    LABELED = "LABELED"
    UNLABELED = "UNLABELED"


class LabelEventDisposition(StrEnum):
    ORDER_ONLY_NO_APPROVAL = "ORDER_ONLY_NO_APPROVAL"
    SIGNED_APPROVAL_CANDIDATE = "SIGNED_APPROVAL_CANDIDATE"
    REJECTED_AMBIGUOUS = "REJECTED_AMBIGUOUS"


class ApprovalSource(StrEnum):
    GITHUB_LABEL = "github_label"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    INVALIDATED = "INVALIDATED"


class ApprovalTtlDecision(StrEnum):
    VALID = "VALID"
    REJECTED_MISSING_GITHUB_DATE = "REJECTED_MISSING_GITHUB_DATE"
    REJECTED_REQUEST_RTT = "REJECTED_REQUEST_RTT"
    REJECTED_MONOTONIC_CLOCK = "REJECTED_MONOTONIC_CLOCK"
    EXPIRED_OR_WITHIN_SAFETY_MARGIN = "EXPIRED_OR_WITHIN_SAFETY_MARGIN"


@dataclass(frozen=True, slots=True)
class ReviewContextContent:
    repository_id: int
    pull_number: int
    base_sha: str
    head_sha: str
    merge_base_sha: str
    diff_sha256: str
    policy_version: str

    def __post_init__(self) -> None:
        _positive_int(self.repository_id, "repository_id")
        _positive_int(self.pull_number, "pull_number")
        _sha1(self.base_sha, "base_sha")
        _sha1(self.head_sha, "head_sha")
        _sha1(self.merge_base_sha, "merge_base_sha")
        _sha256(self.diff_sha256, "diff_sha256")
        if (
            not isinstance(self.policy_version, str)
            or _POLICY_VERSION.fullmatch(self.policy_version) is None
        ):
            raise ValueError("policy_version must be canonical ASCII")

    @property
    def payload(self) -> dict[str, str]:
        return {
            "base_sha": self.base_sha,
            "diff_sha256": self.diff_sha256,
            "head_sha": self.head_sha,
            "merge_base_sha": self.merge_base_sha,
            "policy_version": self.policy_version,
            "pull_number_decimal": str(self.pull_number),
            "repository_id_decimal": str(self.repository_id),
            "schema": REVIEW_CONTEXT_SCHEMA,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")

    @property
    def content_id(self) -> str:
        return hashlib.sha256(REVIEW_CONTEXT_DOMAIN + self.canonical_bytes).hexdigest()

    @classmethod
    def from_canonical_bytes(cls, raw: bytes) -> ReviewContextContent:
        if not isinstance(raw, bytes):
            raise ValueError("canonical review context must be bytes")
        try:
            value = json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_pairs,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid canonical review context JSON") from exc
        if not isinstance(value, Mapping) or frozenset(value) != _FIELDS:
            raise ValueError("canonical review context fields differ")
        if value["schema"] != REVIEW_CONTEXT_SCHEMA:
            raise ValueError("unsupported review context schema")
        for field in _FIELDS:
            if not isinstance(value[field], str):
                raise ValueError(f"{field} must be a JSON string")
        result = cls(
            repository_id=_decimal(value["repository_id_decimal"], "repository_id"),
            pull_number=_decimal(value["pull_number_decimal"], "pull_number"),
            base_sha=value["base_sha"],
            head_sha=value["head_sha"],
            merge_base_sha=value["merge_base_sha"],
            diff_sha256=value["diff_sha256"],
            policy_version=value["policy_version"],
        )
        if raw != result.canonical_bytes:
            raise ValueError("review context JSON is not canonical")
        return result


@dataclass(frozen=True, slots=True)
class StoredReviewContext:
    content_id: str
    algorithm_id: str
    canonical_bytes: bytes
    value: ReviewContextContent
    created_at: str


@dataclass(frozen=True, slots=True)
class ReviewAttempt:
    review_attempt_id: str
    review_context_id: str
    job_id: int
    content_id: str
    status: ReviewAttemptStatus
    github_review_id: int | None
    submitted_at: str | None
    prepared_at: str
    activated_at: str | None
    invalidated_at: str | None
    invalidation_reason: str | None


@dataclass(frozen=True, slots=True)
class AuthoritativeLabelEvent:
    event_id: str
    repository_id: int
    pull_number: int
    label_name: str
    action: LabelAction
    actor_github_user_id: int | None
    created_at: datetime
    ordinal: int
    predecessor_event_id: str | None

    def __post_init__(self) -> None:
        _ascii_token(self.event_id, "event_id", maximum=256)
        _positive_int(self.repository_id, "repository_id")
        _positive_int(self.pull_number, "pull_number")
        _ascii_token(self.label_name, "label_name", maximum=128)
        if not isinstance(self.action, LabelAction):
            raise ValueError("action must be a LabelAction")
        if self.actor_github_user_id is not None:
            _positive_int(self.actor_github_user_id, "actor_github_user_id")
        _utc_datetime(self.created_at, "created_at")
        _positive_int(self.ordinal, "ordinal")
        if self.predecessor_event_id is not None:
            _ascii_token(self.predecessor_event_id, "predecessor_event_id", maximum=256)
            if self.predecessor_event_id == self.event_id:
                raise ValueError("event cannot be its own predecessor")


@dataclass(frozen=True, slots=True)
class FoldedLabelEvent:
    event: AuthoritativeLabelEvent
    generation: int
    label_is_active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.event, AuthoritativeLabelEvent):
            raise ValueError("event must be authoritative")
        _positive_int(self.generation, "generation")
        if not isinstance(self.label_is_active, bool):
            raise ValueError("label_is_active must be boolean")


@dataclass(frozen=True, slots=True)
class AuthoritativeLabelPrefix:
    events: tuple[FoldedLabelEvent, ...]
    latest_generation: int
    label_is_active: bool

    def __post_init__(self) -> None:
        if not isinstance(self.events, tuple):
            raise ValueError("events must be an immutable tuple")
        if (
            isinstance(self.latest_generation, bool)
            or not isinstance(self.latest_generation, int)
            or self.latest_generation < 0
        ):
            raise ValueError("latest_generation must be a non-negative integer")
        if not isinstance(self.label_is_active, bool):
            raise ValueError("label_is_active must be boolean")

    @property
    def active_generation(self) -> int | None:
        return self.latest_generation if self.label_is_active else None


@dataclass(frozen=True, slots=True)
class GithubClockObservation:
    github_date: datetime | None
    request_started_monotonic_ns: int
    response_received_monotonic_ns: int

    def __post_init__(self) -> None:
        if self.github_date is not None:
            _utc_datetime(self.github_date, "github_date")
            if self.github_date.microsecond != 0:
                raise ValueError("github_date must have HTTP Date second precision")
        _nonnegative_int(self.request_started_monotonic_ns, "request_started_monotonic_ns")
        _nonnegative_int(self.response_received_monotonic_ns, "response_received_monotonic_ns")

    @property
    def request_rtt_ns(self) -> int:
        return self.response_received_monotonic_ns - self.request_started_monotonic_ns


@dataclass(frozen=True, slots=True)
class ApprovalTtlEvaluation:
    decision: ApprovalTtlDecision
    expires_at: datetime
    server_now_upper: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, ApprovalTtlDecision):
            raise ValueError("decision must be an ApprovalTtlDecision")
        _utc_datetime(self.expires_at, "expires_at")
        if self.server_now_upper is not None:
            _utc_datetime(self.server_now_upper, "server_now_upper")

    @property
    def is_valid(self) -> bool:
        return self.decision is ApprovalTtlDecision.VALID


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    source: ApprovalSource
    source_version: str
    status: ApprovalStatus
    repository_id: int
    pull_number: int
    review_context_id: str
    review_attempt_id: str
    content_id: str
    label_event_id: str
    webhook_delivery_id: str
    approver_github_user_id: int
    generation: int
    event_created_at: datetime
    accepted_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        require_uuid7(self.approval_id, "approval_id")
        if not isinstance(self.source, ApprovalSource):
            raise ValueError("source must be an ApprovalSource")
        if self.source_version != APPROVAL_SOURCE_VERSION:
            raise ValueError("unsupported approval source version")
        if not isinstance(self.status, ApprovalStatus):
            raise ValueError("status must be an ApprovalStatus")
        _positive_int(self.repository_id, "repository_id")
        _positive_int(self.pull_number, "pull_number")
        _review_context_id(self.review_context_id)
        require_uuid7(self.review_attempt_id, "review_attempt_id")
        if self.review_context_id != REVIEW_CONTEXT_ID_PREFIX + self.review_attempt_id:
            raise ValueError("review_context_id does not bind review_attempt_id")
        _sha256(self.content_id, "content_id")
        _ascii_token(self.label_event_id, "label_event_id", maximum=256)
        _ascii_token(self.webhook_delivery_id, "webhook_delivery_id", maximum=256)
        _positive_int(self.approver_github_user_id, "approver_github_user_id")
        _positive_int(self.generation, "generation")
        _utc_datetime(self.event_created_at, "event_created_at")
        _utc_datetime(self.accepted_at, "accepted_at")
        _utc_datetime(self.expires_at, "expires_at")
        if self.accepted_at < self.event_created_at:
            raise ValueError("accepted_at precedes label event")
        if self.expires_at != self.event_created_at + APPROVAL_TTL:
            raise ValueError("expires_at must be derived from the label event")


def fold_authoritative_label_prefix(
    events: Iterable[AuthoritativeLabelEvent],
) -> AuthoritativeLabelPrefix:
    """Fold a complete authoritative oldest-to-newest label-event prefix."""
    source = tuple(events)
    if not source:
        return AuthoritativeLabelPrefix((), 0, False)

    first = source[0]
    repository_id = first.repository_id
    pull_number = first.pull_number
    label_name = first.label_name
    seen: set[str] = set()
    previous: AuthoritativeLabelEvent | None = None
    generation = 0
    active = False
    folded: list[FoldedLabelEvent] = []

    for expected_ordinal, event in enumerate(source, start=1):
        if not isinstance(event, AuthoritativeLabelEvent):
            raise ValueError("timeline contains a non-authoritative event")
        if (
            event.repository_id != repository_id
            or event.pull_number != pull_number
            or event.label_name != label_name
        ):
            raise ValueError("timeline prefix crosses repository, pull, or label")
        if event.event_id in seen:
            raise ValueError("timeline contains a duplicate stable event ID")
        if event.ordinal != expected_ordinal:
            raise ValueError("timeline prefix is not ordinally continuous")
        expected_predecessor = None if previous is None else previous.event_id
        if event.predecessor_event_id != expected_predecessor:
            raise ValueError("timeline predecessor chain is discontinuous")
        if previous is not None and event.created_at < previous.created_at:
            raise ValueError("timeline timestamps contradict authoritative order")

        if event.action is LabelAction.LABELED:
            if active:
                raise ValueError("timeline contains consecutive label additions")
            generation += 1
            active = True
        elif event.action is LabelAction.UNLABELED:
            if not active:
                raise ValueError("timeline removes a label that is not active")
            active = False
        else:  # pragma: no cover - guarded by AuthoritativeLabelEvent
            raise ValueError("unsupported label action")

        folded.append(FoldedLabelEvent(event, generation, active))
        seen.add(event.event_id)
        previous = event

    return AuthoritativeLabelPrefix(tuple(folded), generation, active)


def github_clock_observation(
    *,
    date_header: str | None,
    request_started_monotonic_ns: int,
    response_received_monotonic_ns: int,
) -> GithubClockObservation:
    github_date: datetime | None = None
    if date_header is not None:
        if not isinstance(date_header, str) or not date_header.isascii():
            raise ValueError("GitHub Date header must be ASCII")
        try:
            github_date = parsedate_to_datetime(date_header)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("invalid GitHub Date header") from exc
        _utc_datetime(github_date, "github_date")
        github_date = github_date.astimezone(timezone.utc)
    return GithubClockObservation(
        github_date=github_date,
        request_started_monotonic_ns=request_started_monotonic_ns,
        response_received_monotonic_ns=response_received_monotonic_ns,
    )


def evaluate_approval_ttl(
    *,
    event_created_at: datetime,
    clock: GithubClockObservation,
    now_monotonic_ns: int,
) -> ApprovalTtlEvaluation:
    _utc_datetime(event_created_at, "event_created_at")
    if not isinstance(clock, GithubClockObservation):
        raise ValueError("clock must be a GitHub clock observation")
    _nonnegative_int(now_monotonic_ns, "now_monotonic_ns")
    expires_at = event_created_at + APPROVAL_TTL

    if clock.github_date is None:
        return ApprovalTtlEvaluation(
            ApprovalTtlDecision.REJECTED_MISSING_GITHUB_DATE,
            expires_at,
            None,
        )
    if clock.request_rtt_ns < 0 or now_monotonic_ns < clock.response_received_monotonic_ns:
        return ApprovalTtlEvaluation(
            ApprovalTtlDecision.REJECTED_MONOTONIC_CLOCK,
            expires_at,
            None,
        )
    if clock.request_rtt_ns > MAX_GITHUB_REQUEST_RTT_NS:
        return ApprovalTtlEvaluation(
            ApprovalTtlDecision.REJECTED_REQUEST_RTT,
            expires_at,
            None,
        )

    elapsed_ns = now_monotonic_ns - clock.response_received_monotonic_ns
    server_now_upper = (
        clock.github_date
        + GITHUB_DATE_RESOLUTION
        + timedelta(microseconds=_ceil_ns_to_microseconds(clock.request_rtt_ns))
        + timedelta(microseconds=_ceil_ns_to_microseconds(elapsed_ns))
    )
    decision = (
        ApprovalTtlDecision.EXPIRED_OR_WITHIN_SAFETY_MARGIN
        if server_now_upper >= expires_at - APPROVAL_TTL_SAFETY_MARGIN
        else ApprovalTtlDecision.VALID
    )
    return ApprovalTtlEvaluation(decision, expires_at, server_now_upper)


def validate_approval_transition(current: ApprovalStatus, target: ApprovalStatus) -> None:
    if not isinstance(current, ApprovalStatus) or not isinstance(target, ApprovalStatus):
        raise ValueError("approval status must be an ApprovalStatus")
    allowed = {
        ApprovalStatus.PENDING: {ApprovalStatus.ACTIVE, ApprovalStatus.INVALIDATED},
        ApprovalStatus.ACTIVE: {ApprovalStatus.CONSUMED, ApprovalStatus.INVALIDATED},
        ApprovalStatus.CONSUMED: set(),
        ApprovalStatus.INVALIDATED: set(),
    }
    if target not in allowed[current]:
        raise ValueError(f"approval transition {current} -> {target} is not allowed")


def new_uuid7(*, timestamp_ms: int | None = None, random_bits: int | None = None) -> str:
    milliseconds = time.time_ns() // 1_000_000 if timestamp_ms is None else timestamp_ms
    if not isinstance(milliseconds, int) or not 0 <= milliseconds < 1 << 48:
        raise ValueError("timestamp_ms is outside UUIDv7 range")
    randomness = secrets.randbits(74) if random_bits is None else random_bits
    if not isinstance(randomness, int) or not 0 <= randomness < 1 << 74:
        raise ValueError("random_bits is outside UUIDv7 range")
    rand_a = randomness >> 62
    rand_b = randomness & ((1 << 62) - 1)
    value = (
        (milliseconds << 80)
        | (7 << 76)
        | (rand_a << 64)
        | (2 << 62)
        | rand_b
    )
    return str(uuid.UUID(int=value))


def require_uuid7(value: str, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a canonical UUIDv7") from exc
    if str(parsed) != value or parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        raise ValueError(f"{field} must be a canonical UUIDv7")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 2**63 - 1:
        raise ValueError(f"{field} must be a positive signed 64-bit integer")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**63 - 1
    ):
        raise ValueError(f"{field} must be a non-negative signed 64-bit integer")
    return value


def _ceil_ns_to_microseconds(value: int) -> int:
    return (value + 999) // 1_000


def _ascii_token(value: Any, field: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(character.isspace() or ord(character) < 0x21 for character in value)
    ):
        raise ValueError(f"{field} must be a non-empty canonical ASCII token")
    return value


def _utc_datetime(value: Any, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"{field} must be a timezone-aware UTC datetime")
    return value


def _review_context_id(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith(REVIEW_CONTEXT_ID_PREFIX):
        raise ValueError("review_context_id has an unsupported format")
    require_uuid7(value.removeprefix(REVIEW_CONTEXT_ID_PREFIX), "review_context_id")
    return value


def _decimal(value: Any, field: str) -> int:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ValueError(f"{field} must be canonical decimal")
    if not value.isdigit() or value.startswith("0"):
        raise ValueError(f"{field} must be positive decimal without leading zero")
    return _positive_int(int(value), field)


def _sha1(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA1.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-1")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value
