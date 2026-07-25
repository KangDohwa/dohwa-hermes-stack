from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import re
import secrets
import time
import uuid
from typing import Any, Mapping


REVIEW_CONTEXT_SCHEMA = "dohwa-review-context-content/v1"
REVIEW_CONTEXT_ALGORITHM = "dohwa-bot/review-context-content/v1"
REVIEW_CONTEXT_DOMAIN = b"dohwa-bot/review-context-content/v1\0"
REVIEW_CONTEXT_ID_PREFIX = "dohwa-review-context-attempt/v1:"

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
