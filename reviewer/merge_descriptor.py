from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping


DESCRIPTOR_SCHEMA = "merge-descriptor/v1"
CI_INPUT_SCHEMA = "targeted-ci-input/v1"
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_ID = _SHA256
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_GITHUB_LOGIN = re.compile(
    r"^(?P<login>[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)(?:\[bot\])?$"
)
_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema",
        "repository_id",
        "pull_number",
        "object_format",
        "base_oid",
        "head_oid",
        "merge_base_oid",
        "tree_oid",
        "parents",
        "candidate_oid",
        "message",
        "author_name",
        "author_email",
        "committer_name",
        "committer_email",
        "timestamp",
        "timezone",
        "ci_profile",
        "workflow_sha",
        "git_profile",
        "policy_version",
    }
)
_CI_INPUT_FIELDS = frozenset(
    {
        "schema",
        "request_id",
        "review_context_id",
        "repository_id",
        "pull_number",
        "descriptor_digest",
        "base_oid",
        "head_oid",
        "candidate_oid",
        "workflow_id",
        "workflow_path",
        "workflow_sha",
        "workflow_definition_sha256",
        "ci_profile",
        "sandbox_profile",
        "expected_actor",
        "expected_installation_id",
        "dispatch_not_before",
    }
)


def _require_exact_fields(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"canonical fields differ: missing={missing}, extra={extra}")


def _require_sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA1.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-1")
    return value


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _require_positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be non-empty text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} must be valid UTF-8") from exc
    if "\x00" in value or "\r" in value:
        raise ValueError(f"{field} contains a forbidden byte")
    return value


def _require_identity(value: Any, field: str) -> str:
    result = _require_text(value, field)
    if "\n" in result or "<" in result or ">" in result:
        raise ValueError(f"{field} is not a canonical Git identity component")
    return result


def _require_workflow_path(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("workflow_path must be a canonical workflow path")
    parts = value.split("/")
    if (
        len(parts) != 3
        or parts[:2] != [".github", "workflows"]
        or not parts[2]
        or not parts[2].endswith((".yml", ".yaml"))
        or parts[2] in {".", ".."}
    ):
        raise ValueError("workflow_path must be a canonical workflow path")
    return value


def _require_safe_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} must be a safe ASCII identifier")
    return value


def _require_github_actor(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("expected_actor must be a canonical GitHub login")
    match = _GITHUB_LOGIN.fullmatch(value)
    if match is None or "--" in match.group("login"):
        raise ValueError("expected_actor must be a canonical GitHub login")
    return value


def _require_utc_seconds(value: Any, field: str) -> str:
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


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("value is not canonical UTF-8 JSON") from exc
    return encoded + b"\n"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


@dataclass(frozen=True, slots=True)
class MergeDescriptor:
    repository_id: int
    pull_number: int
    base_oid: str
    head_oid: str
    merge_base_oid: str
    tree_oid: str
    candidate_oid: str
    message: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    timestamp: int
    ci_profile: str
    workflow_sha: str
    git_profile: str
    policy_version: str
    object_format: str = "sha1"
    timezone: str = "+0000"

    def __post_init__(self) -> None:
        _require_positive_int(self.repository_id, "repository_id")
        _require_positive_int(self.pull_number, "pull_number")
        if self.object_format != "sha1":
            raise ValueError("object_format must be sha1")
        for field in (
            "base_oid",
            "head_oid",
            "merge_base_oid",
            "tree_oid",
            "candidate_oid",
            "workflow_sha",
        ):
            _require_sha(getattr(self, field), field)
        if self.base_oid == self.head_oid:
            raise ValueError("ordered parents must be distinct B0 and H0")
        message = _require_text(self.message, "message")
        if not message.endswith("\n"):
            raise ValueError("message must end with LF")
        for field in (
            "author_name",
            "author_email",
            "committer_name",
            "committer_email",
        ):
            _require_identity(getattr(self, field), field)
        if (
            isinstance(self.timestamp, bool)
            or not isinstance(self.timestamp, int)
            or self.timestamp < 0
        ):
            raise ValueError("timestamp must be a non-negative UTC integer second")
        if self.timezone != "+0000":
            raise ValueError("timezone must be +0000")
        for field in ("ci_profile", "git_profile", "policy_version"):
            _require_text(getattr(self, field), field)
        if self.candidate_oid != self.computed_candidate_oid:
            raise ValueError("candidate_oid does not match canonical Git commit bytes")

    @classmethod
    def build(
        cls,
        *,
        repository_id: int,
        pull_number: int,
        base_oid: str,
        head_oid: str,
        merge_base_oid: str,
        tree_oid: str,
        message: str,
        author_name: str,
        author_email: str,
        committer_name: str,
        committer_email: str,
        timestamp: int,
        ci_profile: str,
        workflow_sha: str,
        git_profile: str,
        policy_version: str,
    ) -> MergeDescriptor:
        values = {
            "tree_oid": _require_sha(tree_oid, "tree_oid"),
            "base_oid": _require_sha(base_oid, "base_oid"),
            "head_oid": _require_sha(head_oid, "head_oid"),
            "author_name": _require_identity(author_name, "author_name"),
            "author_email": _require_identity(author_email, "author_email"),
            "committer_name": _require_identity(committer_name, "committer_name"),
            "committer_email": _require_identity(committer_email, "committer_email"),
            "timestamp": timestamp,
            "message": _require_text(message, "message"),
        }
        if not values["message"].endswith("\n"):
            raise ValueError("message must end with LF")
        payload = _raw_commit_bytes(**values)
        candidate_oid = _git_object_oid(payload)
        return cls(
            repository_id=repository_id,
            pull_number=pull_number,
            base_oid=base_oid,
            head_oid=head_oid,
            merge_base_oid=merge_base_oid,
            tree_oid=tree_oid,
            candidate_oid=candidate_oid,
            message=message,
            author_name=author_name,
            author_email=author_email,
            committer_name=committer_name,
            committer_email=committer_email,
            timestamp=timestamp,
            ci_profile=ci_profile,
            workflow_sha=workflow_sha,
            git_profile=git_profile,
            policy_version=policy_version,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> MergeDescriptor:
        _require_exact_fields(value, _DESCRIPTOR_FIELDS)
        if value["schema"] != DESCRIPTOR_SCHEMA:
            raise ValueError("unsupported merge descriptor schema")
        parents = value["parents"]
        if (
            not isinstance(parents, list)
            or len(parents) != 2
            or parents != [value["base_oid"], value["head_oid"]]
        ):
            raise ValueError("parents must be ordered [B0, H0]")
        return cls(
            repository_id=value["repository_id"],
            pull_number=value["pull_number"],
            object_format=value["object_format"],
            base_oid=value["base_oid"],
            head_oid=value["head_oid"],
            merge_base_oid=value["merge_base_oid"],
            tree_oid=value["tree_oid"],
            candidate_oid=value["candidate_oid"],
            message=value["message"],
            author_name=value["author_name"],
            author_email=value["author_email"],
            committer_name=value["committer_name"],
            committer_email=value["committer_email"],
            timestamp=value["timestamp"],
            timezone=value["timezone"],
            ci_profile=value["ci_profile"],
            workflow_sha=value["workflow_sha"],
            git_profile=value["git_profile"],
            policy_version=value["policy_version"],
        )

    @classmethod
    def from_canonical_bytes(cls, value: bytes) -> MergeDescriptor:
        if not isinstance(value, bytes) or not value.endswith(b"\n"):
            raise ValueError("canonical descriptor must be LF-terminated bytes")
        try:
            decoded = value.decode("utf-8", errors="strict")
            parsed = json.loads(decoded, object_pairs_hook=_reject_duplicate_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid canonical descriptor JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("merge descriptor must be a JSON object")
        descriptor = cls.from_mapping(parsed)
        if descriptor.canonical_bytes != value:
            raise ValueError("merge descriptor bytes are not canonical")
        return descriptor

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema": DESCRIPTOR_SCHEMA,
            "repository_id": self.repository_id,
            "pull_number": self.pull_number,
            "object_format": self.object_format,
            "base_oid": self.base_oid,
            "head_oid": self.head_oid,
            "merge_base_oid": self.merge_base_oid,
            "tree_oid": self.tree_oid,
            "parents": [self.base_oid, self.head_oid],
            "candidate_oid": self.candidate_oid,
            "message": self.message,
            "author_name": self.author_name,
            "author_email": self.author_email,
            "committer_name": self.committer_name,
            "committer_email": self.committer_email,
            "timestamp": self.timestamp,
            "timezone": self.timezone,
            "ci_profile": self.ci_profile,
            "workflow_sha": self.workflow_sha,
            "git_profile": self.git_profile,
            "policy_version": self.policy_version,
        }

    @property
    def raw_commit_bytes(self) -> bytes:
        return _raw_commit_bytes(
            tree_oid=self.tree_oid,
            base_oid=self.base_oid,
            head_oid=self.head_oid,
            author_name=self.author_name,
            author_email=self.author_email,
            committer_name=self.committer_name,
            committer_email=self.committer_email,
            timestamp=self.timestamp,
            message=self.message,
        )

    @property
    def computed_candidate_oid(self) -> str:
        return _git_object_oid(self.raw_commit_bytes)

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_mapping())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class CIRequestInputs:
    request_id: str
    review_context_id: str
    repository_id: int
    pull_number: int
    descriptor_digest: str
    base_oid: str
    head_oid: str
    candidate_oid: str
    workflow_id: int
    workflow_path: str
    workflow_sha: str
    workflow_definition_sha256: str
    ci_profile: str
    sandbox_profile: str
    expected_actor: str
    expected_installation_id: int
    dispatch_not_before: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or _REQUEST_ID.fullmatch(self.request_id) is None:
            raise ValueError("request_id must be 64 lowercase hexadecimal characters")
        _require_safe_identifier(self.review_context_id, "review_context_id")
        _require_positive_int(self.repository_id, "repository_id")
        _require_positive_int(self.pull_number, "pull_number")
        _require_sha256(self.descriptor_digest, "descriptor_digest")
        for field in ("base_oid", "head_oid", "candidate_oid", "workflow_sha"):
            _require_sha(getattr(self, field), field)
        _require_positive_int(self.workflow_id, "workflow_id")
        _require_workflow_path(self.workflow_path)
        _require_sha256(
            self.workflow_definition_sha256,
            "workflow_definition_sha256",
        )
        for field in ("ci_profile", "sandbox_profile"):
            _require_text(getattr(self, field), field)
        _require_github_actor(self.expected_actor)
        _require_positive_int(
            self.expected_installation_id,
            "expected_installation_id",
        )
        _require_utc_seconds(self.dispatch_not_before, "dispatch_not_before")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> CIRequestInputs:
        _require_exact_fields(value, _CI_INPUT_FIELDS)
        if value["schema"] != CI_INPUT_SCHEMA:
            raise ValueError("unsupported CI input schema")
        return cls(**{key: value[key] for key in _CI_INPUT_FIELDS if key != "schema"})

    @classmethod
    def from_canonical_bytes(cls, value: bytes) -> CIRequestInputs:
        if not isinstance(value, bytes) or not value.endswith(b"\n"):
            raise ValueError("canonical CI inputs must be LF-terminated bytes")
        try:
            parsed = json.loads(
                value.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_pairs,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid canonical CI input JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("CI inputs must be a JSON object")
        result = cls.from_mapping(parsed)
        if result.canonical_bytes != value:
            raise ValueError("CI input bytes are not canonical")
        return result

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema": CI_INPUT_SCHEMA,
            "request_id": self.request_id,
            "review_context_id": self.review_context_id,
            "repository_id": self.repository_id,
            "pull_number": self.pull_number,
            "descriptor_digest": self.descriptor_digest,
            "base_oid": self.base_oid,
            "head_oid": self.head_oid,
            "candidate_oid": self.candidate_oid,
            "workflow_id": self.workflow_id,
            "workflow_path": self.workflow_path,
            "workflow_sha": self.workflow_sha,
            "workflow_definition_sha256": self.workflow_definition_sha256,
            "ci_profile": self.ci_profile,
            "sandbox_profile": self.sandbox_profile,
            "expected_actor": self.expected_actor,
            "expected_installation_id": self.expected_installation_id,
            "dispatch_not_before": self.dispatch_not_before,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.to_mapping())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def _raw_commit_bytes(
    *,
    tree_oid: str,
    base_oid: str,
    head_oid: str,
    author_name: str,
    author_email: str,
    committer_name: str,
    committer_email: str,
    timestamp: int,
    message: str,
) -> bytes:
    header = (
        f"tree {tree_oid}\n"
        f"parent {base_oid}\n"
        f"parent {head_oid}\n"
        f"author {author_name} <{author_email}> {timestamp} +0000\n"
        f"committer {committer_name} <{committer_email}> {timestamp} +0000\n"
        "\n"
    )
    return (header + message).encode("utf-8", errors="strict")


def _git_object_oid(payload: bytes) -> str:
    header = f"commit {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()
