"""Minimal GitHub REST/GraphQL client for PR review orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from enum import StrEnum
import hashlib
import json
import math
import re
import time
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib import error, parse, request

from reviewer.github_auth import (
    DEFAULT_API_URL,
    GITHUB_API_VERSION,
    GitHubAppAuth,
)


DEFAULT_GRAPHQL_URL = "https://api.github.com/graphql"
DEFAULT_MAX_TARBALL_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_DIFF_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_WORKFLOW_DEFINITION_BYTES = 1024 * 1024
WORKFLOW_DISPATCH_INPUT_KEYS = frozenset(
    {"base_sha", "head_sha", "merge_descriptor", "review_context_id", "ci_request_id"}
)
DEFAULT_WORKFLOW_RUN_NAME_PREFIX = "dohwa-candidate-ci:"
_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
_PINNED_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CI_REQUEST_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REVIEW_CONTEXT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
_FULL_HEAD_REF_PATTERN = re.compile(
    r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,243}$"
)
_WORKFLOW_PATH_PATTERN = re.compile(
    r"^\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$"
)


@dataclass(frozen=True)
class WorkflowIdentity:
    path: str
    revision: str
    definition_sha256: str
    dispatch_ref: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or _WORKFLOW_PATH_PATTERN.fullmatch(self.path) is None
        ):
            raise ValueError("workflow path must be an exact .github/workflows YAML path")
        if (
            not isinstance(self.revision, str)
            or _PINNED_SHA_PATTERN.fullmatch(self.revision) is None
        ):
            raise ValueError("workflow revision must be 40 lowercase hexadecimal characters")
        if (
            not isinstance(self.definition_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.definition_sha256) is None
        ):
            raise ValueError(
                "workflow definition SHA-256 must be 64 lowercase hexadecimal characters"
            )
        if (
            not isinstance(self.dispatch_ref, str)
            or _FULL_HEAD_REF_PATTERN.fullmatch(self.dispatch_ref) is None
            or ".." in self.dispatch_ref
            or "//" in self.dispatch_ref
            or "@{" in self.dispatch_ref
            or self.dispatch_ref.endswith((".", "/", ".lock"))
            or any(
                part.startswith(".") or part.endswith(".lock")
                for part in self.dispatch_ref.removeprefix("refs/heads/").split("/")
            )
        ):
            raise ValueError(
                "dispatch_ref must be an exact canonical refs/heads reference"
            )


@dataclass(frozen=True)
class GitHubAPIError(RuntimeError):
    message: str
    status: int | None = None
    request_id: str | None = None
    code: str | None = None

    def __str__(self) -> str:
        details = []
        if self.status is not None:
            details.append(f"status={self.status}")
        if self.request_id:
            details.append(f"request_id={self.request_id}")
        suffix = f" ({', '.join(details)})" if details else ""
        prefix = f"{self.code}: " if self.code else ""
        return f"{prefix}{self.message}{suffix}"


@dataclass(frozen=True, slots=True)
class LabelTimelineEvent:
    event_id: str
    action: str
    created_at: str
    actor_type: str | None
    actor_node_id: str | None
    actor_database_id: int | None
    actor_login: str | None
    label_node_id: str
    label_name: str
    cursor: str
    ordinal: int
    predecessor_event_id: str | None


class GitHubClockDateStatus(StrEnum):
    VALID = "VALID"
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True, slots=True)
class GitHubClockObservation:
    response_date: str | None
    server_date_epoch_seconds: int | None
    request_started_monotonic: float
    response_received_monotonic: float
    request_rtt_seconds: float
    date_status: GitHubClockDateStatus

    def __post_init__(self) -> None:
        values = (
            self.request_started_monotonic,
            self.response_received_monotonic,
            self.request_rtt_seconds,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for value in values
        ):
            raise ValueError("GitHub clock monotonic values must be finite numbers")
        if self.request_rtt_seconds < 0:
            raise ValueError("GitHub clock request RTT must not be negative")
        if not math.isclose(
            self.response_received_monotonic - self.request_started_monotonic,
            self.request_rtt_seconds,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            raise ValueError("GitHub clock request RTT does not match its observations")
        if not isinstance(self.date_status, GitHubClockDateStatus):
            raise ValueError("GitHub clock Date status is invalid")
        if self.date_status is GitHubClockDateStatus.VALID:
            if (
                not self.response_date
                or isinstance(self.server_date_epoch_seconds, bool)
                or not isinstance(self.server_date_epoch_seconds, int)
            ):
                raise ValueError(
                    "valid GitHub clock observation requires a server Date"
                )
            try:
                parsed = parsedate_to_datetime(self.response_date)
                if parsed.tzinfo is None:
                    raise ValueError("GitHub clock Date has no timezone")
                canonical = format_datetime(
                    parsed.astimezone(timezone.utc), usegmt=True
                )
                epoch = parsed.timestamp()
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError("valid GitHub clock Date is malformed") from exc
            if (
                canonical != self.response_date
                or not math.isfinite(epoch)
                or not epoch.is_integer()
                or int(epoch) != self.server_date_epoch_seconds
            ):
                raise ValueError("GitHub clock Date and parsed epoch differ")
        elif self.server_date_epoch_seconds is not None:
            raise ValueError("invalid GitHub clock Date must not have a parsed epoch")
        elif (
            self.date_status is GitHubClockDateStatus.MISSING
            and self.response_date is not None
        ):
            raise ValueError("missing GitHub clock Date must not preserve a value")
        elif (
            self.date_status is GitHubClockDateStatus.MALFORMED
            and not isinstance(self.response_date, str)
        ):
            raise ValueError("malformed GitHub clock Date must preserve its value")


@dataclass(frozen=True, slots=True)
class LabelTimelineSnapshot:
    repository_node_id: str
    repository_database_id: int
    repository: str
    pull_number: int
    timeline_updated_at: str
    total_count: int
    events: tuple[LabelTimelineEvent, ...]
    clock: GitHubClockObservation


UrlOpen = Callable[..., Any]


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubClient:
    def __init__(
        self,
        auth: GitHubAppAuth,
        *,
        api_url: str = DEFAULT_API_URL,
        graphql_url: str = DEFAULT_GRAPHQL_URL,
        urlopen: UrlOpen = request.urlopen,
        redirect_urlopen: UrlOpen | None = None,
        timeout: float = 15.0,
        max_tarball_bytes: int = DEFAULT_MAX_TARBALL_BYTES,
        max_diff_bytes: int = DEFAULT_MAX_DIFF_BYTES,
        max_workflow_definition_bytes: int = DEFAULT_MAX_WORKFLOW_DEFINITION_BYTES,
        allowed_workflows: Mapping[str, Mapping[int, WorkflowIdentity]] | None = None,
        workflow_run_name_prefix: str = DEFAULT_WORKFLOW_RUN_NAME_PREFIX,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.auth = auth
        self.api_url = api_url.rstrip("/")
        self.graphql_url = graphql_url
        self._urlopen = urlopen
        self._redirect_urlopen = (
            redirect_urlopen
            if redirect_urlopen is not None
            else request.build_opener(_NoRedirectHandler()).open
        )
        self.timeout = timeout
        if isinstance(max_tarball_bytes, bool) or max_tarball_bytes <= 0:
            raise ValueError("max_tarball_bytes must be positive")
        self.max_tarball_bytes = max_tarball_bytes
        if isinstance(max_diff_bytes, bool) or max_diff_bytes <= 0:
            raise ValueError("max_diff_bytes must be positive")
        self.max_diff_bytes = max_diff_bytes
        if (
            isinstance(max_workflow_definition_bytes, bool)
            or not isinstance(max_workflow_definition_bytes, int)
            or max_workflow_definition_bytes <= 0
        ):
            raise ValueError("max_workflow_definition_bytes must be positive")
        self.max_workflow_definition_bytes = max_workflow_definition_bytes
        if not isinstance(workflow_run_name_prefix, str) or not workflow_run_name_prefix:
            raise ValueError("workflow_run_name_prefix must not be empty")
        if len(workflow_run_name_prefix) > 128:
            raise ValueError("workflow_run_name_prefix is too long")
        self.workflow_run_name_prefix = workflow_run_name_prefix
        if not callable(sleeper) or not callable(monotonic):
            raise ValueError("sleeper and monotonic must be callable")
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._allowed_workflows: dict[
            str, tuple[str, dict[int, WorkflowIdentity]]
        ] = {}
        for repository, workflows in (allowed_workflows or {}).items():
            canonical = self.auth.require_allowed_repository(repository)
            if not isinstance(workflows, Mapping) or not workflows:
                raise ValueError("each workflow allowlist must not be empty")
            normalized: dict[int, WorkflowIdentity] = {}
            for workflow_id, identity in workflows.items():
                validated_id = self._positive_workflow_id(workflow_id)
                if not isinstance(identity, WorkflowIdentity):
                    raise ValueError("workflow allowlist entries must be WorkflowIdentity values")
                normalized[validated_id] = identity
            key = canonical.casefold()
            if key in self._allowed_workflows:
                raise ValueError("duplicate repository workflow allowlist")
            self._allowed_workflows[key] = (canonical, normalized)

    def get_pull_request(self, repository: str, pull_number: int) -> dict[str, Any]:
        return self._request(
            repository,
            "GET",
            f"{self._repo_path(repository)}/pulls/{self._number(pull_number)}",
        )

    def installation_id_for_repository(self, repository: str) -> int:
        return self.auth.installation_id_for_repository(repository)

    def get_merge_base_sha(
        self,
        repository: str,
        *,
        base_sha: str,
        head_sha: str,
    ) -> str:
        base = self._sha(base_sha).lower()
        head = self._sha(head_sha).lower()
        payload = self._request(
            repository,
            "GET",
            f"{self._repo_path(repository)}/compare/{base}...{head}",
        )
        merge_base = (
            payload.get("merge_base_commit")
            if isinstance(payload, dict)
            else None
        )
        value = merge_base.get("sha") if isinstance(merge_base, dict) else None
        if not isinstance(value, str) or _PINNED_SHA_PATTERN.fullmatch(value) is None:
            raise GitHubAPIError("GitHub compare response has no canonical merge base")
        return value

    def list_open_pull_requests(self, repository: str) -> list[dict[str, Any]]:
        return self._paginate(
            repository,
            f"{self._repo_path(repository)}/pulls?state=open",
        )

    def get_pull_request_diff(self, repository: str, pull_number: int) -> str:
        canonical = self.auth.require_allowed_repository(repository)
        number = self._number(pull_number)
        token = self.auth.installation_token_for_repository(canonical)
        api_request = request.Request(
            f"{self.api_url}{self._repo_path(canonical)}/pulls/{number}",
            headers={
                "Accept": "application/vnd.github.diff",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "dohwa-bot-reviewer",
            },
            method="GET",
        )
        try:
            with self._urlopen(api_request, timeout=self.timeout) as response:
                status = getattr(response, "status", response.getcode())
                request_id = response.headers.get("X-GitHub-Request-Id")
                if status != 200:
                    raise GitHubAPIError(
                        "GitHub diff request returned an unexpected status",
                        status=status,
                        request_id=request_id,
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except (TypeError, ValueError) as exc:
                        raise GitHubAPIError(
                            "GitHub diff has an invalid Content-Length"
                        ) from exc
                    if declared_size < 0 or declared_size > self.max_diff_bytes:
                        raise GitHubAPIError("GitHub diff exceeds the size limit")
                raw = self._read_diff_limited(response)
        except error.HTTPError as exc:
            self._raise_http_error(exc)
        except error.URLError as exc:
            raise GitHubAPIError("GitHub diff request failed") from exc
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise GitHubAPIError("GitHub diff is not valid UTF-8") from exc

    def list_pull_request_files(
        self, repository: str, pull_number: int
    ) -> list[dict[str, Any]]:
        return self._paginate(
            repository,
            f"{self._repo_path(repository)}/pulls/{self._number(pull_number)}/files",
        )

    def list_pull_request_reviews(
        self, repository: str, pull_number: int
    ) -> list[dict[str, Any]]:
        return self._paginate(
            repository,
            f"{self._repo_path(repository)}/pulls/{self._number(pull_number)}/reviews",
        )

    def list_check_runs(
        self, repository: str, ref: str
    ) -> list[dict[str, Any]]:
        return self._paginate_keyed(
            repository,
            f"{self._repo_path(repository)}/commits/"
            f"{parse.quote(self._ref(ref), safe='')}/check-runs",
            key="check_runs",
        )

    def get_combined_status(self, repository: str, ref: str) -> dict[str, Any]:
        return self._request(
            repository,
            "GET",
            f"{self._repo_path(repository)}/commits/"
            f"{parse.quote(self._ref(ref), safe='')}/status",
        )

    def dispatch_workflow(
        self,
        repository: str,
        workflow_id: int,
        *,
        workflow_revision: str,
        workflow_definition: bytes,
        inputs: Mapping[str, str],
    ) -> None:
        canonical, validated_id, identity = self._allowed_workflow(
            repository, workflow_id
        )
        revision = self._exact_sha(workflow_revision, "workflow_revision")
        definition_sha256 = self._workflow_definition_sha256(workflow_definition)
        if (
            revision != identity.revision
            or definition_sha256 != identity.definition_sha256
        ):
            self._ci_error(
                "IMMUTABLE_WORKFLOW_IDENTITY_MISMATCH",
                "dispatch identity does not match the approved workflow W0 and digest",
            )
        normalized_inputs = self._validate_workflow_dispatch_inputs(inputs)
        dispatch_ref_name = identity.dispatch_ref.removeprefix("refs/")
        dispatch_ref = self._request(
            canonical,
            "GET",
            f"{self._repo_path(canonical)}/git/ref/"
            f"{parse.quote(dispatch_ref_name, safe='/')}",
        )
        ref_object = (
            dispatch_ref.get("object") if isinstance(dispatch_ref, dict) else None
        )
        if (
            dispatch_ref.get("ref") != identity.dispatch_ref
            or not isinstance(ref_object, dict)
            or ref_object.get("type") != "commit"
            or ref_object.get("sha") != identity.revision
        ):
            self._ci_error(
                "IMMUTABLE_WORKFLOW_REF_MISMATCH",
                "dispatch ref does not resolve to the approved workflow W0",
            )
        self._request(
            canonical,
            "POST",
            f"{self._repo_path(canonical)}/actions/workflows/{validated_id}/dispatches",
            body={"ref": identity.dispatch_ref, "inputs": normalized_inputs},
            expected_statuses=(204,),
        )

    def list_workflow_runs(
        self,
        repository: str,
        workflow_id: int,
        *,
        not_before: datetime,
    ) -> list[dict[str, Any]]:
        canonical, validated_id, _workflow_path = self._allowed_workflow(
            repository, workflow_id
        )
        lower_bound = self._aware_utc(not_before, "not_before")
        created_filter = lower_bound.isoformat(timespec="seconds").replace("+00:00", "Z")
        runs: list[dict[str, Any]] = []
        seen_ids: set[int] = set()
        expected_total: int | None = None
        previous_created_at: datetime | None = None
        for page in range(1, 101):
            query = parse.urlencode(
                {
                    "event": "workflow_dispatch",
                    "created": f">={created_filter}",
                    "per_page": 100,
                    "page": page,
                }
            )
            payload = self._request(
                canonical,
                "GET",
                f"{self._repo_path(canonical)}/actions/workflows/"
                f"{validated_id}/runs?{query}",
            )
            if not isinstance(payload, dict):
                self._ci_error(
                    "CI_RUN_PAGINATION_DISCONTINUITY",
                    "GitHub returned invalid workflow-runs data",
                )
            total_count = payload.get("total_count")
            page_runs = payload.get("workflow_runs")
            if (
                isinstance(total_count, bool)
                or not isinstance(total_count, int)
                or total_count < 0
                or not isinstance(page_runs, list)
            ):
                self._ci_error(
                    "CI_RUN_PAGINATION_DISCONTINUITY",
                    "GitHub returned invalid workflow-runs page data",
                )
            if total_count >= 1_000:
                self._ci_error(
                    "CI_RUN_PAGINATION_LIMIT",
                    "workflow run search exceeded the GitHub 1000-result cap",
                )
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                self._ci_error(
                    "CI_RUN_PAGINATION_DISCONTINUITY",
                    "workflow run total changed during pagination",
                )
            for run in page_runs:
                if not isinstance(run, dict):
                    self._ci_error(
                        "CI_RUN_PAGINATION_DISCONTINUITY",
                        "GitHub returned an invalid workflow run",
                    )
                run_id = run.get("id")
                if (
                    isinstance(run_id, bool)
                    or not isinstance(run_id, int)
                    or run_id <= 0
                    or run_id in seen_ids
                ):
                    self._ci_error(
                        "CI_RUN_PAGINATION_DISCONTINUITY",
                        "workflow run IDs are invalid or duplicated",
                    )
                created_at = self._github_datetime(run.get("created_at"), "created_at")
                if created_at < lower_bound:
                    self._ci_error(
                        "CI_RUN_PAGINATION_DISCONTINUITY",
                        "workflow run fell outside the requested safety window",
                    )
                if previous_created_at is not None and created_at > previous_created_at:
                    self._ci_error(
                        "CI_RUN_PAGINATION_DISCONTINUITY",
                        "workflow run ordering changed during pagination",
                    )
                previous_created_at = created_at
                seen_ids.add(run_id)
                runs.append(run)
            if len(runs) > expected_total:
                self._ci_error(
                    "CI_RUN_PAGINATION_DISCONTINUITY",
                    "workflow run count exceeded total_count",
                )
            if len(runs) == expected_total:
                return runs
            if len(page_runs) < 100:
                self._ci_error(
                    "CI_RUN_PAGINATION_DISCONTINUITY",
                    "workflow run pagination ended before total_count",
                )
        self._ci_error(
            "CI_RUN_PAGINATION_LIMIT",
            "workflow run pagination exceeded 100 pages",
        )

    def correlate_workflow_run(
        self,
        repository: str,
        workflow_id: int,
        *,
        ci_request_id: str,
        expected_actor: str,
        expected_repository_id: int,
        not_before: datetime,
        not_after: datetime,
        workflow_revision: str | None = None,
        visibility_timeout_seconds: float = 30.0,
        settling_window_seconds: float = 2.0,
        poll_interval_seconds: float = 2.0,
    ) -> dict[str, Any]:
        canonical, validated_id, identity = self._allowed_workflow(
            repository, workflow_id
        )
        request_id = self._ci_request_id(ci_request_id)
        if workflow_revision is not None:
            supplied_revision = self._exact_sha(
                workflow_revision, "workflow_revision"
            )
            if supplied_revision != identity.revision:
                self._ci_error(
                    "IMMUTABLE_WORKFLOW_IDENTITY_MISMATCH",
                    "correlation revision does not match the approved workflow W0",
                )
        if not isinstance(expected_actor, str) or not expected_actor:
            raise ValueError("expected_actor must not be empty")
        if (
            isinstance(expected_repository_id, bool)
            or not isinstance(expected_repository_id, int)
            or expected_repository_id <= 0
        ):
            raise ValueError("expected_repository_id must be positive")
        lower_bound = self._aware_utc(not_before, "not_before")
        upper_bound = self._aware_utc(not_after, "not_after")
        if upper_bound < lower_bound:
            raise ValueError("not_after must not precede not_before")
        timeout = self._positive_finite(
            visibility_timeout_seconds, "visibility_timeout_seconds"
        )
        settle_window = self._positive_finite(
            settling_window_seconds, "settling_window_seconds"
        )
        interval = self._positive_finite(
            poll_interval_seconds, "poll_interval_seconds"
        )
        visibility_deadline = self._monotonic() + timeout
        max_visibility_polls = max(1, math.ceil(timeout / interval) + 1)
        expected_title = f"{self.workflow_run_name_prefix}{request_id}"
        candidate = None
        candidate_first_seen = None
        for attempt in range(max_visibility_polls):
            runs = self.list_workflow_runs(
                canonical, validated_id, not_before=lower_bound
            )
            named_runs = [
                run for run in runs if run.get("display_title") == expected_title
            ]
            if len(named_runs) > 1:
                self._ci_error(
                    "CI_RUN_CORRELATION_AMBIGUOUS",
                    "multiple workflow runs matched the exact CI request ID",
                )
            if named_runs:
                candidate = self._validate_correlated_workflow_run(
                    named_runs[0],
                    canonical=canonical,
                    workflow_id=validated_id,
                    identity=identity,
                    expected_actor=expected_actor,
                    expected_repository_id=expected_repository_id,
                    lower_bound=lower_bound,
                    upper_bound=upper_bound,
                )
                candidate_first_seen = self._monotonic()
                break
            remaining = visibility_deadline - self._monotonic()
            if attempt + 1 >= max_visibility_polls or remaining <= 0:
                break
            self._sleeper(min(interval, remaining))
        if candidate is None:
            self._ci_error(
                "CI_RUN_NOT_FOUND",
                "no workflow run matched the exact CI request ID before the deadline",
            )

        candidate_identity = self._correlated_workflow_run_identity(candidate)
        observation_deadline = max(
            visibility_deadline,
            candidate_first_seen + settle_window,
        )
        observation_duration = max(
            0.0, observation_deadline - self._monotonic()
        )
        max_settling_polls = max(
            1, math.ceil(observation_duration / interval) + 1
        )
        for _attempt in range(max_settling_polls):
            remaining = observation_deadline - self._monotonic()
            if remaining > 0:
                self._sleeper(min(interval, remaining))
            runs = self.list_workflow_runs(
                canonical, validated_id, not_before=lower_bound
            )
            named_runs = [
                run for run in runs if run.get("display_title") == expected_title
            ]
            if len(named_runs) > 1:
                self._ci_error(
                    "CI_RUN_CORRELATION_AMBIGUOUS",
                    "multiple workflow runs matched the exact CI request ID",
                )
            if not named_runs:
                self._ci_error(
                    "CI_RUN_CORRELATION_UNSTABLE",
                    "the selected workflow run disappeared during settling",
                )
            current = self._validate_correlated_workflow_run(
                named_runs[0],
                canonical=canonical,
                workflow_id=validated_id,
                identity=identity,
                expected_actor=expected_actor,
                expected_repository_id=expected_repository_id,
                lower_bound=lower_bound,
                upper_bound=upper_bound,
            )
            if self._correlated_workflow_run_identity(current) != candidate_identity:
                self._ci_error(
                    "CI_RUN_CORRELATION_UNSTABLE",
                    "the selected workflow run identity changed during settling",
                )
            if self._monotonic() >= observation_deadline:
                return current
        self._ci_error(
            "CI_RUN_OBSERVATION_TIMEOUT",
            "the workflow run observation clock did not reach its bounded deadline",
        )

    @staticmethod
    def _correlated_workflow_run_identity(run: Mapping[str, Any]) -> tuple[Any, ...]:
        actor = run.get("actor")
        triggering_actor = run.get("triggering_actor")
        repository = run.get("repository")
        return (
            run.get("id"),
            run.get("display_title"),
            run.get("event"),
            actor.get("login") if isinstance(actor, Mapping) else None,
            triggering_actor.get("login")
            if isinstance(triggering_actor, Mapping)
            else None,
            repository.get("id") if isinstance(repository, Mapping) else None,
            repository.get("full_name")
            if isinstance(repository, Mapping)
            else None,
            run.get("workflow_id"),
            run.get("path"),
            run.get("head_sha"),
            run.get("created_at"),
            run.get("run_attempt"),
        )

    def _validate_correlated_workflow_run(
        self,
        run: dict[str, Any],
        *,
        canonical: str,
        workflow_id: int,
        identity: WorkflowIdentity,
        expected_actor: str,
        expected_repository_id: int,
        lower_bound: datetime,
        upper_bound: datetime,
    ) -> dict[str, Any]:
        created_at = self._github_datetime(run.get("created_at"), "created_at")
        actor = run.get("actor")
        triggering_actor = run.get("triggering_actor")
        run_repository = run.get("repository")
        run_attempt = run.get("run_attempt")
        identity_matches = (
            run.get("event") == "workflow_dispatch"
            and isinstance(actor, dict)
            and actor.get("login") == expected_actor
            and isinstance(triggering_actor, dict)
            and triggering_actor.get("login") == expected_actor
            and isinstance(run_repository, dict)
            and run_repository.get("id") == expected_repository_id
            and str(run_repository.get("full_name") or "").casefold()
            == canonical.casefold()
            and run.get("workflow_id") == workflow_id
            and run.get("path") == identity.path
            and run.get("head_branch")
            == identity.dispatch_ref.removeprefix("refs/heads/")
            and run.get("head_sha") == identity.revision
            and lower_bound <= created_at <= upper_bound
            and not isinstance(run_attempt, bool)
            and isinstance(run_attempt, int)
            and run_attempt > 0
        )
        if not identity_matches:
            self._ci_error(
                "CI_RUN_IDENTITY_MISMATCH",
                "workflow run did not match the approved immutable identity",
            )
        return run

    def download_tarball(self, repository: str, ref: str) -> bytes:
        canonical = self.auth.require_allowed_repository(repository)
        sha = self._sha(ref)
        token = self.auth.installation_token_for_repository(canonical)
        api_request = request.Request(
            f"{self.api_url}{self._repo_path(canonical)}/tarball/{sha}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "dohwa-bot-reviewer",
            },
            method="GET",
        )
        location = self._tarball_redirect_location(api_request)
        self._validate_codeload_url(location)

        download_request = request.Request(
            location,
            headers={"User-Agent": "dohwa-bot-reviewer"},
            method="GET",
        )
        try:
            with self._redirect_urlopen(
                download_request, timeout=self.timeout
            ) as response:
                status = getattr(response, "status", response.getcode())
                if status != 200:
                    raise GitHubAPIError(
                        "GitHub tarball download returned an unexpected status",
                        status=status,
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except (TypeError, ValueError) as exc:
                        raise GitHubAPIError(
                            "GitHub tarball has an invalid Content-Length"
                        ) from exc
                    if declared_size < 0 or declared_size > self.max_tarball_bytes:
                        raise GitHubAPIError("GitHub tarball exceeds the size limit")
                return self._read_limited(response)
        except error.HTTPError as exc:
            self._raise_http_error(exc)
        except error.URLError as exc:
            raise GitHubAPIError("GitHub tarball download failed") from exc

    def _tarball_redirect_location(self, api_request: request.Request) -> str:
        try:
            with self._redirect_urlopen(
                api_request, timeout=self.timeout
            ) as response:
                status = getattr(response, "status", response.getcode())
                location = response.headers.get("Location")
        except error.HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                self._raise_http_error(exc)
            status = exc.code
            location = exc.headers.get("Location")
            exc.close()
        except error.URLError as exc:
            raise GitHubAPIError("GitHub tarball redirect request failed") from exc
        if status not in {301, 302, 303, 307, 308}:
            raise GitHubAPIError(
                "GitHub tarball endpoint did not return a redirect",
                status=status,
            )
        if not isinstance(location, str) or not location:
            raise GitHubAPIError("GitHub tarball redirect has no Location")
        return location

    @staticmethod
    def _validate_codeload_url(location: str) -> None:
        try:
            parsed = parse.urlsplit(location)
            port = parsed.port
        except ValueError as exc:
            raise GitHubAPIError("GitHub tarball redirect URL is invalid") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.casefold() != "codeload.github.com"
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or not parsed.path.startswith("/")
        ):
            raise GitHubAPIError(
                "GitHub tarball redirect target is not trusted codeload.github.com"
            )

    def _read_limited(self, response: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(64 * 1024, self.max_tarball_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            if not isinstance(chunk, bytes):
                raise GitHubAPIError("GitHub tarball response is not binary")
            total += len(chunk)
            if total > self.max_tarball_bytes:
                raise GitHubAPIError("GitHub tarball exceeds the size limit")
            chunks.append(chunk)

    def _read_diff_limited(self, response: Any) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(64 * 1024, self.max_diff_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            if not isinstance(chunk, bytes):
                raise GitHubAPIError("GitHub diff response is not binary")
            total += len(chunk)
            if total > self.max_diff_bytes:
                raise GitHubAPIError("GitHub diff exceeds the size limit")
            chunks.append(chunk)

    def create_review(
        self,
        repository: str,
        pull_number: int,
        *,
        body: str,
        event: str,
        comments: Sequence[Mapping[str, Any]] | None = None,
        commit_id: str | None = None,
    ) -> dict[str, Any]:
        normalized_event = event.upper()
        if normalized_event not in {"APPROVE", "REQUEST_CHANGES", "COMMENT"}:
            raise ValueError("event must be APPROVE, REQUEST_CHANGES, or COMMENT")
        payload: dict[str, Any] = {"body": body, "event": normalized_event}
        if comments:
            payload["comments"] = [dict(comment) for comment in comments]
        if commit_id is not None:
            payload["commit_id"] = self._sha(commit_id)
        return self._request(
            repository,
            "POST",
            f"{self._repo_path(repository)}/pulls/{self._number(pull_number)}/reviews",
            body=payload,
            expected_statuses=(200,),
        )

    def dismiss_review(
        self,
        repository: str,
        pull_number: int,
        review_id: int,
        *,
        message: str,
    ) -> dict[str, Any]:
        if isinstance(review_id, bool) or not isinstance(review_id, int) or review_id <= 0:
            raise ValueError("review_id must be a positive integer")
        if not isinstance(message, str) or not message.strip() or len(message) > 1_000:
            raise ValueError("dismissal message must contain at most 1000 characters")
        payload = self._request(
            repository,
            "PUT",
            (
                f"{self._repo_path(repository)}/pulls/"
                f"{self._number(pull_number)}/reviews/{review_id}/dismissals"
            ),
            body={"message": message},
            expected_statuses=(200,),
        )
        if (
            not isinstance(payload, dict)
            or payload.get("id") != review_id
            or str(payload.get("state") or "").upper() != "DISMISSED"
        ):
            raise GitHubAPIError("GitHub did not confirm review dismissal")
        return payload

    def create_comment(
        self, repository: str, pull_number: int, *, body: str
    ) -> dict[str, Any]:
        if not body:
            raise ValueError("body must not be empty")
        return self._request(
            repository,
            "POST",
            f"{self._repo_path(repository)}/issues/{self._number(pull_number)}/comments",
            body={"body": body},
            expected_statuses=(201,),
        )

    def add_labels(
        self, repository: str, pull_number: int, labels: Iterable[str]
    ) -> list[dict[str, Any]]:
        normalized = list(dict.fromkeys(label for label in labels if label))
        if not normalized:
            raise ValueError("labels must not be empty")
        payload = self._request(
            repository,
            "POST",
            f"{self._repo_path(repository)}/issues/{self._number(pull_number)}/labels",
            body={"labels": normalized},
            expected_statuses=(200,),
        )
        if not isinstance(payload, list):
            raise GitHubAPIError("GitHub returned invalid label data")
        return payload

    def remove_label(
        self, repository: str, pull_number: int, label: str
    ) -> list[dict[str, Any]]:
        if not isinstance(label, str) or not label:
            raise ValueError("label must not be empty")
        payload = self._request(
            repository,
            "DELETE",
            f"{self._repo_path(repository)}/issues/{self._number(pull_number)}"
            f"/labels/{parse.quote(label, safe='')}",
            expected_statuses=(200,),
        )
        if not isinstance(payload, list) or not all(
            isinstance(item, dict)
            and self._is_positive_int(item.get("id"))
            and isinstance(item.get("node_id"), str)
            and bool(item["node_id"])
            and isinstance(item.get("name"), str)
            and bool(item["name"])
            for item in payload
        ):
            raise GitHubAPIError("GitHub returned invalid label data")
        return payload

    def list_pull_request_label_timeline(
        self,
        repository: str,
        pull_number: int,
        *,
        should_stop: Callable[[], bool] | None = None,
    ) -> LabelTimelineSnapshot:
        canonical = self.auth.require_allowed_repository(repository)
        number = self._number(pull_number)
        if should_stop is not None and not callable(should_stop):
            raise TypeError("should_stop must be callable")

        def require_running() -> None:
            if should_stop is not None and should_stop():
                raise GitHubAPIError(
                    "GitHub label timeline request interrupted"
                )

        owner, name = canonical.split("/", 1)
        query = (
            "query PullRequestLabelTimeline("
            "$owner: String!, $name: String!, $number: Int!, "
            "$first: Int!, $after: String) {"
            " repository(owner: $owner, name: $name) {"
            " id databaseId nameWithOwner"
            " pullRequest(number: $number) {"
            " number"
            " timelineItems("
            "first: $first, after: $after, "
            "itemTypes: [LABELED_EVENT, UNLABELED_EVENT]) {"
            " updatedAt filteredCount"
            " edges {"
            " cursor"
            " node {"
            " __typename"
            " ... on LabeledEvent {"
            " id createdAt"
            " actor {"
            " __typename login"
            " ... on Node { id }"
            " ... on Bot { databaseId }"
            " ... on Mannequin { databaseId }"
            " ... on Organization { databaseId }"
            " ... on User { databaseId }"
            " }"
            " label { id name }"
            " }"
            " ... on UnlabeledEvent {"
            " id createdAt"
            " actor {"
            " __typename login"
            " ... on Node { id }"
            " ... on Bot { databaseId }"
            " ... on Mannequin { databaseId }"
            " ... on Organization { databaseId }"
            " ... on User { databaseId }"
            " }"
            " label { id name }"
            " }"
            " }"
            " }"
            " pageInfo { hasNextPage endCursor }"
            " }"
            " }"
            " }"
            "}"
        )
        cursor: str | None = None
        seen_cursors: set[str] = set()
        seen_event_ids: set[str] = set()
        events: list[LabelTimelineEvent] = []
        identity: tuple[str, int, str, int] | None = None
        timeline_identity: tuple[str, int] | None = None
        previous_created_at: datetime | None = None

        for _page in range(100):
            require_running()
            data = self._graphql(
                canonical,
                query,
                {
                    "owner": owner,
                    "name": name,
                    "number": number,
                    "first": 100,
                    "after": cursor,
                },
            )
            page_identity, page_timeline, edges, page_info = (
                self._parse_label_timeline_page(
                    data, canonical=canonical, pull_number=number
                )
            )
            if identity is None:
                identity = page_identity
                timeline_identity = page_timeline
            elif (
                identity != page_identity
                or timeline_identity is None
                or timeline_identity[0] != page_timeline[0]
            ):
                self._label_timeline_error(
                    "GitHub label timeline changed during pagination"
                )
            assert timeline_identity is not None
            expected_remaining = timeline_identity[1] - len(events)
            if (
                expected_remaining < 0
                or page_timeline[1] != expected_remaining
                or len(edges) > expected_remaining
            ):
                self._label_timeline_error(
                    "GitHub label timeline count changed during pagination"
                )

            if cursor is not None and not edges:
                self._label_timeline_error(
                    "GitHub label timeline returned an empty intermediate page"
                )
            for edge in edges:
                event_id = edge["event_id"]
                edge_cursor = edge["cursor"]
                if event_id in seen_event_ids or edge_cursor in seen_cursors:
                    self._label_timeline_error(
                        "GitHub label timeline repeated an event or cursor"
                    )
                created_at = self._label_timeline_datetime(
                    edge["created_at"], "event createdAt"
                )
                if previous_created_at is not None and created_at < previous_created_at:
                    self._label_timeline_error(
                        "GitHub label timeline event order moved backwards"
                    )
                previous_created_at = created_at
                predecessor = events[-1].event_id if events else None
                events.append(
                    LabelTimelineEvent(
                        event_id=event_id,
                        action=edge["action"],
                        created_at=edge["created_at"],
                        actor_node_id=edge["actor_node_id"],
                        actor_type=edge["actor_type"],
                        actor_database_id=edge["actor_database_id"],
                        actor_login=edge["actor_login"],
                        label_node_id=edge["label_node_id"],
                        label_name=edge["label_name"],
                        cursor=edge_cursor,
                        ordinal=len(events) + 1,
                        predecessor_event_id=predecessor,
                    )
                )
                seen_event_ids.add(event_id)
                seen_cursors.add(edge_cursor)

            has_next_page = page_info["hasNextPage"]
            end_cursor = page_info["endCursor"]
            if edges and end_cursor != edges[-1]["cursor"]:
                self._label_timeline_error(
                    "GitHub label timeline end cursor does not match page order"
                )
            if not has_next_page:
                break
            if not isinstance(end_cursor, str) or not end_cursor:
                self._label_timeline_error(
                    "GitHub label timeline has an invalid next cursor"
                )
            cursor = end_cursor
        else:
            self._label_timeline_error(
                "GitHub label timeline pagination exceeded 100 pages"
            )

        assert identity is not None
        assert timeline_identity is not None
        if len(events) != timeline_identity[1]:
            self._label_timeline_error(
                "GitHub label timeline count does not match its events"
            )

        require_running()
        watermark_data, clock = self._graphql_observed(
            canonical,
            query,
            {
                "owner": owner,
                "name": name,
                "number": number,
                "first": 1,
                "after": None,
            },
        )
        watermark_identity, watermark_timeline, watermark_edges, _ = (
            self._parse_label_timeline_page(
                watermark_data, canonical=canonical, pull_number=number
            )
        )
        first_identity = (
            (events[0].event_id, events[0].cursor) if events else None
        )
        watermark_first = (
            (watermark_edges[0]["event_id"], watermark_edges[0]["cursor"])
            if watermark_edges
            else None
        )
        if (
            watermark_identity != identity
            or watermark_timeline != timeline_identity
            or watermark_first != first_identity
        ):
            self._label_timeline_error(
                "GitHub label timeline changed before verification completed"
            )

        if any(
            self._label_timeline_datetime(previous.created_at, "event createdAt")
            == self._label_timeline_datetime(current.created_at, "event createdAt")
            for previous, current in zip(events, events[1:])
        ):
            clock = self._verify_tied_label_timeline(
                canonical=canonical,
                owner=owner,
                name=name,
                pull_number=number,
                query=query,
                identity=identity,
                timeline_identity=timeline_identity,
                events=events,
                should_stop=should_stop,
            )

        return LabelTimelineSnapshot(
            repository_node_id=identity[0],
            repository_database_id=identity[1],
            repository=identity[2],
            pull_number=identity[3],
            timeline_updated_at=timeline_identity[0],
            total_count=timeline_identity[1],
            events=tuple(events),
            clock=clock,
        )

    def _verify_tied_label_timeline(
        self,
        *,
        canonical: str,
        owner: str,
        name: str,
        pull_number: int,
        query: str,
        identity: tuple[str, int, str, int],
        timeline_identity: tuple[str, int],
        events: Sequence[LabelTimelineEvent],
        should_stop: Callable[[], bool] | None,
    ) -> GitHubClockObservation:
        cursor: str | None = None
        event_index = 0
        observation: GitHubClockObservation | None = None
        for _page in range(100):
            if should_stop is not None and should_stop():
                raise GitHubAPIError(
                    "GitHub label timeline request interrupted"
                )
            data, observation = self._graphql_observed(
                canonical,
                query,
                {
                    "owner": owner,
                    "name": name,
                    "number": pull_number,
                    "first": 100,
                    "after": cursor,
                },
            )
            page_identity, page_timeline, edges, page_info = (
                self._parse_label_timeline_page(
                    data, canonical=canonical, pull_number=pull_number
                )
            )
            if (
                page_identity != identity
                or page_timeline[0] != timeline_identity[0]
            ):
                self._label_timeline_error(
                    "GitHub tied label timeline changed during full verification"
                )
            expected_remaining = timeline_identity[1] - event_index
            if (
                expected_remaining < 0
                or page_timeline[1] != expected_remaining
                or len(edges) > expected_remaining
            ):
                self._label_timeline_error(
                    "GitHub tied label timeline count changed during full "
                    "verification"
                )
            if cursor is not None and not edges:
                self._label_timeline_error(
                    "GitHub tied label timeline returned an empty intermediate page"
                )
            for edge in edges:
                if event_index >= len(events) or not self._same_label_timeline_event(
                    events[event_index], edge
                ):
                    self._label_timeline_error(
                        "GitHub tied label timeline sequence changed during "
                        "verification"
                    )
                event_index += 1

            has_next_page = page_info["hasNextPage"]
            end_cursor = page_info["endCursor"]
            if edges and end_cursor != edges[-1]["cursor"]:
                self._label_timeline_error(
                    "GitHub tied label timeline end cursor does not match page order"
                )
            if not has_next_page:
                break
            if not isinstance(end_cursor, str) or not end_cursor:
                self._label_timeline_error(
                    "GitHub tied label timeline has an invalid next cursor"
                )
            cursor = end_cursor
        else:
            self._label_timeline_error(
                "GitHub tied label timeline pagination exceeded 100 pages"
            )

        if event_index != len(events) or observation is None:
            self._label_timeline_error(
                "GitHub tied label timeline sequence is incomplete"
            )
        return observation

    @staticmethod
    def _same_label_timeline_event(
        expected: LabelTimelineEvent, actual: Mapping[str, Any]
    ) -> bool:
        return (
            expected.event_id == actual.get("event_id")
            and expected.action == actual.get("action")
            and expected.created_at == actual.get("created_at")
            and expected.actor_type == actual.get("actor_type")
            and expected.actor_node_id == actual.get("actor_node_id")
            and expected.actor_database_id == actual.get("actor_database_id")
            and expected.actor_login == actual.get("actor_login")
            and expected.label_node_id == actual.get("label_node_id")
            and expected.label_name == actual.get("label_name")
            and expected.cursor == actual.get("cursor")
        )

    def has_unresolved_review_threads(
        self, repository: str, pull_number: int
    ) -> bool:
        canonical = self.auth.require_allowed_repository(repository)
        number = self._number(pull_number)
        owner, name = canonical.split("/", 1)
        query = (
            "query PullRequestReviewThreads("
            "$owner: String!, $name: String!, $number: Int!, $after: String) {"
            " repository(owner: $owner, name: $name) {"
            " pullRequest(number: $number) {"
            " reviewThreads(first: 100, after: $after) {"
            " nodes { isResolved }"
            " pageInfo { hasNextPage endCursor }"
            " }"
            " }"
            " }"
            "}"
        )
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(100):
            data = self._graphql(
                canonical,
                query,
                {
                    "owner": owner,
                    "name": name,
                    "number": number,
                    "after": cursor,
                },
            )
            repository_data = data.get("repository")
            if not isinstance(repository_data, dict):
                raise GitHubAPIError("GitHub returned invalid review-thread repository data")
            pull_data = repository_data.get("pullRequest")
            if not isinstance(pull_data, dict):
                raise GitHubAPIError("GitHub returned invalid review-thread pull request data")
            threads = pull_data.get("reviewThreads")
            if not isinstance(threads, dict):
                raise GitHubAPIError("GitHub returned invalid review-thread data")
            nodes = threads.get("nodes")
            page_info = threads.get("pageInfo")
            if not isinstance(nodes, list) or not isinstance(page_info, dict):
                raise GitHubAPIError("GitHub returned invalid review-thread page data")
            page_has_unresolved = False
            for node in nodes:
                if not isinstance(node, dict) or not isinstance(
                    node.get("isResolved"), bool
                ):
                    raise GitHubAPIError("GitHub returned invalid review-thread node data")
                if node["isResolved"] is False:
                    page_has_unresolved = True
            has_next_page = page_info.get("hasNextPage")
            if not isinstance(has_next_page, bool):
                raise GitHubAPIError("GitHub returned invalid review-thread page info")
            if page_has_unresolved:
                return True
            if not has_next_page:
                return False
            next_cursor = page_info.get("endCursor")
            if (
                not isinstance(next_cursor, str)
                or not next_cursor
                or next_cursor in seen_cursors
            ):
                raise GitHubAPIError("GitHub returned invalid review-thread cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise GitHubAPIError("GitHub review-thread pagination exceeded 100 pages")

    def convert_pull_request_to_draft(
        self,
        repository: str,
        pull_number: int,
        *,
        pull_request_node_id: str | None = None,
    ) -> dict[str, Any]:
        node_id = pull_request_node_id
        if node_id is None:
            pull = self.get_pull_request(repository, pull_number)
            node_id = pull.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            raise GitHubAPIError("pull request has no GraphQL node ID")
        query = (
            "mutation ConvertPullRequestToDraft($pullRequestId: ID!) {"
            " convertPullRequestToDraft(input: {pullRequestId: $pullRequestId}) {"
            " pullRequest { id isDraft }"
            " }"
            "}"
        )
        payload = self._graphql(
            repository, query, {"pullRequestId": node_id}
        )
        result = payload.get("convertPullRequestToDraft")
        if not isinstance(result, dict) or not isinstance(
            result.get("pullRequest"), dict
        ):
            raise GitHubAPIError("GitHub returned invalid draft-conversion data")
        return result["pullRequest"]

    def squash_merge(
        self,
        repository: str,
        pull_number: int,
        *,
        expected_head_sha: str,
        commit_title: str | None = None,
        commit_message: str | None = None,
    ) -> dict[str, Any]:
        expected_sha = self._sha(expected_head_sha)
        pull = self.get_pull_request(repository, pull_number)
        current_sha = (pull.get("head") or {}).get("sha")
        if current_sha != expected_sha:
            raise GitHubAPIError("pull request head SHA changed before merge")
        if pull.get("state") != "open" or pull.get("draft") is True:
            raise GitHubAPIError("pull request is not open and ready for merge")

        payload: dict[str, Any] = {
            "merge_method": "squash",
            "sha": expected_sha,
        }
        if commit_title is not None:
            payload["commit_title"] = commit_title
        if commit_message is not None:
            payload["commit_message"] = commit_message
        result = self._request(
            repository,
            "PUT",
            f"{self._repo_path(repository)}/pulls/{self._number(pull_number)}/merge",
            body=payload,
            expected_statuses=(200,),
        )
        if result.get("merged") is not True:
            raise GitHubAPIError(
                str(result.get("message") or "GitHub did not merge the pull request")
            )
        return result

    def _parse_label_timeline_page(
        self,
        data: Mapping[str, Any],
        *,
        canonical: str,
        pull_number: int,
    ) -> tuple[
        tuple[str, int, str, int],
        tuple[str, int],
        list[dict[str, Any]],
        dict[str, Any],
    ]:
        repository_data = data.get("repository")
        if not isinstance(repository_data, dict):
            self._label_timeline_error(
                "GitHub returned invalid label-timeline repository data"
            )
        repository_node_id = repository_data.get("id")
        repository_database_id = repository_data.get("databaseId")
        repository_name = repository_data.get("nameWithOwner")
        pull_data = repository_data.get("pullRequest")
        if (
            not isinstance(repository_node_id, str)
            or not repository_node_id
            or not self._is_positive_int(repository_database_id)
            or repository_name != canonical
            or not isinstance(pull_data, dict)
            or pull_data.get("number") != pull_number
        ):
            self._label_timeline_error(
                "GitHub returned mismatched label-timeline identity"
            )

        timeline = pull_data.get("timelineItems")
        if not isinstance(timeline, dict):
            self._label_timeline_error(
                "GitHub returned invalid label-timeline connection data"
            )
        updated_at = timeline.get("updatedAt")
        self._label_timeline_datetime(updated_at, "timeline updatedAt")
        total_count = timeline.get("filteredCount")
        edges_data = timeline.get("edges")
        page_info = timeline.get("pageInfo")
        if (
            not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < 0
            or not isinstance(edges_data, list)
            or not isinstance(page_info, dict)
            or not isinstance(page_info.get("hasNextPage"), bool)
            or not (
                page_info.get("endCursor") is None
                or (
                    isinstance(page_info.get("endCursor"), str)
                    and bool(page_info["endCursor"])
                )
            )
        ):
            self._label_timeline_error(
                "GitHub returned invalid label-timeline page data"
            )

        edges: list[dict[str, Any]] = []
        for edge in edges_data:
            if not isinstance(edge, dict):
                self._label_timeline_error(
                    "GitHub returned invalid label-timeline edge"
                )
            cursor = edge.get("cursor")
            node = edge.get("node")
            if not isinstance(cursor, str) or not cursor or not isinstance(node, dict):
                self._label_timeline_error(
                    "GitHub returned invalid label-timeline edge"
                )
            typename = node.get("__typename")
            if typename not in {"LabeledEvent", "UnlabeledEvent"}:
                self._label_timeline_error(
                    "GitHub returned an unexpected label-timeline event type"
                )
            event_id = node.get("id")
            created_at = node.get("createdAt")
            actor = node.get("actor")
            label = node.get("label")
            actor_type: str | None = None
            actor_node_id: str | None = None
            actor_database_id: int | None = None
            actor_login: str | None = None
            if actor is not None:
                if not isinstance(actor, dict):
                    self._label_timeline_error(
                        "GitHub returned invalid label-timeline actor data"
                    )
                actor_type = actor.get("__typename")
                actor_node_id = actor.get("id")
                actor_database_id = actor.get("databaseId")
                actor_login = actor.get("login")
                if (
                    not isinstance(actor_type, str)
                    or not actor_type
                    or not isinstance(actor_login, str)
                    or not actor_login
                    or not (
                        actor_node_id is None
                        or (isinstance(actor_node_id, str) and bool(actor_node_id))
                    )
                    or not (
                        actor_database_id is None
                        or self._is_positive_int(actor_database_id)
                    )
                ):
                    self._label_timeline_error(
                        "GitHub returned invalid label-timeline actor identity"
                    )
            self._label_timeline_datetime(created_at, "event createdAt")
            if (
                not isinstance(event_id, str)
                or not event_id
                or not isinstance(label, dict)
                or not isinstance(label.get("id"), str)
                or not label["id"]
                or not isinstance(label.get("name"), str)
                or not label["name"]
            ):
                self._label_timeline_error(
                    "GitHub returned invalid label-timeline event identity"
                )
            edges.append(
                {
                    "event_id": event_id,
                    "action": "labeled" if typename == "LabeledEvent" else "unlabeled",
                    "created_at": created_at,
                    "actor_type": actor_type,
                    "actor_node_id": actor_node_id,
                    "actor_database_id": actor_database_id,
                    "actor_login": actor_login,
                    "label_node_id": label["id"],
                    "label_name": label["name"],
                    "cursor": cursor,
                }
            )

        return (
            (
                repository_node_id,
                repository_database_id,
                repository_name,
                pull_number,
            ),
            (updated_at, total_count),
            edges,
            page_info,
        )

    def _paginate(self, repository: str, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in range(1, 101):
            separator = "&" if "?" in path else "?"
            payload = self._request(
                repository,
                "GET",
                f"{path}{separator}per_page=100&page={page}",
            )
            if not isinstance(payload, list) or not all(
                isinstance(item, dict) for item in payload
            ):
                raise GitHubAPIError("GitHub returned invalid paginated data")
            items.extend(payload)
            if len(payload) < 100:
                return items
        raise GitHubAPIError("GitHub pagination exceeded 100 pages")

    def _paginate_keyed(
        self, repository: str, path: str, *, key: str
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in range(1, 101):
            separator = "&" if "?" in path else "?"
            payload = self._request(
                repository,
                "GET",
                f"{path}{separator}per_page=100&page={page}",
            )
            page_items = payload.get(key) if isinstance(payload, dict) else None
            if not isinstance(page_items, list) or not all(
                isinstance(item, dict) for item in page_items
            ):
                raise GitHubAPIError(f"GitHub returned invalid {key} data")
            items.extend(page_items)
            if len(page_items) < 100:
                return items
        raise GitHubAPIError(f"GitHub {key} pagination exceeded 100 pages")

    def _allowed_workflow(
        self, repository: str, workflow_id: int
    ) -> tuple[str, int, WorkflowIdentity]:
        canonical = self.auth.require_allowed_repository(repository)
        validated_id = self._positive_workflow_id(workflow_id)
        entry = self._allowed_workflows.get(canonical.casefold())
        if entry is None or validated_id not in entry[1]:
            raise GitHubAPIError("workflow is not allowlisted")
        return canonical, validated_id, entry[1][validated_id]

    @staticmethod
    def _positive_workflow_id(workflow_id: int) -> int:
        if (
            isinstance(workflow_id, bool)
            or not isinstance(workflow_id, int)
            or workflow_id <= 0
        ):
            raise ValueError("workflow_id must be a positive integer")
        return workflow_id

    @staticmethod
    def _exact_sha(value: str, name: str) -> str:
        if not isinstance(value, str) or _SHA_PATTERN.fullmatch(value) is None:
            raise ValueError(f"{name} must be exactly 40 hexadecimal characters")
        return value.lower()

    def _workflow_definition_sha256(self, value: bytes) -> str:
        if not isinstance(value, bytes):
            raise ValueError("workflow_definition must be bytes")
        if not value:
            raise ValueError("workflow_definition must not be empty")
        if len(value) > self.max_workflow_definition_bytes:
            raise ValueError("workflow_definition exceeds the size limit")
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _ci_request_id(value: str) -> str:
        if not isinstance(value, str) or _CI_REQUEST_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("ci_request_id must be 64 lowercase hexadecimal characters")
        return value

    def _validate_workflow_dispatch_inputs(
        self, inputs: Mapping[str, str]
    ) -> dict[str, str]:
        if not isinstance(inputs, Mapping) or set(inputs) != WORKFLOW_DISPATCH_INPUT_KEYS:
            raise ValueError("workflow inputs must contain only the approved keys")
        if not all(isinstance(value, str) for value in inputs.values()):
            raise ValueError("workflow input values must be strings")
        normalized = dict(inputs)
        normalized["base_sha"] = self._exact_sha(inputs["base_sha"], "base_sha")
        normalized["head_sha"] = self._exact_sha(inputs["head_sha"], "head_sha")
        normalized["ci_request_id"] = self._ci_request_id(inputs["ci_request_id"])
        if not normalized["merge_descriptor"] or len(normalized["merge_descriptor"]) > 65_536:
            raise ValueError("merge_descriptor must be between 1 and 65536 characters")
        if (
            _REVIEW_CONTEXT_ID_PATTERN.fullmatch(normalized["review_context_id"])
            is None
        ):
            raise ValueError("review_context_id contains unsafe characters")
        return normalized

    @staticmethod
    def _nonnegative_finite(value: float, name: str) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError(f"{name} must be finite and nonnegative")
        return float(value)

    @staticmethod
    def _positive_finite(value: float, name: str) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"{name} must be finite and positive")
        return float(value)

    @staticmethod
    def _aware_utc(value: datetime, name: str) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError(f"{name} must be a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _github_datetime(value: Any, name: str) -> datetime:
        if not isinstance(value, str) or not value:
            raise GitHubAPIError(
                f"workflow run has invalid {name}",
                code="CI_RUN_PAGINATION_DISCONTINUITY",
            )
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GitHubAPIError(
                f"workflow run has invalid {name}",
                code="CI_RUN_PAGINATION_DISCONTINUITY",
            ) from exc
        if parsed.tzinfo is None:
            raise GitHubAPIError(
                f"workflow run has invalid {name}",
                code="CI_RUN_PAGINATION_DISCONTINUITY",
            )
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _ci_error(code: str, message: str) -> None:
        raise GitHubAPIError(message, code=code)

    @staticmethod
    def _is_positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    @staticmethod
    def _label_timeline_datetime(value: object, name: str) -> datetime:
        if not isinstance(value, str) or not value:
            GitHubClient._label_timeline_error(
                f"GitHub label timeline has invalid {name}"
            )
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GitHubAPIError(
                f"GitHub label timeline has invalid {name}",
                code="LABEL_TIMELINE_DISCONTINUITY",
            ) from exc
        if parsed.tzinfo is None:
            GitHubClient._label_timeline_error(
                f"GitHub label timeline has invalid {name}"
            )
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _label_timeline_error(message: str) -> None:
        raise GitHubAPIError(
            message,
            code="LABEL_TIMELINE_DISCONTINUITY",
        )

    def _repo_path(self, repository: str) -> str:
        canonical = self.auth.require_allowed_repository(repository)
        owner, name = canonical.split("/", 1)
        return f"/repos/{parse.quote(owner, safe='')}/{parse.quote(name, safe='')}"

    @staticmethod
    def _number(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("pull_number must be a positive integer")
        return value

    @staticmethod
    def _sha(value: str) -> str:
        if not isinstance(value, str) or _SHA_PATTERN.fullmatch(value) is None:
            raise ValueError("SHA must be exactly 40 hexadecimal characters")
        return value.lower()

    @staticmethod
    def _ref(value: str) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("ref must not be empty")
        return value

    def _request(
        self,
        repository: str,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        expected_statuses: tuple[int, ...] = (200,),
    ) -> Any:
        return self._send_json(
            repository,
            method,
            f"{self.api_url}{path}",
            body=body,
            expected_statuses=expected_statuses,
        )

    def _graphql(
        self, repository: str, query: str, variables: dict[str, Any]
    ) -> dict[str, Any]:
        data, _ = self._graphql_observed(repository, query, variables)
        return data

    def _graphql_observed(
        self, repository: str, query: str, variables: dict[str, Any]
    ) -> tuple[dict[str, Any], GitHubClockObservation]:
        payload, observation = self._send_json_observed(
            repository,
            "POST",
            self.graphql_url,
            body={"query": query, "variables": variables},
            expected_statuses=(200,),
        )
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if errors:
            messages = [
                item.get("message", "unknown GraphQL error")
                for item in errors
                if isinstance(item, dict)
            ]
            raise GitHubAPIError(
                f"GitHub GraphQL request failed: {'; '.join(messages)}"
            )
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise GitHubAPIError("GitHub returned invalid GraphQL data")
        return data, observation

    def _send_json(
        self,
        repository: str,
        method: str,
        url: str,
        *,
        body: dict[str, Any] | None,
        expected_statuses: tuple[int, ...],
    ) -> Any:
        payload, _ = self._send_json_observed(
            repository,
            method,
            url,
            body=body,
            expected_statuses=expected_statuses,
        )
        return payload

    def _send_json_observed(
        self,
        repository: str,
        method: str,
        url: str,
        *,
        body: dict[str, Any] | None,
        expected_statuses: tuple[int, ...],
    ) -> tuple[Any, GitHubClockObservation]:
        canonical = self.auth.require_allowed_repository(repository)
        token = self.auth.installation_token_for_repository(canonical)
        encoded_body = (
            json.dumps(body, separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "dohwa-bot-reviewer",
        }
        if encoded_body is not None:
            headers["Content-Type"] = "application/json"
        api_request = request.Request(
            url,
            data=encoded_body,
            headers=headers,
            method=method,
        )
        request_started = self._monotonic()
        try:
            with self._urlopen(api_request, timeout=self.timeout) as response:
                raw = response.read()
                response_received = self._monotonic()
                status = getattr(response, "status", response.getcode())
                request_id = response.headers.get("X-GitHub-Request-Id")
                response_date = response.headers.get("Date")
        except error.HTTPError as exc:
            self._raise_http_error(exc)
        except error.URLError as exc:
            raise GitHubAPIError("GitHub API request failed") from exc
        if status not in expected_statuses:
            raise GitHubAPIError(
                "GitHub API returned an unexpected status",
                status=status,
                request_id=request_id,
            )
        observation = self._github_clock_observation(
            response_date,
            request_started=request_started,
            response_received=response_received,
        )
        if not raw:
            return {}, observation
        try:
            return json.loads(raw.decode("utf-8")), observation
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubAPIError("GitHub returned invalid JSON") from exc

    @staticmethod
    def _github_clock_observation(
        response_date: object,
        *,
        request_started: float,
        response_received: float,
    ) -> GitHubClockObservation:
        raw_date = response_date if isinstance(response_date, str) else None
        status = GitHubClockDateStatus.MISSING
        epoch: int | None = None
        if raw_date is not None:
            status = GitHubClockDateStatus.MALFORMED
            try:
                parsed = parsedate_to_datetime(raw_date)
                if (
                    parsed.tzinfo is not None
                    and format_datetime(parsed.astimezone(timezone.utc), usegmt=True)
                    == raw_date
                ):
                    timestamp = parsed.timestamp()
                    if math.isfinite(timestamp) and timestamp.is_integer():
                        epoch = int(timestamp)
                        status = GitHubClockDateStatus.VALID
            except (TypeError, ValueError, OverflowError):
                pass
        return GitHubClockObservation(
            response_date=raw_date,
            server_date_epoch_seconds=epoch,
            request_started_monotonic=request_started,
            response_received_monotonic=response_received,
            request_rtt_seconds=response_received - request_started,
            date_status=status,
        )

    @staticmethod
    def _raise_http_error(exc: error.HTTPError) -> None:
        request_id = exc.headers.get("X-GitHub-Request-Id")
        message = "GitHub API request failed"
        try:
            payload = json.loads(exc.read().decode("utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("message"), str):
                message = payload["message"]
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        raise GitHubAPIError(message, status=exc.code, request_id=request_id) from exc
