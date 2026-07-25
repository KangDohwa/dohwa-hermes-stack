from __future__ import annotations

import re
from typing import Any, Protocol

from reviewer.approval import (
    APPROVAL_REVIEW_DECISION,
    ReviewAttempt,
    ReviewAttemptStatus,
)
from reviewer.decision import (
    find_review_attempt_review,
    parse_review_attempt_marker,
    review_attempt_marker,
)
from reviewer.models import ReviewJob
from reviewer.review_schema import ReviewDecision
from reviewer.state import StateStore


REVIEW_PUBLISH_UNKNOWN = "REVIEW_PUBLISH_UNKNOWN"
_BOT_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98})\[bot\]$")


class ReviewPublishUnknown(RuntimeError):
    """A review POST may have succeeded and must not be retried automatically."""

    def __init__(self, message: str = REVIEW_PUBLISH_UNKNOWN) -> None:
        super().__init__(message)
        self.reason = REVIEW_PUBLISH_UNKNOWN


class ReviewGitHubClient(Protocol):
    def list_pull_request_reviews(
        self, repository: str, pull_number: int
    ) -> list[dict[str, Any]]: ...

    def create_review(
        self,
        repository: str,
        pull_number: int,
        *,
        body: str,
        event: str,
        commit_id: str | None = None,
    ) -> dict[str, Any]: ...


class ReviewAttemptPublisher:
    def __init__(
        self,
        store: StateStore,
        github: ReviewGitHubClient,
        *,
        app_actor: str,
    ) -> None:
        if (
            not isinstance(app_actor, str)
            or _BOT_LOGIN.fullmatch(app_actor) is None
        ):
            raise ValueError("app_actor must be a GitHub App bot login")
        self._store = store
        self._github = github
        self._app_actor = app_actor

    def publish(
        self,
        job: ReviewJob,
        attempt: ReviewAttempt,
        *,
        body: str,
        event: str,
        decision: ReviewDecision,
    ) -> ReviewAttempt:
        if decision is not ReviewDecision.PASS:
            raise ValueError("approval-capable review attempt requires a pass decision")
        if attempt.review_decision != APPROVAL_REVIEW_DECISION:
            raise ValueError("review attempt is not bound to a pass decision")
        normalized_event = _pass_review_event(event)
        marker = _validate_identity(job, attempt, body)
        current = self._load_current(
            job, attempt, allow_invalidated_reconciliation=True
        )

        reviews = self._github.list_pull_request_reviews(
            job.repository, job.pull_number
        )
        existing = self._trusted_review(
            reviews,
            marker=marker,
            event=normalized_event,
            head_sha=job.head_sha,
        )
        if existing is not None:
            return self._confirm_trusted_existing(current, existing)

        publish_state = self._store.get_review_attempt_publish_state(
            current.review_context_id
        )
        if publish_state != "NOT_SENT":
            raise ReviewPublishUnknown()

        try:
            self._store.mark_review_attempt_publish_maybe_sent(
                current.review_context_id
            )
        except RuntimeError as exc:
            # Another worker may have won the NOT_SENT -> MAYBE_SENT CAS.
            # Once that happens this worker may only reconcile, never POST.
            return self._reconcile_after_cas_loss(
                job,
                current,
                marker=marker,
                event=normalized_event,
                cause=exc,
            )

        try:
            current = self._load_current(
                job, current, allow_invalidated_reconciliation=False
            )
        except Exception as exc:
            # The CAS is durable and cannot be rolled back safely: another
            # publisher or a restored process must treat this as MAYBE_SENT.
            raise ReviewPublishUnknown() from exc

        try:
            response = self._github.create_review(
                job.repository,
                job.pull_number,
                body=body,
                event=normalized_event,
                commit_id=job.head_sha,
            )
        except Exception as exc:
            return self._reconcile_after_post(
                job,
                current,
                marker=marker,
                event=normalized_event,
                cause=exc,
            )

        try:
            trusted = self._trusted_review(
                [response],
                marker=marker,
                event=normalized_event,
                head_sha=job.head_sha,
            )
        except Exception as exc:
            return self._reconcile_after_post(
                job,
                current,
                marker=marker,
                event=normalized_event,
                cause=exc,
            )
        if trusted is None:
            return self._reconcile_after_post(
                job,
                current,
                marker=marker,
                event=normalized_event,
                cause=ValueError("GitHub returned an untrusted review response"),
            )
        return self._activate_trusted(current, trusted)

    def _load_current(
        self,
        job: ReviewJob,
        attempt: ReviewAttempt,
        *,
        allow_invalidated_reconciliation: bool,
    ) -> ReviewAttempt:
        current_job = self._store.get_job_by_id(job.id)
        if current_job is None:
            raise KeyError(f"unknown review job: {job.id}")
        if _job_identity(current_job) != _job_identity(job):
            raise ValueError("review job identity changed")

        current = self._store.get_review_attempt(attempt.review_context_id)
        if current is None:
            raise KeyError(f"unknown review attempt: {attempt.review_context_id}")
        if (
            current.review_attempt_id != attempt.review_attempt_id
            or current.review_context_id != attempt.review_context_id
            or current.job_id != attempt.job_id
            or current.job_id != job.id
            or current.content_id != attempt.content_id
            or current.review_decision != attempt.review_decision
        ):
            raise ValueError("review attempt identity does not match review job")
        if current.status is ReviewAttemptStatus.INVALIDATED:
            publish_state = self._store.get_review_attempt_publish_state(
                current.review_context_id
            )
            if not (
                allow_invalidated_reconciliation
                and publish_state == "MAYBE_SENT"
            ):
                raise RuntimeError("review attempt is terminal")
        elif current.status not in {
            ReviewAttemptStatus.PREPARED,
            ReviewAttemptStatus.ACTIVE,
        }:
            raise RuntimeError("review attempt is terminal")
        elif current_job.review_decision != APPROVAL_REVIEW_DECISION:
            raise ValueError("review job decision is not pass")

        context = self._store.get_review_context(current.content_id)
        if context is None:
            raise RuntimeError("review attempt context is missing")
        value = context.value
        if (
            value.repository_id != job.repository_id
            or value.pull_number != job.pull_number
            or value.base_sha != job.base_sha
            or value.head_sha != job.head_sha
        ):
            raise ValueError("review attempt context does not match review job")
        return current

    def _trusted_review(
        self,
        reviews: list[dict[str, Any]],
        *,
        marker: str,
        event: str,
        head_sha: str,
    ) -> dict[str, Any] | None:
        if not isinstance(reviews, list):
            raise TypeError("GitHub reviews response must be a list")
        marker_candidates = [
            review
            for review in reviews
            if isinstance(review, dict)
            and marker in str(review.get("body") or "").splitlines()
        ]
        if len(marker_candidates) > 1:
            raise ReviewPublishUnknown(
                f"{REVIEW_PUBLISH_UNKNOWN}: duplicate review marker"
            )
        trusted = find_review_attempt_review(
            reviews,
            marker,
            event=event,
            actor=self._app_actor,
            head_sha=head_sha,
        )
        if marker_candidates and trusted is None:
            raise ReviewPublishUnknown(
                f"{REVIEW_PUBLISH_UNKNOWN}: review marker identity mismatch"
            )
        return trusted

    def _activate(
        self, attempt: ReviewAttempt, review: dict[str, Any]
    ) -> ReviewAttempt:
        return self._store.activate_review_attempt(
            attempt.review_context_id,
            github_review_id=review["id"],
            submitted_at=review["submitted_at"],
        )

    def _activate_trusted(
        self, attempt: ReviewAttempt, review: dict[str, Any]
    ) -> ReviewAttempt:
        try:
            return self._activate(attempt, review)
        except RuntimeError:
            current = self._store.get_review_attempt(
                attempt.review_context_id
            )
            if (
                current is None
                or current.status is not ReviewAttemptStatus.INVALIDATED
                or self._store.get_review_attempt_publish_state(
                    attempt.review_context_id
                )
                != "MAYBE_SENT"
            ):
                raise
            return self._store.confirm_invalidated_review_attempt_publication(
                attempt.review_context_id,
                github_review_id=review["id"],
                submitted_at=review["submitted_at"],
            )

    def _confirm_trusted_existing(
        self, attempt: ReviewAttempt, review: dict[str, Any]
    ) -> ReviewAttempt:
        publish_state = self._store.get_review_attempt_publish_state(
            attempt.review_context_id
        )
        if publish_state == "NOT_SENT":
            try:
                self._store.mark_review_attempt_publish_maybe_sent(
                    attempt.review_context_id
                )
            except RuntimeError:
                publish_state = self._store.get_review_attempt_publish_state(
                    attempt.review_context_id
                )
                if publish_state not in {"MAYBE_SENT", "CONFIRMED"}:
                    raise ReviewPublishUnknown()
        return self._activate_trusted(attempt, review)

    def _reconcile_after_cas_loss(
        self,
        job: ReviewJob,
        attempt: ReviewAttempt,
        *,
        marker: str,
        event: str,
        cause: Exception,
    ) -> ReviewAttempt:
        try:
            reviews = self._github.list_pull_request_reviews(
                job.repository, job.pull_number
            )
            trusted = self._trusted_review(
                reviews,
                marker=marker,
                event=event,
                head_sha=job.head_sha,
            )
        except ReviewPublishUnknown:
            raise
        except Exception:
            raise ReviewPublishUnknown() from cause
        if trusted is not None:
            return self._activate_trusted(attempt, trusted)
        raise ReviewPublishUnknown() from cause

    def _reconcile_after_post(
        self,
        job: ReviewJob,
        attempt: ReviewAttempt,
        *,
        marker: str,
        event: str,
        cause: Exception,
    ) -> ReviewAttempt:
        try:
            reviews = self._github.list_pull_request_reviews(
                job.repository, job.pull_number
            )
            trusted = self._trusted_review(
                reviews,
                marker=marker,
                event=event,
                head_sha=job.head_sha,
            )
        except ReviewPublishUnknown:
            raise
        except Exception:
            raise ReviewPublishUnknown() from cause
        if trusted is not None:
            return self._activate_trusted(attempt, trusted)
        raise ReviewPublishUnknown() from cause


def _pass_review_event(event: str) -> str:
    if not isinstance(event, str):
        raise ValueError("event must be APPROVE or COMMENT")
    normalized = event.upper()
    if normalized not in {"APPROVE", "COMMENT"}:
        raise ValueError("event must be APPROVE or COMMENT")
    return normalized


def _validate_identity(
    job: ReviewJob, attempt: ReviewAttempt, body: str
) -> str:
    if not isinstance(body, str) or not body:
        raise ValueError("review body is required")
    lines = body.splitlines()
    if not lines:
        raise ValueError("review body is required")
    marker = review_attempt_marker(
        job.repository,
        job.pull_number,
        job.head_sha,
        attempt.review_attempt_id,
    )
    if lines[0] != marker or lines.count(marker) != 1:
        raise ValueError("review body must contain one leading attempt marker")
    parsed = parse_review_attempt_marker(lines[0])
    if (
        parsed is None
        or parsed.repository != job.repository
        or parsed.pull_number != job.pull_number
        or parsed.head_sha != job.head_sha
        or parsed.review_attempt_id != attempt.review_attempt_id
    ):
        raise ValueError("review body marker identity mismatch")
    return marker


def _job_identity(job: ReviewJob) -> tuple[object, ...]:
    return (
        job.id,
        job.repository_id,
        job.repository,
        job.pull_number,
        job.base_sha,
        job.head_sha,
    )
