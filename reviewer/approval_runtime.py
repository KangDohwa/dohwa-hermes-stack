from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any

from reviewer.approval import ReviewAttempt, ReviewContextContent
from reviewer.approval_adapter import (
    ApprovalTransactionResult,
    process_github_label_approval,
)
from reviewer.decision import review_attempt_marker
from reviewer.discord_reporter import DiscordReporter
from reviewer.github_client import (
    GitHubAPIError,
    GitHubClient,
    LabelTimelineSnapshot,
)
from reviewer.models import ReviewJob, ReviewState, WebhookEvent
from reviewer.policy import RepositoryPolicy
from reviewer.review_publisher import ReviewAttemptPublisher, ReviewPublishUnknown
from reviewer.review_schema import ReviewDecision
from reviewer.state import StateStore


MAX_REVIEW_BODY_CHARS = 60_000
# Keep webhook processing bounded while allowing short GitHub GraphQL visibility lag.
LABEL_TIMELINE_RECONCILIATION_DELAYS_SECONDS = (0.25, 0.75)


@dataclass(frozen=True, slots=True)
class PassReviewPublication:
    job: ReviewJob
    attempt: ReviewAttempt


class ApprovalRuntime:
    def __init__(
        self,
        store: StateStore,
        github: GitHubClient,
        reporter: DiscordReporter,
        *,
        app_actor: str,
        approver_ids: tuple[int, ...],
        approval_label: str,
    ) -> None:
        self._store = store
        self._github = github
        self._reporter = reporter
        self._approver_ids = approver_ids
        self._approval_label = approval_label
        self._publisher = ReviewAttemptPublisher(
            store,
            github,
            app_actor=app_actor,
        )

    @property
    def approval_label(self) -> str:
        return self._approval_label

    def publish_pass_review(
        self,
        job: ReviewJob,
        *,
        pull: dict[str, Any],
        diff: str,
        body: str,
        findings_hash: str,
        policy: RepositoryPolicy,
    ) -> PassReviewPublication:
        job = self._bind_repository_identity(job, pull)
        if self._store.has_unresolved_review_publication(
            repository_id=job.repository_id,
            pull_number=job.pull_number,
        ):
            raise ReviewPublishUnknown(
                "REVIEW_PUBLISH_UNKNOWN: unresolved prior review publication"
            )
        self._remove_stale_approval_label(job, pull)
        if job.base_sha is None:
            raise RuntimeError("review job has no base SHA")
        merge_base_sha = self._github.get_merge_base_sha(
            job.repository,
            base_sha=job.base_sha,
            head_sha=job.head_sha,
        )
        current_job = self._store.transition(
            job.id,
            ReviewState.REVIEWING,
            expected=ReviewState.REVIEWING,
            review_decision=ReviewDecision.PASS.value,
            findings_hash=findings_hash,
        )
        if current_job.repository_id is None or current_job.base_sha is None:
            raise RuntimeError("review job has no bound review context identity")
        context = self._store.store_review_context(
            ReviewContextContent(
                repository_id=current_job.repository_id,
                pull_number=current_job.pull_number,
                base_sha=current_job.base_sha,
                head_sha=current_job.head_sha,
                merge_base_sha=merge_base_sha,
                diff_sha256=hashlib.sha256(diff.encode("utf-8")).hexdigest(),
                policy_version=policy.policy_version,
            )
        )
        attempt = self._store.prepare_review_attempt(
            job_id=current_job.id,
            content_id=context.content_id,
            review_decision=ReviewDecision.PASS.value,
        )
        marker = review_attempt_marker(
            current_job.repository,
            current_job.pull_number,
            current_job.head_sha,
            attempt.review_attempt_id,
        )
        review_body = (marker + "\n" + body)[:MAX_REVIEW_BODY_CHARS]
        active = self._publisher.publish(
            current_job,
            attempt,
            body=review_body,
            event="COMMENT",
            decision=ReviewDecision.PASS,
        )
        confirmed = self._github.get_pull_request(
            current_job.repository,
            current_job.pull_number,
        )
        if not self._candidate_matches_job(confirmed, current_job):
            invalidated = self._store.invalidate_review_attempt(
                active.review_context_id,
                reason="POST_REVIEW_CONTEXT_CHANGED",
            )
            target = (
                ReviewState.OBSOLETE
                if confirmed.get("state") == "open"
                else ReviewState.MERGED
                if confirmed.get("merged")
                else ReviewState.CLOSED
            )
            stopped = self._store.transition(
                current_job.id,
                target,
                expected=ReviewState.REVIEWING,
                review_decision=ReviewDecision.PASS.value,
                findings_hash=findings_hash,
                github_review_id=active.github_review_id,
                last_error="POST_REVIEW_CONTEXT_CHANGED",
            )
            return PassReviewPublication(job=stopped, attempt=invalidated)
        waiting = self._store.transition(
            current_job.id,
            ReviewState.READY_TO_MERGE,
            expected=ReviewState.REVIEWING,
            review_decision=ReviewDecision.PASS.value,
            findings_hash=findings_hash,
            github_review_id=active.github_review_id,
            last_error="EXPLICIT_APPROVAL_REQUIRED",
        )
        return PassReviewPublication(job=waiting, attempt=active)

    def process_label_event(
        self,
        event: WebhookEvent,
        *,
        policy: RepositoryPolicy,
    ) -> ApprovalTransactionResult:
        if event.label_name != self._approval_label:
            raise ValueError("label event does not target the approval label")
        if not self._approver_ids:
            raise RuntimeError("approval runtime has no approver allowlist")
        if event.repository is None or event.pull_number is None:
            raise ValueError("label event has no pull request identity")
        snapshot = self._github.list_pull_request_label_timeline(
            event.repository,
            event.pull_number,
        )
        for delay in LABEL_TIMELINE_RECONCILIATION_DELAYS_SECONDS:
            if _matching_timeline_event_count(snapshot, event) != 0:
                break
            time.sleep(delay)
            snapshot = self._github.list_pull_request_label_timeline(
                event.repository,
                event.pull_number,
            )
        installation_id = self._github.installation_id_for_repository(
            event.repository
        )
        return process_github_label_approval(
            self._store,
            snapshot=snapshot,
            webhook=event,
            allowed_approver_ids=self._approver_ids,
            expected_installation_id=installation_id,
            expected_policy_version=policy.policy_version,
            target_label=self._approval_label,
        )

    def deliver_outbox_row(self, row: sqlite3.Row) -> None:
        action = str(row["action"])
        if action == "REMOVE_LABEL":
            label = row["label_name"]
            if not isinstance(label, str) or not label:
                raise RuntimeError("REMOVE_LABEL outbox row has no label")
            payload = _outbox_payload(row)
            self._remove_current_approval_label(
                repository=str(row["repository"]),
                pull_number=int(row["pull_number"]),
                label=label,
                payload=payload,
            )
            return
        if action != "DISCORD_REPORT":
            raise RuntimeError(f"unsupported approval outbox action: {action}")
        payload = _outbox_payload(row)
        repository = str(row["repository"])
        pull_number = int(row["pull_number"])
        pull = self._github.get_pull_request(repository, pull_number)
        head_sha = str(((pull.get("head") or {}).get("sha") or ""))
        self._reporter.send(
            event="병합 승인 처리",
            repository=repository,
            pull_number=pull_number,
            pull_url=str(
                pull.get("html_url")
                or f"https://github.com/{repository}/pull/{pull_number}"
            ),
            title=str(pull.get("title") or "Pull request"),
            head_sha=head_sha,
            summary=_approval_report_summary(payload),
        )

    def _remove_current_approval_label(
        self,
        *,
        repository: str,
        pull_number: int,
        label: str,
        payload: dict[str, Any],
    ) -> None:
        generation = payload.get("generation")
        event_id = payload.get("label_event_id")
        repository_id = payload.get("repository_id")
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation <= 0
            or not isinstance(event_id, str)
            or not event_id
            or isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            approval_id = payload.get("approval_id")
            if not isinstance(approval_id, str) or not approval_id:
                raise RuntimeError("REMOVE_LABEL outbox identity is incomplete")
            approval = self._store.get_approval_record(approval_id)
            if approval is None:
                raise RuntimeError("REMOVE_LABEL approval identity is missing")
            generation = approval["generation"]
            event_id = approval["label_event_id"]
            repository_id = approval["repository_id"]
        snapshot = self._github.list_pull_request_label_timeline(
            repository,
            pull_number,
        )
        if (
            snapshot.repository_database_id != repository_id
            or snapshot.repository != repository
            or snapshot.pull_number != pull_number
        ):
            raise RuntimeError("REMOVE_LABEL timeline identity changed")
        current_generation = 0
        current_event_id: str | None = None
        for item in snapshot.events:
            if item.label_name != label:
                continue
            if item.action.lower() == "labeled":
                current_generation += 1
                current_event_id = item.event_id
            elif item.action.lower() == "unlabeled":
                current_event_id = None
        if (
            current_event_id is None
            or current_generation != generation
            or current_event_id != event_id
        ):
            return
        # GitHub deletes labels by name and offers no generation-conditional
        # operation. This cleanup is advisory; durable authorization is bound
        # to the signed timeline event above and never to current label presence.
        try:
            self._github.remove_label(repository, pull_number, label)
        except GitHubAPIError as exc:
            if exc.status != 404:
                raise
        confirmed = self._github.get_pull_request(repository, pull_number)
        base_repo = ((confirmed.get("base") or {}).get("repo") or {})
        labels = {
            str(item.get("name") or "")
            for item in (confirmed.get("labels") or [])
            if isinstance(item, dict)
        }
        if (
            base_repo.get("id") != repository_id
            or base_repo.get("full_name") != repository
            or label in labels
        ):
            raise RuntimeError("REMOVE_LABEL absence was not confirmed")

    def _bind_repository_identity(
        self,
        job: ReviewJob,
        pull: dict[str, Any],
    ) -> ReviewJob:
        base_repo = ((pull.get("base") or {}).get("repo") or {})
        repository_id = base_repo.get("id")
        full_name = base_repo.get("full_name")
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
            or full_name != job.repository
        ):
            raise RuntimeError("GitHub pull has no trusted base repository identity")
        if job.repository_id is not None:
            if job.repository_id != repository_id:
                raise RuntimeError("GitHub pull repository identity changed")
            return job
        return self._store.bind_job_repository_id(job.id, repository_id)

    def _remove_stale_approval_label(
        self,
        job: ReviewJob,
        pull: dict[str, Any],
    ) -> None:
        labels = {
            str(item.get("name") or "")
            for item in (pull.get("labels") or [])
            if isinstance(item, dict)
        }
        if self._approval_label in labels:
            try:
                self._github.remove_label(
                    job.repository,
                    job.pull_number,
                    self._approval_label,
                )
            except GitHubAPIError as exc:
                if exc.status != 404:
                    raise
        confirmed = self._github.get_pull_request(job.repository, job.pull_number)
        confirmed_labels = {
            str(item.get("name") or "")
            for item in (confirmed.get("labels") or [])
            if isinstance(item, dict)
        }
        if (
            not self._candidate_matches_job(confirmed, job)
            or self._approval_label in confirmed_labels
        ):
            raise RuntimeError("stale approval label cleanup was not confirmed")

    @staticmethod
    def _candidate_matches_job(
        pull: dict[str, Any],
        job: ReviewJob,
    ) -> bool:
        base = pull.get("base") or {}
        base_repo = base.get("repo") or {}
        return (
            pull.get("state") == "open"
            and base_repo.get("id") == job.repository_id
            and base_repo.get("full_name") == job.repository
            and str(base.get("sha") or "") == job.base_sha
            and str(((pull.get("head") or {}).get("sha") or "")) == job.head_sha
        )


def _approval_report_summary(payload: dict[str, Any]) -> str:
    reason = str(payload.get("reason") or "UNKNOWN_APPROVAL_RESULT")
    approval_id = payload.get("approval_id")
    if reason == "ATOMIC_SERVER_GATES_UNAVAILABLE" and isinstance(
        approval_id, str
    ):
        return (
            "승인 label을 exact review context에 결속하고 1회 소비했습니다.\n"
            "결과: 자동 병합 차단\n"
            "사유: 원자적 병합 backend가 아직 검증·활성화되지 않았습니다.\n"
            "필요 조치: 사람이 PR 상태와 검토 결과를 확인한 뒤 직접 병합하세요."
        )
    if (
        reason == "TIMELINE_EVENT_MATCH_NOT_UNIQUE"
        and payload.get("webhook_action") == "unlabeled"
        and payload.get("sender_type") == "Bot"
    ):
        return (
            "도화봇의 승인 label 자동 정리 event가 GitHub timeline에서 "
            "제한 시간 내 확인되지 않았습니다.\n"
            "결과: 추가 승인이나 자동 병합 없음\n"
            "필요 조치: 같은 알림이 반복되면 운영자가 GitHub timeline을 확인하세요."
        )
    return (
        "승인 요청을 적용하지 않았습니다.\n"
        f"사유: {reason[:180]}\n"
        "필요 조치: exact head/base와 승인 label 순서·승인자를 확인하세요."
    )


def _matching_timeline_event_count(
    snapshot: LabelTimelineSnapshot,
    webhook: WebhookEvent,
) -> int:
    return sum(
        1
        for item in snapshot.events
        if snapshot.repository_database_id == webhook.repository_id
        and snapshot.repository == webhook.repository
        and snapshot.pull_number == webhook.pull_number
        and item.action.lower() == webhook.action
        and item.label_node_id == webhook.label_node_id
        and item.label_name == webhook.label_name
        and item.actor_type == webhook.sender_type
        and item.actor_database_id == webhook.sender_id
        and item.actor_node_id == webhook.sender_node_id
        and item.actor_login == webhook.sender_login
        and item.created_at == webhook.pull_updated_at
    )


def _outbox_payload(row: sqlite3.Row) -> dict[str, Any]:
    try:
        payload = json.loads(str(row["payload"]))
    except json.JSONDecodeError as exc:
        raise RuntimeError("approval outbox payload is invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("approval outbox payload is not an object")
    return payload
