from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response

from reviewer.config import Settings
from reviewer.decision import (
    ci_satisfies_policy,
    decision_summary,
    find_existing_review,
    format_review,
    has_blocking_human_review,
)
from reviewer.discord_reporter import DiscordReporter
from reviewer.github_auth import GitHubAppAuth
from reviewer.github_client import GitHubClient
from reviewer.models import ReviewJob, ReviewState, WebhookEvent
from reviewer.policy import Eligibility, RepositoryPolicy, load_policies
from reviewer.review_schema import ReviewDecision, ReviewResult
from reviewer.spool import read_json, write_bytes_atomic, write_json_atomic
from reviewer.state import StateStore
from reviewer.webhook import (
    InvalidPayload,
    InvalidSignature,
    PayloadTooLarge,
    parse_webhook,
    read_limited_body,
)


LOGGER = logging.getLogger("hermes-reviewer")
MAX_WEBHOOK_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
WEBHOOK_CONCURRENCY = 8
WEBHOOK_ACQUIRE_TIMEOUT_SECONDS = 0.25
WEBHOOK_SLOTS = asyncio.Semaphore(WEBHOOK_CONCURRENCY)
CHANGES_REQUESTED_LABEL = "hermes:changes-requested"


class ReviewerRuntime:
    def __init__(
        self,
        settings: Settings,
        *,
        github: GitHubClient | None = None,
        reporter: DiscordReporter | None = None,
    ) -> None:
        self.settings = settings
        settings.state_db_path.parent.mkdir(parents=True, exist_ok=True)
        settings.spool_path.mkdir(parents=True, exist_ok=True)
        self.store = StateStore(settings.state_db_path)
        self.policies = load_policies(settings.policy_path)
        missing = set(settings.repositories).difference(self.policies)
        if missing:
            raise ValueError(f"repositories missing from policy: {sorted(missing)}")
        if github is None:
            auth = GitHubAppAuth(
                settings.app_id,
                settings.private_key_path,
                settings.repositories,
            )
            github = GitHubClient(auth)
        self.github = github
        self.reporter = reporter or DiscordReporter(settings.discord_webhook_url)
        self._stop = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        self._reconciler: asyncio.Task[None] | None = None
        self._bootstrapper: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self.store.recover_after_restart()
        self._worker = asyncio.create_task(self._worker_loop(), name="review-worker")
        self._reconciler = asyncio.create_task(self._reconcile_loop(), name="review-reconciler")
        self._bootstrapper = asyncio.create_task(self._bootstrap_open_pulls(), name="review-bootstrap")

    async def stop(self) -> None:
        self._stop.set()
        tasks = [task for task in (self._worker, self._reconciler, self._bootstrapper) if task is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.store.close()

    async def _bootstrap_open_pulls(self) -> None:
        for repository in self.settings.repositories:
            if self._stop.is_set():
                return
            try:
                pulls = await asyncio.to_thread(
                    self.github.list_open_pull_requests, repository
                )
                for pull in pulls:
                    number = pull.get("number")
                    head_sha = str(((pull.get("head") or {}).get("sha") or "")).lower()
                    base_sha = str(((pull.get("base") or {}).get("sha") or "")).lower()
                    if not isinstance(number, int) or len(head_sha) != 40 or len(base_sha) != 40:
                        continue
                    event = WebhookEvent(
                        delivery_id=f"bootstrap:{repository}:{number}:{head_sha}",
                        event_name="pull_request",
                        action="opened",
                        repository_id=None,
                        repository=repository,
                        installation_id=None,
                        pull_number=number,
                        base_sha=base_sha,
                        head_sha=head_sha,
                        is_draft=bool(pull.get("draft")),
                        is_merged=False,
                        merge_sha=None,
                    )
                    await asyncio.to_thread(self.store.ingest, event)
            except Exception:
                LOGGER.exception("open pull bootstrap failed for %s", repository)

    async def _worker_loop(self) -> None:
        while not self._stop.is_set():
            if not self.settings.enabled:
                await asyncio.sleep(5)
                continue
            job = await asyncio.to_thread(self.store.claim_next)
            if job is None:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=2)
                except TimeoutError:
                    pass
                continue
            try:
                await self.process_job(job)
            except Exception as exc:
                LOGGER.exception("review job %s failed", job.id)
                try:
                    if job.attempt_count < 3:
                        retry_at = (
                            datetime.now(timezone.utc) + timedelta(minutes=2 ** job.attempt_count)
                        ).isoformat(timespec="seconds")
                        await asyncio.to_thread(
                            self.store.transition, job.id, ReviewState.QUEUED,
                            expected=ReviewState.REVIEWING,
                            last_error=f"{type(exc).__name__}: {exc}"[:2_000],
                            retry_at=retry_at,
                        )
                    else:
                        await asyncio.to_thread(
                            self.store.transition, job.id, ReviewState.FAILED,
                            expected=ReviewState.REVIEWING,
                            last_error=f"{type(exc).__name__}: {exc}"[:2_000],
                        )
                except Exception:
                    LOGGER.exception("could not persist failure for job %s", job.id)
                event = "검토 재시도 예약" if job.attempt_count < 3 else "검토 실패"
                await self._report(job, event, "자동 검토 중 오류가 발생했습니다. 수동 확인이 필요할 수 있습니다.", pull={})

    async def _reconcile_loop(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(60)
            jobs = await asyncio.to_thread(
                self.store.list_jobs,
                {ReviewState.WAITING_CI, ReviewState.MERGING},
            )
            for job in jobs:
                try:
                    await self._reconcile_job(job)
                except Exception:
                    LOGGER.exception("reconciliation failed for job %s", job.id)

    async def _reconcile_job(self, job: ReviewJob) -> None:
        pull = await asyncio.to_thread(self.github.get_pull_request, job.repository, job.pull_number)
        live_sha = str(((pull.get("head") or {}).get("sha") or "")).lower()
        if live_sha != job.head_sha.lower():
            self.store.transition(job.id, ReviewState.OBSOLETE, expected=job.state)
            return
        if pull.get("state") != "open":
            target = ReviewState.MERGED if pull.get("merged") else ReviewState.CLOSED
            self.store.transition(job.id, target, expected=job.state, merge_sha=str(pull.get("merge_commit_sha") or "") or None)
            return
        if pull.get("draft"):
            self.store.transition(job.id, ReviewState.WAITING_READY, expected=job.state)
            return
        if job.state is ReviewState.MERGING:
            self.store.transition(job.id, ReviewState.HUMAN_REVIEW, expected=ReviewState.MERGING, last_error="merge outcome was ambiguous after restart")
            return
        if await self._ci_green(job, self.policies[job.repository]):
            self.store.transition(job.id, ReviewState.WAITING_READY, expected=ReviewState.WAITING_CI)
            self.store.transition(job.id, ReviewState.QUEUED, expected=ReviewState.WAITING_READY)

    async def process_job(self, job: ReviewJob) -> None:
        pull, files = await asyncio.gather(
            asyncio.to_thread(self.github.get_pull_request, job.repository, job.pull_number),
            asyncio.to_thread(self.github.list_pull_request_files, job.repository, job.pull_number),
        )
        live_sha = str(((pull.get("head") or {}).get("sha") or "")).lower()
        if live_sha != job.head_sha.lower():
            self.store.transition(job.id, ReviewState.OBSOLETE, expected=ReviewState.REVIEWING)
            return
        if pull.get("state") != "open":
            target = ReviewState.MERGED if pull.get("merged") else ReviewState.CLOSED
            self.store.transition(job.id, target, expected=ReviewState.REVIEWING)
            return

        policy = self.policies[job.repository]
        eligibility = policy.evaluate(pull, files)
        if not eligibility.eligible:
            await self._finish_ineligible(job, pull, eligibility)
            return

        await self._report(job, "검토 시작", "도화봇이 pull request 검토를 시작했습니다.", pull=pull)
        diff = await asyncio.to_thread(
            self.github.get_pull_request_diff, job.repository, job.pull_number
        )
        analyzer_payload = {
            "repository": job.repository,
            "pull_number": job.pull_number,
            "head_sha": job.head_sha.lower(),
            "title": pull.get("title"),
            "body": pull.get("body"),
            "files": files,
            "diff": diff,
        }
        analyzer_response = await self._dispatch(
            "analyzer", job, analyzer_payload, timeout_seconds=policy.timeout_minutes * 60
        )
        if not analyzer_response.get("ok"):
            raise RuntimeError("analyzer failed: " + str(analyzer_response.get("error") or "unknown error")[:1_000])
        result_value = analyzer_response.get("result")
        result = ReviewResult.from_dict(result_value)
        if result.reviewed_head_sha != job.head_sha.lower():
            raise RuntimeError("analyzer result SHA does not match queued head")

        tests = await self._run_tests(job, policy)
        test_failed = not tests.get("all_passed", False)
        current, current_files, current_diff = await asyncio.gather(
            asyncio.to_thread(self.github.get_pull_request, job.repository, job.pull_number),
            asyncio.to_thread(self.github.list_pull_request_files, job.repository, job.pull_number),
            asyncio.to_thread(self.github.get_pull_request_diff, job.repository, job.pull_number),
        )
        current_sha = str(((current.get("head") or {}).get("sha") or "")).lower()
        if current_sha != job.head_sha.lower():
            self.store.transition(job.id, ReviewState.OBSOLETE, expected=ReviewState.REVIEWING)
            return
        current_eligibility = policy.evaluate(current, current_files)
        if not current_eligibility.eligible:
            await self._finish_ineligible(job, current, current_eligibility)
            return
        if hashlib.sha256(current_diff.encode("utf-8")).digest() != hashlib.sha256(diff.encode("utf-8")).digest():
            self.store.transition(
                job.id,
                ReviewState.HUMAN_REVIEW,
                expected=ReviewState.REVIEWING,
                review_decision="human_review",
                last_error="pull request diff changed during review",
            )
            await self._report(job, "사람 검토 대기", "검토 중 diff가 변경되어 자동 작업을 중단했습니다.", pull=current)
            return

        final_decision = result.decision
        if test_failed and final_decision is ReviewDecision.PASS:
            final_decision = ReviewDecision.CHANGES_REQUIRED
        body = format_review(result, tests, decision=final_decision, mode=self.settings.mode)
        findings_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        if self.settings.mode == "observe":
            self.store.transition(
                job.id,
                ReviewState.HUMAN_REVIEW,
                expected=ReviewState.REVIEWING,
                review_decision=final_decision.value,
                findings_hash=findings_hash,
                last_error="observe mode: GitHub writes are disabled",
            )
            await self._report(job, "관찰 모드 검토 완료", decision_summary(final_decision, result.summary), pull=current)
            return

        if final_decision is ReviewDecision.CHANGES_REQUIRED:
            review_event = "COMMENT" if self.settings.mode == "comment" else "REQUEST_CHANGES"
            review = await self._create_review_once(
                job,
                body=body,
                event=review_event,
            )
            if self.settings.mode in {"draft", "auto"}:
                pre_label = await asyncio.to_thread(
                    self.github.get_pull_request,
                    job.repository,
                    job.pull_number,
                )
                if not self._draft_candidate_matches_job(pre_label, job):
                    self.store.transition(
                        job.id,
                        ReviewState.OBSOLETE,
                        expected=ReviewState.REVIEWING,
                    )
                    return
                if pre_label.get("state") != "open":
                    target = (
                        ReviewState.MERGED
                        if pre_label.get("merged")
                        else ReviewState.CLOSED
                    )
                    self.store.transition(
                        job.id,
                        target,
                        expected=ReviewState.REVIEWING,
                    )
                    return
                labels = await asyncio.to_thread(
                    self.github.add_labels,
                    job.repository,
                    job.pull_number,
                    [CHANGES_REQUESTED_LABEL],
                )
                if not any(
                    isinstance(item, dict)
                    and item.get("name") == CHANGES_REQUESTED_LABEL
                    for item in labels
                ):
                    raise RuntimeError(
                        "GitHub did not confirm changes-requested label"
                    )
                pre_convert = await asyncio.to_thread(
                    self.github.get_pull_request,
                    job.repository,
                    job.pull_number,
                )
                if not self._draft_candidate_matches_job(pre_convert, job):
                    self.store.transition(
                        job.id,
                        ReviewState.OBSOLETE,
                        expected=ReviewState.REVIEWING,
                    )
                    return
                if pre_convert.get("state") != "open":
                    target = (
                        ReviewState.MERGED
                        if pre_convert.get("merged")
                        else ReviewState.CLOSED
                    )
                    self.store.transition(
                        job.id,
                        target,
                        expected=ReviewState.REVIEWING,
                    )
                    return
                if pre_convert.get("draft") is True:
                    self._transition_after_draft_confirmation(
                        job,
                        review_decision=final_decision.value,
                        findings_hash=findings_hash,
                        github_review_id=_optional_id(review),
                    )
                    await self._report(
                        job, "수정 필요", result.summary, pull=pre_convert
                    )
                    return
                converted = await asyncio.to_thread(
                    self.github.convert_pull_request_to_draft,
                    job.repository,
                    job.pull_number,
                    pull_request_node_id=pre_convert.get("node_id"),
                )
                if converted.get("isDraft") is not True:
                    raise RuntimeError(
                        "GitHub did not confirm pull request draft conversion"
                    )
                confirmed_draft = await asyncio.to_thread(
                    self.github.get_pull_request,
                    job.repository,
                    job.pull_number,
                )
                if not self._draft_candidate_matches_job(confirmed_draft, job):
                    self.store.transition(
                        job.id,
                        ReviewState.OBSOLETE,
                        expected=ReviewState.REVIEWING,
                    )
                    return
                if confirmed_draft.get("state") != "open":
                    target = (
                        ReviewState.MERGED
                        if confirmed_draft.get("merged")
                        else ReviewState.CLOSED
                    )
                    self.store.transition(
                        job.id,
                        target,
                        expected=ReviewState.REVIEWING,
                    )
                    return
                if confirmed_draft.get("draft") is not True:
                    raise RuntimeError(
                        "GitHub did not persist pull request draft conversion"
                    )
                self._transition_after_draft_confirmation(
                    job,
                    review_decision=final_decision.value,
                    findings_hash=findings_hash,
                    github_review_id=_optional_id(review),
                )
                await self._report(
                    job, "수정 필요", result.summary, pull=confirmed_draft
                )
                return
            else:
                self.store.transition(
                    job.id,
                    ReviewState.CHANGES_REQUIRED,
                    expected=ReviewState.REVIEWING,
                    review_decision=final_decision.value,
                    findings_hash=findings_hash,
                    github_review_id=_optional_id(review),
                )
            await self._report(job, "수정 필요", result.summary, pull=current)
            return

        if final_decision is ReviewDecision.HUMAN_REVIEW or self.settings.mode in {"comment", "draft"}:
            review = await self._create_review_once(
                job,
                body=body,
                event="COMMENT",
            )
            self.store.transition(
                job.id,
                ReviewState.HUMAN_REVIEW,
                expected=ReviewState.REVIEWING,
                review_decision=final_decision.value,
                findings_hash=findings_hash,
                github_review_id=_optional_id(review),
            )
            await self._report(job, "사람 검토 대기", result.summary, pull=current)
            return

        review = await self._create_review_once(
            job,
            body=body,
            event="COMMENT",
        )
        reason = "ATOMIC_SERVER_GATES_UNAVAILABLE"
        self.store.transition(
            job.id,
            ReviewState.HUMAN_REVIEW,
            expected=ReviewState.REVIEWING,
            review_decision=final_decision.value,
            findings_hash=findings_hash,
            github_review_id=_optional_id(review),
            last_error=reason,
        )
        await self._report(
            job,
            "병합 중단",
            "원자적 병합 backend가 아직 검증·활성화되지 않아 자동 병합을 차단했습니다.",
            pull=current,
        )

    def _transition_after_draft_confirmation(
        self,
        job: ReviewJob,
        *,
        review_decision: str,
        findings_hash: str,
        github_review_id: int | None,
    ) -> None:
        try:
            self.store.transition(
                job.id,
                ReviewState.WAITING_READY,
                expected=ReviewState.REVIEWING,
                review_decision=review_decision,
                findings_hash=findings_hash,
                github_review_id=github_review_id,
            )
        except RuntimeError as exc:
            persisted = self.store.get_job_by_id(job.id)
            expected_error = (
                f"job {job.id} is {ReviewState.WAITING_READY}, "
                f"expected {ReviewState.REVIEWING}"
            )
            if (
                str(exc) != expected_error
                or persisted is None
                or persisted.state is not ReviewState.WAITING_READY
            ):
                raise
            self.store.transition(
                job.id,
                ReviewState.WAITING_READY,
                expected=ReviewState.WAITING_READY,
                review_decision=review_decision,
                findings_hash=findings_hash,
                github_review_id=github_review_id,
            )

    @staticmethod
    def _draft_candidate_matches_job(
        pull: dict[str, Any], job: ReviewJob
    ) -> bool:
        head_sha = str(((pull.get("head") or {}).get("sha") or "")).lower()
        base_sha = str(((pull.get("base") or {}).get("sha") or "")).lower()
        return (
            head_sha == job.head_sha.lower()
            and base_sha == job.base_sha.lower()
        )

    async def _finish_ineligible(self, job: ReviewJob, pull: dict[str, Any], eligibility: Eligibility) -> None:
        target = ReviewState.WAITING_READY if eligibility.state == "WAITING_READY" else ReviewState.HUMAN_REVIEW
        self.store.transition(job.id, target, expected=ReviewState.REVIEWING, review_decision="human_review", last_error=eligibility.reason)
        await self._report(job, "자동 검토 제외", eligibility.reason, pull=pull)

    async def _dispatch(
        self,
        worker: str,
        job: ReviewJob,
        payload: dict[str, Any],
        *,
        timeout_seconds: int,
        attachments: dict[str, bytes] | None = None,
    ) -> dict[str, Any]:
        name = f"{job.id}-{job.head_sha.lower()}.json"
        incoming = self.settings.spool_path / worker / "in" / name
        outgoing = self.settings.spool_path / worker / "out" / name
        attachment_paths: list[Path] = []
        outgoing.unlink(missing_ok=True)
        try:
            for attachment_name, attachment in (attachments or {}).items():
                if (
                    not attachment_name
                    or attachment_name in {".", ".."}
                    or Path(attachment_name).name != attachment_name
                ):
                    raise ValueError("attachment name must be a plain filename")
                attachment_path = incoming.parent / attachment_name
                write_bytes_atomic(attachment_path, attachment)
                attachment_paths.append(attachment_path)
            write_json_atomic(incoming, payload)
            deadline = asyncio.get_running_loop().time() + timeout_seconds
            while asyncio.get_running_loop().time() < deadline:
                if outgoing.exists():
                    response = read_json(outgoing)
                    outgoing.unlink(missing_ok=True)
                    return response
                await asyncio.sleep(1)
            raise TimeoutError(f"{worker} timed out")
        finally:
            incoming.unlink(missing_ok=True)
            for attachment_path in attachment_paths:
                attachment_path.unlink(missing_ok=True)

    async def _create_review_once(self, job: ReviewJob, *, body: str, event: str) -> dict[str, Any]:
        marker = body.splitlines()[0]
        reviews = await asyncio.to_thread(
            self.github.list_pull_request_reviews, job.repository, job.pull_number
        )
        existing = find_existing_review(
            reviews,
            marker,
            event=event,
            actor=f"{self.settings.app_slug}[bot]",
        )
        if existing is not None:
            return existing
        return await asyncio.to_thread(
            self.github.create_review,
            job.repository,
            job.pull_number,
            body=body,
            event=event,
            commit_id=job.head_sha,
        )

    async def _final_merge_gate(
        self,
        job: ReviewJob,
        policy: RepositoryPolicy,
        *,
        expected_diff: str,
        expected_base_sha: str,
    ) -> tuple[bool, dict[str, Any], str]:
        pull, files, diff, reviews, checks, status, unresolved = await asyncio.gather(
            asyncio.to_thread(self.github.get_pull_request, job.repository, job.pull_number),
            asyncio.to_thread(self.github.list_pull_request_files, job.repository, job.pull_number),
            asyncio.to_thread(self.github.get_pull_request_diff, job.repository, job.pull_number),
            asyncio.to_thread(self.github.list_pull_request_reviews, job.repository, job.pull_number),
            asyncio.to_thread(self.github.list_check_runs, job.repository, job.head_sha),
            asyncio.to_thread(self.github.get_combined_status, job.repository, job.head_sha),
            asyncio.to_thread(self.github.has_unresolved_review_threads, job.repository, job.pull_number),
        )
        current_sha = str(((pull.get("head") or {}).get("sha") or "")).lower()
        current_base_sha = str(((pull.get("base") or {}).get("sha") or "")).lower()
        if current_sha != job.head_sha.lower():
            return False, pull, "head SHA changed before merge"
        if not expected_base_sha or current_base_sha != expected_base_sha:
            return False, pull, "base SHA changed before merge"
        eligibility = policy.evaluate(pull, files)
        if not eligibility.eligible:
            return False, pull, eligibility.reason
        if pull.get("mergeable") is not True:
            return False, pull, "pull request is not currently mergeable"
        if hashlib.sha256(diff.encode("utf-8")).digest() != hashlib.sha256(expected_diff.encode("utf-8")).digest():
            return False, pull, "pull request diff or base changed before merge"
        if not ci_satisfies_policy(policy.required_checks, checks, status):
            return False, pull, "required or pending CI gate is not successful"
        if unresolved:
            return False, pull, "unresolved review conversation exists"
        if has_blocking_human_review(
            reviews, app_actor=f"{self.settings.app_slug}[bot]"
        ):
            return False, pull, "another reviewer requested changes"
        return True, pull, "all merge gates passed"

    async def _run_tests(self, job: ReviewJob, policy: RepositoryPolicy) -> dict[str, Any]:
        if not policy.test_commands:
            return {"tests": [], "all_passed": True}
        archive = await asyncio.to_thread(self.github.download_tarball, job.repository, job.head_sha)
        if len(archive) > MAX_ARCHIVE_BYTES:
            raise RuntimeError("repository archive exceeds size limit")
        archive_name = f"{job.id}-{job.head_sha.lower()}.tar.gz"
        response = await self._dispatch(
            "executor",
            job,
            {
                "repository": job.repository,
                "archive": {
                    "name": archive_name,
                    "size": len(archive),
                    "sha256": hashlib.sha256(archive).hexdigest(),
                },
                "commands": [list(command) for command in policy.test_commands],
                "timeout_seconds": policy.timeout_minutes * 60,
            },
            timeout_seconds=policy.timeout_minutes * 60 + 30,
            attachments={archive_name: archive},
        )
        if not response.get("ok") or not isinstance(response.get("result"), dict):
            raise RuntimeError("executor infrastructure failed")
        return response["result"]

    async def _ci_green(self, job: ReviewJob, policy: RepositoryPolicy) -> bool:
        checks, status = await asyncio.gather(
            asyncio.to_thread(self.github.list_check_runs, job.repository, job.head_sha),
            asyncio.to_thread(self.github.get_combined_status, job.repository, job.head_sha),
        )
        return ci_satisfies_policy(policy.required_checks, checks, status)

    async def _report(self, job: ReviewJob, event: str, summary: str, *, pull: dict[str, Any]) -> bool:
        try:
            await asyncio.to_thread(
                self.reporter.send,
                event=event,
                repository=job.repository,
                pull_number=job.pull_number,
                pull_url=str(pull.get("html_url") or f"https://github.com/{job.repository}/pull/{job.pull_number}"),
                title=str(pull.get("title") or "Pull request"),
                head_sha=job.head_sha,
                summary=summary,
            )
            return True
        except Exception:
            LOGGER.warning("Discord report failed for job %s", job.id)
            return False


def _optional_id(payload: dict[str, Any]) -> int | None:
    value = payload.get("id")
    return value if isinstance(value, int) else None


@asynccontextmanager
async def lifespan(application: FastAPI):
    runtime = ReviewerRuntime(Settings.from_env())
    application.state.runtime = runtime
    await runtime.start()
    try:
        yield
    finally:
        await runtime.stop()


app = FastAPI(title="Hermes GitHub Reviewer", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "hermes-github-reviewer", "status": "ok"}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/github/webhook", status_code=202)
async def github_webhook(request: Request) -> Response:
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")
    try:
        await asyncio.wait_for(
            WEBHOOK_SLOTS.acquire(), timeout=WEBHOOK_ACQUIRE_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=429, detail="webhook concurrency limit reached") from exc
    try:
        try:
            raw = await read_limited_body(
                request.stream(), maximum_bytes=MAX_WEBHOOK_BYTES
            )
        except PayloadTooLarge as exc:
            raise HTTPException(status_code=413, detail="payload too large") from exc
        runtime: ReviewerRuntime = request.app.state.runtime
        try:
            event = parse_webhook(request.headers, raw, runtime.settings.webhook_secret())
        except InvalidSignature as exc:
            raise HTTPException(status_code=401, detail="invalid signature") from exc
        except InvalidPayload as exc:
            raise HTTPException(status_code=400, detail="invalid payload") from exc
        if event.repository and event.repository not in runtime.settings.repositories:
            return Response(status_code=202)
        await asyncio.to_thread(runtime.store.ingest, event)
        return Response(status_code=202)
    finally:
        WEBHOOK_SLOTS.release()
