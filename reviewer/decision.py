from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any

from reviewer.approval import require_uuid7
from reviewer.review_schema import ReviewDecision, ReviewResult


_REVIEW_ATTEMPT_MARKER = re.compile(
    r"^<!-- dohwa-bot-review "
    r"repo=(?P<repository>[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}) "
    r"pr=(?P<pull_number>[1-9][0-9]*) "
    r"head=(?P<head_sha>[0-9a-f]{40}) "
    r"attempt=(?P<review_attempt_id>[0-9a-f-]{36}) "
    r"schema=2 -->$"
)
_REVIEW_ATTEMPT_MARKER_PREFIX = "<!-- dohwa-bot-review repo="


@dataclass(frozen=True, slots=True)
class ReviewAttemptMarker:
    repository: str
    pull_number: int
    head_sha: str
    review_attempt_id: str


def review_marker(head_sha: str, decision: ReviewDecision) -> str:
    return f"<!-- dohwa-bot-review:{head_sha}:{decision.value} -->"


def review_attempt_marker(
    repository: str,
    pull_number: int,
    head_sha: str,
    review_attempt_id: str,
) -> str:
    marker = (
        f"<!-- dohwa-bot-review repo={repository} pr={pull_number} "
        f"head={head_sha} attempt={review_attempt_id} schema=2 -->"
    )
    parsed = parse_review_attempt_marker(marker)
    if parsed is None:
        raise ValueError("review attempt marker fields are not canonical")
    return marker


def parse_review_attempt_marker(value: str) -> ReviewAttemptMarker | None:
    if not isinstance(value, str):
        return None
    match = _REVIEW_ATTEMPT_MARKER.fullmatch(value)
    if match is None:
        return None
    pull_number = int(match.group("pull_number"))
    if pull_number > 2**63 - 1:
        return None
    review_attempt_id = match.group("review_attempt_id")
    try:
        require_uuid7(review_attempt_id, "review_attempt_id")
    except ValueError:
        return None
    return ReviewAttemptMarker(
        repository=match.group("repository"),
        pull_number=pull_number,
        head_sha=match.group("head_sha"),
        review_attempt_id=review_attempt_id,
    )


def find_review_attempt_review(
    reviews: list[dict[str, Any]],
    marker: str,
    *,
    event: str,
    actor: str,
    head_sha: str,
) -> dict[str, Any] | None:
    if parse_review_attempt_marker(marker) is None:
        raise ValueError("marker must be a canonical schema=2 review marker")
    expected_state = {
        "APPROVE": "APPROVED",
        "COMMENT": "COMMENTED",
    }.get(event.upper())
    if expected_state is None:
        raise ValueError("pass review event must be APPROVE or COMMENT")
    matches: list[dict[str, Any]] = []
    for review in reviews:
        body = review.get("body")
        if not isinstance(body, str):
            continue
        marker_lines = [
            line
            for line in body.splitlines()
            if line.startswith(_REVIEW_ATTEMPT_MARKER_PREFIX)
        ]
        if marker_lines != [marker]:
            continue
        user = review.get("user")
        review_id = review.get("id")
        submitted_at = review.get("submitted_at")
        if (
            not isinstance(user, dict)
            or str(user.get("login") or "").casefold() != actor.casefold()
            or str(user.get("type") or "") != "Bot"
            or isinstance(review_id, bool)
            or not isinstance(review_id, int)
            or review_id <= 0
            or str(review.get("state") or "").upper() != expected_state
            or review.get("commit_id") != head_sha
            or not _is_github_timestamp(submitted_at)
        ):
            continue
        matches.append(review)
    if len(matches) > 1:
        raise RuntimeError("multiple GitHub reviews match one review attempt")
    return matches[0] if matches else None


def find_existing_review(
    reviews: list[dict[str, Any]], marker: str, *, event: str, actor: str
) -> dict[str, Any] | None:
    expected_state = {
        "APPROVE": "APPROVED",
        "REQUEST_CHANGES": "CHANGES_REQUESTED",
        "COMMENT": "COMMENTED",
    }[event.upper()]
    for review in reviews:
        if (
            marker in str(review.get("body") or "")
            and str(review.get("state") or "").upper() == expected_state
            and str((review.get("user") or {}).get("login") or "").casefold() == actor.casefold()
        ):
            return review
    return None


def ci_satisfies_policy(
    required_checks: tuple[str, ...],
    checks: list[dict[str, Any]],
    status: dict[str, Any],
) -> bool:
    if not required_checks:
        return False
    by_name = {str(check.get("name") or ""): check for check in checks}
    for check in checks:
        if check.get("status") != "completed":
            return False
        if check.get("conclusion") not in {"success", "neutral", "skipped"}:
            return False
    for required in required_checks:
        check = by_name.get(required)
        if not check or check.get("status") != "completed" or check.get("conclusion") != "success":
            return False
    statuses = status.get("statuses") if isinstance(status, dict) else None
    if not isinstance(statuses, list):
        return False
    if statuses and (
        status.get("state") != "success"
        or any(item.get("state") != "success" for item in statuses if isinstance(item, dict))
    ):
        return False
    return True


def has_blocking_human_review(
    reviews: list[dict[str, Any]], *, app_actor: str
) -> bool:
    latest: dict[str, tuple[int, str]] = {}
    for index, review in enumerate(reviews):
        login = str((review.get("user") or {}).get("login") or "")
        if not login or login.casefold() == app_actor.casefold():
            continue
        review_id = review.get("id")
        order = review_id if isinstance(review_id, int) else index
        state = str(review.get("state") or "").upper()
        current = latest.get(login.casefold())
        if current is None or order >= current[0]:
            latest[login.casefold()] = (order, state)
    return any(state == "CHANGES_REQUESTED" for _, state in latest.values())


def format_review(
    result: ReviewResult,
    tests: dict[str, Any],
    *,
    decision: ReviewDecision,
    mode: str,
) -> str:
    lines = [
        review_marker(result.reviewed_head_sha, decision),
        f"## 도화봇 검토 결과: `{decision.value}`",
        "",
        _safe(result.summary),
        "",
    ]
    if result.findings:
        lines.extend(["### 발견 사항", ""])
        for finding in result.findings:
            location = f"{finding.path}:{finding.line}" if finding.line else finding.path
            lines.append(f"- **{finding.severity.value}** `{_safe(location)}` — {_safe(finding.title)}")
            lines.append(f"  - 근거: {_safe(finding.evidence)}")
            lines.append(f"  - 권장: {_safe(finding.recommendation)}")
    test_items = tests.get("tests") if isinstance(tests, dict) else []
    if test_items:
        lines.extend(["", "### 검증", ""])
        for item in test_items:
            lines.append(f"- `{_safe(item.get('command'))}` — {_safe(item.get('result'))}")
    lines.extend(["", f"검토 SHA: `{result.reviewed_head_sha}` · 신뢰도: `{result.confidence}` · 모드: `{mode}`"])
    return "\n".join(lines)[:60_000]


def decision_summary(decision: ReviewDecision, summary: str) -> str:
    return f"예상 결정: {decision.value}\n{summary}"[:4_000]


def _safe(value: Any) -> str:
    return str(value or "").replace("@", "@\u200b").strip()


def _is_github_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 20:
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value
