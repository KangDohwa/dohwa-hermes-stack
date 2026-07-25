from __future__ import annotations

from typing import Any

from reviewer.review_schema import ReviewDecision, ReviewResult


def review_marker(head_sha: str, decision: ReviewDecision) -> str:
    return f"<!-- dohwa-bot-review:{head_sha}:{decision.value} -->"


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
