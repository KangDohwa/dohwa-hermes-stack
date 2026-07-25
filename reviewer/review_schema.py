from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import re
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ReviewDecision(str, Enum):
    PASS = "pass"
    CHANGES_REQUIRED = "changes_required"
    HUMAN_REVIEW = "human_review"


class Severity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    path: str
    line: int | None
    title: str
    evidence: str
    recommendation: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        if not isinstance(value, dict):
            raise ValueError("finding must be an object")
        path = str(value.get("path") or "").strip()
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise ValueError("finding path must be repository-relative")
        line_raw = value.get("line")
        line = None if line_raw is None else int(line_raw)
        if line is not None and line < 1:
            raise ValueError("finding line must be positive")
        return cls(
            severity=Severity(str(value.get("severity") or "")),
            path=path,
            line=line,
            title=_bounded(value.get("title"), "finding title", 200),
            evidence=_bounded(value.get("evidence"), "finding evidence", 2_000),
            recommendation=_bounded(
                value.get("recommendation"),
                "finding recommendation",
                2_000,
            ),
        )


@dataclass(frozen=True)
class TestResult:
    command: str
    result: str
    detail: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TestResult":
        if not isinstance(value, dict):
            raise ValueError("test result must be an object")
        result = str(value.get("result") or "")
        if result not in {"passed", "failed", "skipped"}:
            raise ValueError("invalid test result")
        return cls(
            command=_bounded(value.get("command"), "test command", 500),
            result=result,
            detail=_bounded(value.get("detail"), "test detail", 2_000, allow_empty=True),
        )


@dataclass(frozen=True)
class ReviewResult:
    decision: ReviewDecision
    reviewed_head_sha: str
    summary: str
    findings: tuple[Finding, ...]
    tests: tuple[TestResult, ...]
    confidence: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ReviewResult":
        if not isinstance(value, dict):
            raise ValueError("review result must be an object")
        sha = str(value.get("reviewed_head_sha") or "").strip().lower()
        if not SHA_RE.fullmatch(sha):
            raise ValueError("reviewed_head_sha must be a 40-character lowercase SHA")
        confidence = str(value.get("confidence") or "").lower()
        if confidence not in {"high", "medium", "low"}:
            raise ValueError("invalid confidence")
        findings_raw = value.get("findings")
        tests_raw = value.get("tests")
        if not isinstance(findings_raw, list) or not isinstance(tests_raw, list):
            raise ValueError("findings and tests must be arrays")
        if len(findings_raw) > 100 or len(tests_raw) > 50:
            raise ValueError("review result exceeds item limits")
        result = cls(
            decision=ReviewDecision(str(value.get("decision") or "")),
            reviewed_head_sha=sha,
            summary=_bounded(value.get("summary"), "summary", 4_000),
            findings=tuple(Finding.from_dict(item) for item in findings_raw),
            tests=tuple(TestResult.from_dict(item) for item in tests_raw),
            confidence=confidence,
        )
        if confidence == "low" and result.decision is not ReviewDecision.HUMAN_REVIEW:
            raise ValueError("low confidence must result in human_review")
        if result.blocking_findings and result.decision is ReviewDecision.PASS:
            raise ValueError("pass result cannot contain blocking findings")
        return result

    @property
    def blocking_findings(self) -> tuple[Finding, ...]:
        return tuple(
            item for item in self.findings if item.severity in {Severity.P0, Severity.P1, Severity.P2}
        )


def parse_review_output(raw: str) -> ReviewResult:
    text = raw.strip()
    if len(text) > 1_000_000:
        raise ValueError("review output is too large")
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if len(lines) < 3:
            raise ValueError("invalid JSON code fence")
        text = "\n".join(lines[1:-1]).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("review output is not strict JSON") from exc
    return ReviewResult.from_dict(value)


def _bounded(value: Any, label: str, maximum: int, allow_empty: bool = False) -> str:
    text = str(value or "").strip()
    if not text and not allow_empty:
        raise ValueError(f"{label} is required")
    if len(text) > maximum:
        raise ValueError(f"{label} exceeds {maximum} characters")
    return text
