from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
import re
from typing import Any

import yaml


_POLICY_VERSION = re.compile(r"[A-Za-z0-9._-]{1,64}")


@dataclass(frozen=True)
class Eligibility:
    eligible: bool
    state: str
    reason: str
    reason_code: str = "other"
    actual: int | None = None
    limit: int | None = None
    affected_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class RepositoryPolicy:
    full_name: str
    base_branches: tuple[str, ...]
    merge_method: str
    max_files: int
    max_changed_lines: int
    timeout_minutes: int
    high_risk_paths: tuple[str, ...]
    skip_labels: tuple[str, ...]
    test_commands: tuple[tuple[str, ...], ...]
    required_checks: tuple[str, ...]
    writable_test_paths: tuple[str, ...]
    policy_version: str = "1"

    @classmethod
    def from_mapping(
        cls,
        full_name: str,
        value: dict[str, Any],
        *,
        policy_version: str = "1",
    ) -> "RepositoryPolicy":
        if _POLICY_VERSION.fullmatch(policy_version) is None:
            raise ValueError("policy version must be canonical ASCII")
        limits = value.get("limits") or {}
        tests = value.get("tests") or []
        commands: list[tuple[str, ...]] = []
        for test in tests:
            if not isinstance(test, list) or not test or not all(isinstance(part, str) for part in test):
                raise ValueError(f"{full_name}: tests must be argv arrays")
            commands.append(tuple(test))
        merge_method = str(value.get("merge_method") or "squash")
        if merge_method != "squash":
            raise ValueError(f"{full_name}: only squash merge is approved")
        raw_writable_paths = value.get("writable_test_paths") or []
        if not isinstance(raw_writable_paths, list) or not all(
            isinstance(item, str) for item in raw_writable_paths
        ):
            raise ValueError(f"{full_name}: writable_test_paths must be an array of paths")
        writable_paths = tuple(raw_writable_paths)
        if any(
            not path
            or Path(path) == Path(".")
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            for path in writable_paths
        ):
            raise ValueError(f"{full_name}: writable_test_paths must be repository-relative")
        return cls(
            full_name=full_name,
            base_branches=tuple(value.get("base_branches") or ("main",)),
            merge_method=merge_method,
            max_files=int(limits.get("max_files", 50)),
            max_changed_lines=int(limits.get("max_changed_lines", 3_000)),
            timeout_minutes=int(limits.get("timeout_minutes", 20)),
            high_risk_paths=tuple(value.get("high_risk_paths") or ()),
            skip_labels=tuple(value.get("skip_labels") or ()),
            test_commands=tuple(commands),
            required_checks=tuple(value.get("required_checks") or ()),
            writable_test_paths=writable_paths,
            policy_version=policy_version,
        )

    def high_risk_files(self, paths: list[str]) -> list[str]:
        return sorted(
            path
            for path in paths
            if any(_path_matches(path, pattern) for pattern in self.high_risk_paths)
        )

    def evaluate(self, pull: dict[str, Any], files: list[dict[str, Any]]) -> Eligibility:
        if pull.get("state") != "open":
            return Eligibility(False, "IGNORED", "pull request is not open")
        if pull.get("draft"):
            return Eligibility(False, "WAITING_READY", "pull request is draft")
        base = ((pull.get("base") or {}).get("ref") or "").strip()
        if base not in self.base_branches:
            return Eligibility(False, "HUMAN_REVIEW", f"base branch {base!r} is not allowed")
        labels = {
            str(item.get("name") or "").casefold()
            for item in (pull.get("labels") or [])
            if isinstance(item, dict)
        }
        skip_labels = {label.casefold() for label in self.skip_labels}
        blocked = sorted(labels.intersection(skip_labels))
        if blocked:
            return Eligibility(False, "SKIPPED", f"skip label present: {', '.join(blocked)}")
        head_repo = (((pull.get("head") or {}).get("repo") or {}).get("full_name") or "")
        if head_repo and head_repo != self.full_name:
            return Eligibility(False, "HUMAN_REVIEW", "fork pull requests require human review")
        if len(files) > self.max_files:
            return Eligibility(
                False,
                "HUMAN_REVIEW",
                "changed file limit exceeded",
                reason_code="changed_file_limit",
                actual=len(files),
                limit=self.max_files,
            )
        changed_lines = sum(
            int(item.get("additions") or 0) + int(item.get("deletions") or 0)
            for item in files
        )
        if changed_lines > self.max_changed_lines:
            return Eligibility(
                False,
                "HUMAN_REVIEW",
                "changed line limit exceeded",
                reason_code="changed_line_limit",
                actual=changed_lines,
                limit=self.max_changed_lines,
            )
        candidate_paths = []
        for item in files:
            candidate_paths.append(str(item.get("filename") or ""))
            if item.get("previous_filename"):
                candidate_paths.append(str(item["previous_filename"]))
        risky = self.high_risk_files(candidate_paths)
        if risky:
            return Eligibility(
                False,
                "HUMAN_REVIEW",
                f"high-risk paths changed: {', '.join(risky[:5])}",
                reason_code="high_risk_paths",
                actual=len(risky),
                limit=0,
                affected_paths=tuple(risky),
            )
        unreviewable = sorted(
            str(item.get("filename") or "")
            for item in files
            if not isinstance(item.get("patch"), str)
        )
        if unreviewable:
            return Eligibility(
                False,
                "HUMAN_REVIEW",
                f"diff content unavailable: {', '.join(unreviewable[:5])}",
                reason_code="diff_unavailable",
                actual=len(unreviewable),
                limit=0,
                affected_paths=tuple(unreviewable),
            )
        return Eligibility(True, "QUEUED", "eligible")


def _path_matches(path: str, pattern: str) -> bool:
    if fnmatch(path, pattern):
        return True
    return pattern.startswith("**/") and fnmatch(path, pattern[3:])


def load_policies(path: Path) -> dict[str, RepositoryPolicy]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
        raise ValueError("policy version must be a positive integer")
    policy_version = str(version)
    repositories = raw.get("repositories")
    if not isinstance(repositories, dict):
        raise ValueError("policy must contain a repositories mapping")
    return {
        full_name: RepositoryPolicy.from_mapping(
            full_name,
            value or {},
            policy_version=policy_version,
        )
        for full_name, value in repositories.items()
    }
