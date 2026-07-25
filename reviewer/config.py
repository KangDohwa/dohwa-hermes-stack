from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re


_APP_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?")
_REPOSITORY_PART = re.compile(r"[A-Za-z0-9_.-]+")


def _required(name: str, environ: dict[str, str]) -> str:
    value = (environ.get(name) or "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _repositories(name: str, raw: str) -> tuple[str, ...]:
    repositories = tuple(item.strip() for item in raw.split(",") if item.strip())
    if not repositories:
        raise ValueError(f"{name} must contain at least one repository")
    for repository in repositories:
        parts = repository.split("/")
        if (
            len(parts) != 2
            or not all(_REPOSITORY_PART.fullmatch(part) for part in parts)
        ):
            raise ValueError(f"{name} must contain owner/name repositories")
    if len({repository.casefold() for repository in repositories}) != len(repositories):
        raise ValueError(f"{name} must not contain duplicate repositories")
    return repositories


def _read_secret(path: Path, name: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"{name} could not be read") from exc
    if not value:
        raise ValueError(f"{name} is empty")
    return value


@dataclass(frozen=True)
class Settings:
    app_id: int
    app_slug: str
    private_key_path: Path
    webhook_secret_path: Path
    discord_webhook_url: str
    state_db_path: Path
    spool_path: Path
    policy_path: Path
    repositories: tuple[str, ...]
    mode: str = "observe"
    enabled: bool = True

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "Settings":
        env = dict(os.environ if environ is None else environ)
        app_id_raw = _required("GITHUB_APP_ID", env)
        if not app_id_raw.isdigit():
            raise ValueError("GITHUB_APP_ID must be numeric")

        slug = _required("GITHUB_APP_SLUG", env)
        if _APP_SLUG.fullmatch(slug) is None:
            raise ValueError("GITHUB_APP_SLUG must be a lowercase GitHub App slug")

        mode = (env.get("REVIEWER_MODE") or "observe").strip().lower()
        if mode not in {"observe", "comment", "draft", "auto"}:
            raise ValueError("REVIEWER_MODE must be observe, comment, draft, or auto")

        approved_repositories = _repositories(
            "GITHUB_REPOSITORY_ALLOWLIST",
            _required("GITHUB_REPOSITORY_ALLOWLIST", env),
        )
        repositories = _repositories(
            "REVIEWER_REPOSITORIES",
            _required("REVIEWER_REPOSITORIES", env),
        )
        approved = {repository.casefold() for repository in approved_repositories}
        if any(repository.casefold() not in approved for repository in repositories):
            raise ValueError("REVIEWER_REPOSITORIES exceeds the approved allowlist")

        private_key_path = Path(
            env.get("GITHUB_APP_PRIVATE_KEY_FILE")
            or "/run/secrets/github_app_private_key"
        )
        webhook_secret_path = Path(
            env.get("GITHUB_WEBHOOK_SECRET_FILE")
            or "/run/secrets/github_webhook_secret"
        )
        _read_secret(private_key_path, "GitHub App private key")
        _read_secret(webhook_secret_path, "GitHub webhook secret")

        discord_url = _required("DISCORD_WEBHOOK_URL", env)
        if not discord_url.startswith("https://discord.com/api/webhooks/"):
            raise ValueError("DISCORD_WEBHOOK_URL must be an official Discord webhook URL")

        enabled = (env.get("REVIEWER_ENABLED") or "true").strip().lower()
        if enabled not in {"true", "false"}:
            raise ValueError("REVIEWER_ENABLED must be true or false")

        return cls(
            app_id=int(app_id_raw),
            app_slug=slug,
            private_key_path=private_key_path,
            webhook_secret_path=webhook_secret_path,
            discord_webhook_url=discord_url,
            state_db_path=Path(env.get("REVIEWER_STATE_DB") or "/var/lib/reviewer/state.sqlite3"),
            spool_path=Path(env.get("REVIEWER_SPOOL") or "/var/lib/reviewer/spool"),
            policy_path=Path(env.get("REVIEWER_POLICY") or "/app/reviewer/policies/central.yml"),
            repositories=repositories,
            mode=mode,
            enabled=enabled == "true",
        )

    def webhook_secret(self) -> str:
        return _read_secret(self.webhook_secret_path, "GitHub webhook secret")
