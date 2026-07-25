"""GitHub App authentication with installation-token caching."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Iterable
from urllib import error, parse, request

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:  # pragma: no cover - exercised only in incomplete deployments
    hashes = serialization = padding = None


DEFAULT_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"


class GitHubAuthError(RuntimeError):
    """Raised when GitHub App authentication cannot be completed."""


@dataclass(frozen=True)
class InstallationToken:
    value: str
    expires_at: float
    installation_id: int


UrlOpen = Callable[..., Any]


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _parse_repository(repository: str) -> tuple[str, str]:
    if not isinstance(repository, str):
        raise ValueError("repository must be an owner/name string")
    parts = repository.split("/")
    if len(parts) != 2 or not all(parts) or any(part.strip() != part for part in parts):
        raise ValueError("repository must be an owner/name string")
    return parts[0], parts[1]


def _parse_github_timestamp(value: Any) -> float:
    if not isinstance(value, str) or not value:
        raise GitHubAuthError("GitHub returned an invalid token expiration")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubAuthError("GitHub returned an invalid token expiration") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


class GitHubAppAuth:
    """Create App JWTs and cache repository installation tokens."""

    def __init__(
        self,
        app_id: int | str,
        private_key_path: str | os.PathLike[str],
        allowed_repositories: Iterable[str],
        *,
        api_url: str = DEFAULT_API_URL,
        urlopen: UrlOpen = request.urlopen,
        clock: Callable[[], float] = time.time,
        timeout: float = 10.0,
        refresh_before_seconds: float = 300.0,
    ) -> None:
        try:
            self.app_id = int(app_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("app_id must be an integer") from exc
        if self.app_id <= 0:
            raise ValueError("app_id must be positive")

        self.private_key_path = Path(private_key_path)
        self.api_url = api_url.rstrip("/")
        if not self.api_url:
            raise ValueError("api_url must not be empty")
        self._urlopen = urlopen
        self._clock = clock
        self.timeout = timeout
        self.refresh_before_seconds = refresh_before_seconds

        canonical: dict[str, str] = {}
        for repository in allowed_repositories:
            owner, name = _parse_repository(repository)
            normalized = f"{owner}/{name}"
            canonical[normalized.casefold()] = normalized
        if not canonical:
            raise ValueError("allowed_repositories must not be empty")
        self._allowed_repositories = canonical

        self._private_key: Any | None = None
        self._installation_ids: dict[str, int] = {}
        self._tokens: dict[int, InstallationToken] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_environment(cls) -> "GitHubAppAuth":
        app_id = os.environ.get("GITHUB_APP_ID")
        if not app_id:
            raise GitHubAuthError("GITHUB_APP_ID is required")
        key_path = os.environ.get(
            "GITHUB_PRIVATE_KEY_PATH", "/run/secrets/github-app.pem"
        )
        raw_allowlist = os.environ.get("GITHUB_REPOSITORY_ALLOWLIST")
        if not raw_allowlist:
            raise GitHubAuthError("GITHUB_REPOSITORY_ALLOWLIST is required")
        allowlist = tuple(
            item.strip() for item in raw_allowlist.split(",") if item.strip()
        )
        return cls(
            app_id,
            key_path,
            allowlist,
            api_url=os.environ.get("GITHUB_API_URL", DEFAULT_API_URL),
        )

    @property
    def allowed_repositories(self) -> tuple[str, ...]:
        return tuple(self._allowed_repositories.values())

    def require_allowed_repository(self, repository: str) -> str:
        owner, name = _parse_repository(repository)
        normalized = f"{owner}/{name}"
        try:
            return self._allowed_repositories[normalized.casefold()]
        except KeyError as exc:
            raise GitHubAuthError(
                f"repository is not allowlisted: {normalized}"
            ) from exc

    def create_app_jwt(self) -> str:
        now = int(self._clock())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iat": now - 60,
            "exp": now + 540,
            "iss": str(self.app_id),
        }
        encoded_header = _base64url(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        encoded_payload = _base64url(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        private_key = self._load_private_key()
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"

    def installation_id_for_repository(self, repository: str) -> int:
        canonical = self.require_allowed_repository(repository)
        key = canonical.casefold()
        with self._lock:
            cached = self._installation_ids.get(key)
            if cached is not None:
                return cached

            owner, name = _parse_repository(canonical)
            payload = self._app_request(
                "GET",
                f"/repos/{parse.quote(owner, safe='')}/{parse.quote(name, safe='')}"
                "/installation",
            )
            installation_id = payload.get("id") if isinstance(payload, dict) else None
            if not isinstance(installation_id, int) or installation_id <= 0:
                raise GitHubAuthError(
                    f"GitHub returned no valid installation for {canonical}"
                )
            self._installation_ids[key] = installation_id
            return installation_id

    def installation_token_for_repository(self, repository: str) -> str:
        canonical = self.require_allowed_repository(repository)
        installation_id = self.installation_id_for_repository(canonical)
        now = self._clock()
        with self._lock:
            cached = self._tokens.get(installation_id)
            if (
                cached is not None
                and cached.expires_at - now > self.refresh_before_seconds
            ):
                return cached.value

            payload = self._app_request(
                "POST",
                f"/app/installations/{installation_id}/access_tokens",
                body={},
            )
            token = payload.get("token") if isinstance(payload, dict) else None
            expires_at = (
                _parse_github_timestamp(payload.get("expires_at"))
                if isinstance(payload, dict)
                else None
            )
            if not isinstance(token, str) or not token or expires_at is None:
                raise GitHubAuthError("GitHub returned an invalid installation token")
            if expires_at <= now:
                raise GitHubAuthError("GitHub returned an already expired token")

            record = InstallationToken(token, expires_at, installation_id)
            self._tokens[installation_id] = record
            return record.value

    def invalidate_installation_token(self, repository: str) -> None:
        canonical = self.require_allowed_repository(repository)
        key = canonical.casefold()
        with self._lock:
            installation_id = self._installation_ids.get(key)
            if installation_id is not None:
                self._tokens.pop(installation_id, None)

    def _load_private_key(self) -> Any:
        with self._lock:
            if self._private_key is not None:
                return self._private_key
            if serialization is None or hashes is None or padding is None:
                raise GitHubAuthError(
                    "GitHub App JWT signing requires the 'cryptography' package"
                )
            try:
                key_bytes = self.private_key_path.read_bytes()
                private_key = serialization.load_pem_private_key(
                    key_bytes, password=None
                )
            except (OSError, ValueError, TypeError) as exc:
                raise GitHubAuthError(
                    f"unable to load GitHub App private key: {self.private_key_path}"
                ) from exc
            if not hasattr(private_key, "sign"):
                raise GitHubAuthError("GitHub App private key does not support signing")
            self._private_key = private_key
            return private_key

    def _app_request(
        self, method: str, path: str, *, body: dict[str, Any] | None = None
    ) -> Any:
        encoded_body = (
            json.dumps(body, separators=(",", ":")).encode("utf-8")
            if body is not None
            else None
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.create_app_jwt()}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "dohwa-bot-reviewer",
        }
        if encoded_body is not None:
            headers["Content-Type"] = "application/json"
        api_request = request.Request(
            f"{self.api_url}{path}",
            data=encoded_body,
            headers=headers,
            method=method,
        )
        try:
            with self._urlopen(api_request, timeout=self.timeout) as response:
                raw = response.read()
                status = getattr(response, "status", response.getcode())
        except error.HTTPError as exc:
            request_id = exc.headers.get("X-GitHub-Request-Id", "unknown")
            raise GitHubAuthError(
                f"GitHub App authentication request failed "
                f"(status={exc.code}, request_id={request_id})"
            ) from exc
        except error.URLError as exc:
            raise GitHubAuthError("GitHub App authentication request failed") from exc
        if status < 200 or status >= 300:
            raise GitHubAuthError(
                f"GitHub App authentication request failed (status={status})"
            )
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubAuthError("GitHub returned invalid JSON") from exc
