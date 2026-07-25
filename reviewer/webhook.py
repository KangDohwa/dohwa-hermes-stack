from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import AsyncIterator, Mapping
from typing import Any

from reviewer.models import WebhookEvent


class WebhookError(ValueError):
    pass


class InvalidSignature(WebhookError):
    pass


class InvalidPayload(WebhookError):
    pass


class PayloadTooLarge(WebhookError):
    pass


async def read_limited_body(
    stream: AsyncIterator[bytes], *, maximum_bytes: int
) -> bytes:
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    body = bytearray()
    async for chunk in stream:
        if len(body) + len(chunk) > maximum_bytes:
            raise PayloadTooLarge("webhook payload is too large")
        body.extend(chunk)
    return bytes(body)


def signature_for(raw_body: bytes, secret: str | bytes) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not key:
        raise InvalidSignature("webhook secret must not be empty")
    return "sha256=" + hmac.new(key, raw_body, hashlib.sha256).hexdigest()


def verify_signature(
    raw_body: bytes,
    signature_header: str | None,
    secret: str | bytes,
) -> None:
    if not isinstance(raw_body, bytes):
        raise TypeError("raw_body must be bytes")
    if not signature_header or not signature_header.startswith("sha256="):
        raise InvalidSignature("missing or malformed X-Hub-Signature-256")
    expected = signature_for(raw_body, secret)
    if not hmac.compare_digest(expected, signature_header):
        raise InvalidSignature("webhook signature does not match")


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.casefold()
    for key, value in headers.items():
        if key.casefold() == wanted:
            return value
    return None


def parse_webhook(
    headers: Mapping[str, str],
    raw_body: bytes,
    secret: str | bytes,
) -> WebhookEvent:
    verify_signature(
        raw_body,
        _header(headers, "X-Hub-Signature-256"),
        secret,
    )

    delivery_id = (_header(headers, "X-GitHub-Delivery") or "").strip()
    event_name = (_header(headers, "X-GitHub-Event") or "").strip()
    if not delivery_id or not event_name:
        raise InvalidPayload("missing GitHub delivery or event header")

    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidPayload("webhook body is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise InvalidPayload("webhook body must be a JSON object")

    repository = payload.get("repository")
    installation = payload.get("installation")
    pull_request = payload.get("pull_request")
    if not isinstance(repository, dict):
        repository = {}
    if not isinstance(installation, dict):
        installation = {}
    if not isinstance(pull_request, dict):
        pull_request = _pull_request_from_check_payload(payload)

    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict):
        base = {}
    if not isinstance(head, dict):
        head = {}

    event = WebhookEvent(
        delivery_id=delivery_id,
        event_name=event_name,
        action=_optional_str(payload.get("action")),
        repository_id=_optional_int(repository.get("id")),
        repository=_optional_str(repository.get("full_name")),
        installation_id=_optional_int(installation.get("id")),
        pull_number=_optional_int(
            pull_request.get("number", payload.get("number"))
        ),
        base_sha=_optional_str(base.get("sha")),
        head_sha=_optional_str(head.get("sha")),
        is_draft=_optional_bool(pull_request.get("draft")),
        is_merged=_optional_bool(pull_request.get("merged")),
        merge_sha=_optional_str(pull_request.get("merge_commit_sha")),
    )
    if event_name == "pull_request":
        if (
            not event.repository
            or not event.pull_number
            or not _is_sha(event.base_sha)
            or not _is_sha(event.head_sha)
        ):
            raise InvalidPayload("pull_request payload is missing repository/PR/SHA identity")
        if event.is_merged is True and not _is_sha(event.merge_sha):
            raise InvalidPayload("merged pull_request payload is missing merge SHA")
        if event.merge_sha is not None and not _is_sha(event.merge_sha):
            raise InvalidPayload("pull_request payload has an invalid merge SHA")
    return event


def _pull_request_from_check_payload(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("check_run", "check_suite"):
        check = payload.get(key)
        if not isinstance(check, dict):
            continue
        pull_requests = check.get("pull_requests")
        if isinstance(pull_requests, list) and pull_requests:
            candidate = pull_requests[0]
            if isinstance(candidate, dict):
                return candidate
    return {}


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _is_sha(value: str | None) -> bool:
    return bool(value and re.fullmatch(r"[0-9a-fA-F]{40,64}", value))
