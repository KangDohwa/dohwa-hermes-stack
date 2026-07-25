from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


EMBED_TITLE_UNITS = 256
EMBED_DESCRIPTION_UNITS = 4_096
EMBED_FIELD_NAME_UNITS = 256
EMBED_FIELD_VALUE_UNITS = 1_024
EMBED_TOTAL_UNITS = 6_000
SUMMARY_UNITS = 3_500
COMPACT_SUMMARY_UNITS = 768
SUMMARY_OMISSION = "\n\n… Discord 표시 한도로 일부 생략됨"
COMPACT_NOTICE = "\n\nDiscord가 원문을 거부하여 축약 보고로 재전송했습니다."


class DiscordReporter:
    def __init__(self, webhook_url: str, timeout: float = 10.0):
        if not webhook_url.startswith("https://discord.com/api/webhooks/"):
            raise ValueError("invalid Discord webhook URL")
        self._url = webhook_url
        self._timeout = timeout

    def send(
        self,
        *,
        event: str,
        repository: str,
        pull_number: int,
        pull_url: str,
        title: str,
        head_sha: str,
        summary: str,
        color: int = 0x5865F2,
    ) -> str | None:
        payload = _build_payload(
            event=event,
            repository=repository,
            pull_number=pull_number,
            pull_url=pull_url,
            title=title,
            head_sha=head_sha,
            summary=summary,
            color=color,
            summary_units=SUMMARY_UNITS,
        )
        try:
            return self._post(payload)
        except urllib.error.HTTPError as exc:
            if exc.code != 400:
                raise
            exc.close()
            compact_summary = (
                _limit(summary or "세부 내용 없음", COMPACT_SUMMARY_UNITS)
                + COMPACT_NOTICE
            )
            compact_payload = _build_payload(
                event=event,
                repository=repository,
                pull_number=pull_number,
                pull_url=pull_url,
                title=title,
                head_sha=head_sha,
                summary=compact_summary,
                color=color,
                summary_units=COMPACT_SUMMARY_UNITS + _discord_units(COMPACT_NOTICE),
            )
            return self._post(compact_payload)

    def _post(self, payload: dict[str, Any]) -> str | None:
        separator = "&" if urllib.parse.urlsplit(self._url).query else "?"
        request = urllib.request.Request(
            self._url + separator + "wait=true",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "dohwa-bot-reviewer/1"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            body = response.read(64 * 1024)
        if not body:
            return None
        value: dict[str, Any] = json.loads(body)
        message_id = value.get("id")
        return str(message_id) if message_id else None


def _build_payload(
    *,
    event: str,
    repository: str,
    pull_number: int,
    pull_url: str,
    title: str,
    head_sha: str,
    summary: str,
    color: int,
    summary_units: int,
) -> dict[str, Any]:
    embed_title = _limit(
        f"[{repository}] PR #{pull_number}: {title}",
        EMBED_TITLE_UNITS,
    )
    status_name = _limit("상태", EMBED_FIELD_NAME_UNITS)
    status_value = _limit(event or "상태 정보 없음", EMBED_FIELD_VALUE_UNITS)
    sha_name = _limit("검토 SHA", EMBED_FIELD_NAME_UNITS)
    sha_value = _limit(head_sha[:12] or "unknown", EMBED_FIELD_VALUE_UNITS)
    reserved_units = sum(
        _discord_units(value)
        for value in (embed_title, status_name, status_value, sha_name, sha_value)
    )
    description_units = min(
        summary_units,
        EMBED_DESCRIPTION_UNITS,
        max(1, EMBED_TOTAL_UNITS - reserved_units),
    )
    description = _limit(
        summary or "세부 내용 없음",
        description_units,
        suffix=SUMMARY_OMISSION,
    )
    embed = {
        "title": embed_title,
        "url": pull_url,
        "description": description,
        "color": color,
        "fields": [
            {"name": status_name, "value": status_value, "inline": True},
            {"name": sha_name, "value": sha_value, "inline": True},
        ],
    }
    if _embed_units(embed) > EMBED_TOTAL_UNITS:
        raise ValueError("Discord embed exceeds the aggregate character limit")
    return {
        "username": "도화봇 GitHub Reviewer",
        "allowed_mentions": {"parse": []},
        "embeds": [embed],
    }


def _embed_units(embed: dict[str, Any]) -> int:
    values = [embed.get("title"), embed.get("description")]
    for field in embed.get("fields") or []:
        values.extend((field.get("name"), field.get("value")))
    return sum(_discord_units(str(value or "")) for value in values)


def _discord_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _limit(value: str, maximum: int, *, suffix: str = "…") -> str:
    if maximum < 1:
        raise ValueError("maximum must be positive")
    text = str(value or "").strip()
    if _discord_units(text) <= maximum:
        return text
    marker = suffix if _discord_units(suffix) <= maximum else "…"
    budget = maximum - _discord_units(marker)
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if _discord_units(text[:middle]) <= budget:
            low = middle
        else:
            high = middle - 1
    prefix = text[:low].rstrip()
    while prefix and _discord_units(prefix + marker) > maximum:
        prefix = prefix[:-1].rstrip()
    return prefix + marker
