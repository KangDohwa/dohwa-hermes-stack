"""Fail-open Discord activity controller for the single-server Hermes gateway."""

from __future__ import annotations

import asyncio
import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional


logger = logging.getLogger(__name__)

IDLE_ROTATION_SECONDS = 10.0
PRESENCE_MIN_UPDATE_SECONDS = 5.0
PRESENCE_RETRY_SECONDS = 30.0
USAGE_REFRESH_SECONDS = 600.0
USAGE_AFTER_WORK_SECONDS = 300.0
USAGE_RETRY_SECONDS = (60.0, 120.0, 300.0, 600.0)
USAGE_UNAVAILABLE = "⏱️ Usage 확인 불가"
SYSTEM_UNAVAILABLE = "⚡ 시스템 정보 확인 불가"


@dataclass(frozen=True)
class SystemSnapshot:
    cpu_percent: float
    memory_percent: float
    disk_used_gb: float
    disk_total_gb: float


@dataclass(frozen=True)
class UsageSnapshot:
    five_hour_remaining: Optional[int]
    weekly_remaining: Optional[int]


def korean_subject_particle(name: str) -> str:
    """Return 이 after a Hangul syllable with jongseong, otherwise 가."""

    text = str(name or "").rstrip()
    if not text:
        return "가"
    codepoint = ord(text[-1])
    if 0xAC00 <= codepoint <= 0xD7A3 and (codepoint - 0xAC00) % 28:
        return "이"
    return "가"


def active_activity_text(bot_name: str, state: str) -> str:
    label = {
        "approval": "승인 대기 중...",
        "response": "응답 대기 중...",
        "tool": "도구 실행 중...",
        "thinking": "생각 중...",
    }[state]
    name = str(bot_name or "Hermes").strip() or "Hermes"
    return f"{name}{korean_subject_particle(name)} {label}"


def format_system_activity(snapshot: SystemSnapshot) -> str:
    return (
        f"⚡{snapshot.cpu_percent:.1f}% "
        f"🧠{snapshot.memory_percent:.1f}% "
        f"💾{snapshot.disk_used_gb:.2f}/{snapshot.disk_total_gb:.0f}GB"
    )


def format_usage_activity(snapshot: UsageSnapshot) -> str:
    five_hour = (
        "∞"
        if snapshot.five_hour_remaining is None
        else f"{snapshot.five_hour_remaining}%"
    )
    weekly = (
        "∞"
        if snapshot.weekly_remaining is None
        else f"{snapshot.weekly_remaining}%"
    )
    return f"⏱️ 5h {five_hour} / 주간 {weekly}"


def collect_system_snapshot(psutil_module: Any = None) -> SystemSnapshot:
    if psutil_module is None:
        import psutil as psutil_module

    memory = psutil_module.virtual_memory()
    disk = psutil_module.disk_usage("/")
    gib = 1024**3
    return SystemSnapshot(
        cpu_percent=float(psutil_module.cpu_percent(interval=None)),
        memory_percent=float(memory.percent),
        disk_used_gb=float(disk.used) / gib,
        disk_total_gb=float(disk.total) / gib,
    )


def parse_codex_usage_payload(payload: Any) -> Optional[UsageSnapshot]:
    """Classify active windows by duration, treating absent limits as unlimited."""

    if not isinstance(payload, dict):
        return None
    rate_limit = payload.get("rate_limit")
    if not isinstance(rate_limit, dict):
        return None
    window_keys = ("primary_window", "secondary_window")
    if not all(key in rate_limit for key in window_keys):
        return None

    def remaining(window: Any) -> Optional[int]:
        used = window.get("used_percent")
        if (
            isinstance(used, bool)
            or not isinstance(used, (int, float))
            or not math.isfinite(float(used))
        ):
            raise ValueError("Invalid Usage percentage")
        return max(0, min(100, round(100 - float(used))))

    five_hour: Optional[int] = None
    weekly: Optional[int] = None
    positional: list[tuple[str, int]] = []
    try:
        for key in window_keys:
            window = rate_limit.get(key)
            if window is None:
                continue
            if not isinstance(window, dict):
                return None
            value = remaining(window)
            seconds = window.get("limit_window_seconds")
            if isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
                if not math.isfinite(float(seconds)):
                    return None
                if 4 * 3600 <= float(seconds) <= 6 * 3600:
                    five_hour = value
                    continue
                if 6 * 86400 <= float(seconds) <= 8 * 86400:
                    weekly = value
                    continue
            positional.append((key, value))
    except ValueError:
        return None

    # Older responses omitted duration but consistently used primary=5h and
    # secondary=weekly. Only use that fallback when both windows exist.
    if five_hour is None and weekly is None and len(positional) == 2:
        by_key = dict(positional)
        five_hour = by_key.get("primary_window")
        weekly = by_key.get("secondary_window")
        positional.clear()

    # A single durationless window is ambiguous rather than demonstrably absent.
    if positional:
        return None
    return UsageSnapshot(five_hour_remaining=five_hour, weekly_remaining=weekly)


def fetch_openai_codex_usage() -> Optional[UsageSnapshot]:
    import httpx
    from agent.account_usage import (
        _resolve_codex_usage_credentials,
        _resolve_codex_usage_url,
    )

    token, base_url, account_id = _resolve_codex_usage_credentials(None, None)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "codex-cli",
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    with httpx.Client(timeout=15.0) as client:
        response = client.get(_resolve_codex_usage_url(base_url), headers=headers)
        response.raise_for_status()
    return parse_codex_usage_payload(response.json() or {})


class DiscordPresenceController:
    """Own all dynamic activity state without blocking gateway work."""

    def __init__(
        self,
        adapter: Any,
        *,
        usage_fetcher: Callable[[], Optional[UsageSnapshot]] = fetch_openai_codex_usage,
        system_collector: Callable[[], SystemSnapshot] = collect_system_snapshot,
        monotonic: Callable[[], float] = time.monotonic,
        idle_rotation_seconds: float = IDLE_ROTATION_SECONDS,
        min_update_seconds: float = PRESENCE_MIN_UPDATE_SECONDS,
        presence_retry_seconds: float = PRESENCE_RETRY_SECONDS,
        usage_refresh_seconds: float = USAGE_REFRESH_SECONDS,
        usage_after_work_seconds: float = USAGE_AFTER_WORK_SECONDS,
        usage_retry_seconds: tuple[float, ...] = USAGE_RETRY_SECONDS,
    ):
        self.adapter = adapter
        self.usage_fetcher = usage_fetcher
        self.system_collector = system_collector
        self.monotonic = monotonic
        self.idle_rotation_seconds = idle_rotation_seconds
        self.min_update_seconds = min_update_seconds
        self.presence_retry_seconds = presence_retry_seconds
        self.usage_refresh_seconds = usage_refresh_seconds
        self.usage_after_work_seconds = usage_after_work_seconds
        self.usage_retry_seconds = usage_retry_seconds

        self.bot_name = "Hermes"
        self.system_text = SYSTEM_UNAVAILABLE
        self.usage_text = USAGE_UNAVAILABLE
        self.idle_index = 0

        self._state_lock = threading.RLock()
        self._turns: set[tuple[str, int]] = set()
        self._tools: set[tuple[tuple[str, int], str]] = set()
        self._approvals: set[str] = set()
        self._responses: set[str] = set()

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
        self._idle_task: Optional[asyncio.Task] = None
        self._usage_task: Optional[asyncio.Task] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._usage_wake: Optional[asyncio.Event] = None
        self._wait_watchers: dict[tuple[str, str], asyncio.Task] = {}

        self._refresh_pending = False
        self._last_presence_text: Optional[str] = None
        self._last_presence_at = float("-inf")
        self._last_usage_attempt_at = float("-inf")
        self._usage_failures = 0

    @staticmethod
    def _turn_token(session_key: str, generation: Any) -> tuple[str, int]:
        try:
            parsed_generation = int(generation)
        except (TypeError, ValueError):
            parsed_generation = 0
        return str(session_key or ""), parsed_generation

    def current_state(self) -> str:
        with self._state_lock:
            if self._approvals:
                return "approval"
            if self._responses:
                return "response"
            if self._tools:
                return "tool"
            if self._turns:
                return "thinking"
        return "idle"

    def desired_text(self) -> str:
        state = self.current_state()
        if state != "idle":
            return active_activity_text(self.bot_name, state)
        return self.system_text if self.idle_index == 0 else self.usage_text

    def _call_on_loop(self, callback: Callable[..., None], *args: Any) -> None:
        loop = self._loop
        if not self._running or loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(callback, *args)
        except Exception:
            logger.debug("Discord presence loop scheduling failed", exc_info=True)

    def turn_started(self, session_key: str, generation: Any) -> None:
        token = self._turn_token(session_key, generation)
        with self._state_lock:
            self._turns.add(token)
        self._call_on_loop(self._reconcile)

    def turn_finished(self, session_key: str, generation: Any) -> None:
        token = self._turn_token(session_key, generation)
        with self._state_lock:
            self._turns.discard(token)
            self._tools = {entry for entry in self._tools if entry[0] != token}
            if not any(turn[0] == token[0] for turn in self._turns):
                self._approvals.discard(token[0])
                self._responses.discard(token[0])
        self._call_on_loop(self._after_turn_finished)

    def tool_started(self, session_key: str, generation: Any, call_id: Any) -> None:
        token = self._turn_token(session_key, generation)
        with self._state_lock:
            if token not in self._turns:
                return
            self._tools.add((token, str(call_id or "")))
        self._call_on_loop(self._reconcile)

    def tool_finished(self, session_key: str, generation: Any, call_id: Any) -> None:
        token = self._turn_token(session_key, generation)
        with self._state_lock:
            self._tools.discard((token, str(call_id or "")))
        self._call_on_loop(self._reconcile)

    def clear_session(self, session_key: str) -> None:
        key = str(session_key or "")
        with self._state_lock:
            self._approvals.discard(key)
            self._responses.discard(key)
            self._tools = {entry for entry in self._tools if entry[0][0] != key}
        self._call_on_loop(self._reconcile)

    async def start(self) -> None:
        if self._running:
            await self._refresh_bot_name()
            self._request_refresh()
            return
        self._loop = asyncio.get_running_loop()
        self._running = True
        self._last_presence_text = None
        self._last_presence_at = float("-inf")
        self._last_usage_attempt_at = float("-inf")
        self._usage_failures = 0
        self._refresh_pending = False
        self._usage_wake = asyncio.Event()
        await self._refresh_bot_name()
        self._usage_task = asyncio.create_task(
            self._usage_loop(), name="discord-presence-usage"
        )
        self._reconcile()

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        tasks = [
            self._idle_task,
            self._usage_task,
            self._refresh_task,
            *self._wait_watchers.values(),
        ]
        self._idle_task = None
        self._usage_task = None
        self._refresh_task = None
        self._wait_watchers.clear()
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(
                *(task for task in tasks if task is not None),
                return_exceptions=True,
            )
        with self._state_lock:
            self._turns.clear()
            self._tools.clear()
            self._approvals.clear()
            self._responses.clear()
        self._loop = None
        self._usage_wake = None
        self._refresh_pending = False

    async def reassert(self) -> None:
        """Republish the latest desired activity after Discord reconnects."""

        if not self._running:
            await self.start()
            return
        await self._refresh_bot_name()
        self._last_presence_text = None
        self._last_presence_at = float("-inf")
        self._request_refresh()

    async def _refresh_bot_name(self) -> None:
        client = getattr(self.adapter, "_client", None)
        user = getattr(client, "user", None)
        resolved = ""
        guilds = list(getattr(client, "guilds", None) or ())
        if len(guilds) == 1:
            member = getattr(guilds[0], "me", None)
            resolved = str(getattr(member, "display_name", "") or "").strip()
        if not resolved:
            resolved = str(
                getattr(user, "display_name", "")
                or getattr(user, "global_name", "")
                or getattr(user, "name", "")
                or "Hermes"
            ).strip()
        self.bot_name = resolved or "Hermes"

    def _is_idle(self) -> bool:
        return self.current_state() == "idle"

    def _reconcile(self) -> None:
        if not self._running:
            return
        if self._is_idle():
            if self._idle_task is None or self._idle_task.done():
                self._idle_task = asyncio.create_task(
                    self._idle_loop(), name="discord-presence-idle"
                )
                return
        elif self._idle_task is not None:
            task = self._idle_task
            self._idle_task = None
            if not task.done():
                task.cancel()
        self._request_refresh()

    def _after_turn_finished(self) -> None:
        self._reconcile()
        if (
            self._usage_wake is not None
            and self._last_usage_attempt_at != float("-inf")
            and self.monotonic() - self._last_usage_attempt_at
            >= self.usage_after_work_seconds
        ):
            self._usage_wake.set()

    async def _idle_loop(self) -> None:
        self.idle_index = 0
        try:
            while self._running and self._is_idle():
                if self.idle_index == 0:
                    await self._refresh_system_text()
                self._request_refresh()
                await asyncio.sleep(self.idle_rotation_seconds)
                self.idle_index = 1 - self.idle_index
        except asyncio.CancelledError:
            pass
        finally:
            if self._idle_task is asyncio.current_task():
                self._idle_task = None

    async def _refresh_system_text(self) -> None:
        try:
            snapshot = await asyncio.to_thread(self.system_collector)
            self.system_text = format_system_activity(snapshot)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.system_text = SYSTEM_UNAVAILABLE
            logger.debug("Discord system presence collection failed", exc_info=True)

    async def _usage_loop(self) -> None:
        delay = 0.0
        try:
            while self._running:
                if delay > 0:
                    wake = self._usage_wake
                    if wake is None:
                        return
                    try:
                        await asyncio.wait_for(wake.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass
                    wake.clear()
                success = await self._refresh_usage()
                if success:
                    self._usage_failures = 0
                    delay = self.usage_refresh_seconds
                else:
                    index = min(
                        self._usage_failures,
                        max(0, len(self.usage_retry_seconds) - 1),
                    )
                    delay = (
                        self.usage_retry_seconds[index]
                        if self.usage_retry_seconds
                        else self.usage_refresh_seconds
                    )
                    self._usage_failures += 1
        except asyncio.CancelledError:
            pass

    async def _refresh_usage(self) -> bool:
        self._last_usage_attempt_at = self.monotonic()
        try:
            snapshot = await asyncio.to_thread(self.usage_fetcher)
            if snapshot is None:
                raise RuntimeError("Usage windows unavailable")
            self.usage_text = format_usage_activity(snapshot)
            success = True
        except asyncio.CancelledError:
            raise
        except Exception:
            self.usage_text = USAGE_UNAVAILABLE
            success = False
            logger.debug("Discord Usage presence refresh failed", exc_info=True)
        self._request_refresh()
        return success

    def watch_approval(self, session_key: str) -> None:
        self._watch_wait_state("approval", session_key)

    def watch_response(self, session_key: str) -> None:
        self._watch_wait_state("response", session_key)

    def _watch_wait_state(self, kind: str, session_key: str) -> None:
        key = (kind, str(session_key or ""))
        existing = self._wait_watchers.get(key)
        if existing is not None and not existing.done():
            return
        with self._state_lock:
            target = self._approvals if kind == "approval" else self._responses
            target.add(key[1])
        self._reconcile()
        self._wait_watchers[key] = asyncio.create_task(
            self._wait_state_loop(kind, key[1]),
            name=f"discord-presence-{kind}",
        )

    async def _wait_state_loop(self, kind: str, session_key: str) -> None:
        try:
            while self._running:
                try:
                    if kind == "approval":
                        from tools.approval import has_blocking_approval

                        pending = has_blocking_approval(session_key)
                    else:
                        from tools.clarify_gateway import has_pending

                        pending = has_pending(session_key)
                except Exception:
                    pending = False
                    logger.debug(
                        "Discord %s presence watcher failed", kind, exc_info=True
                    )
                if not pending:
                    return
                await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            pass
        finally:
            with self._state_lock:
                target = (
                    self._approvals if kind == "approval" else self._responses
                )
                target.discard(session_key)
            self._wait_watchers.pop((kind, session_key), None)
            self._reconcile()

    def _request_refresh(self) -> None:
        if not self._running:
            return
        self._refresh_pending = True
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = asyncio.create_task(
                self._refresh_loop(), name="discord-presence-publish"
            )

    async def _refresh_loop(self) -> None:
        try:
            while self._running and self._refresh_pending:
                self._refresh_pending = False
                wait_seconds = max(
                    0.0,
                    self.min_update_seconds
                    - (self.monotonic() - self._last_presence_at),
                )
                if wait_seconds:
                    await asyncio.sleep(wait_seconds)
                text = self.desired_text()
                if text == self._last_presence_text:
                    continue
                self._last_presence_at = self.monotonic()
                try:
                    await self._publish(text)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.warning(
                        "Discord presence update failed", exc_info=True
                    )
                    self._refresh_pending = True
                    await asyncio.sleep(self.presence_retry_seconds)
                    continue
                self._last_presence_text = text
        except asyncio.CancelledError:
            pass
        finally:
            if self._refresh_task is asyncio.current_task():
                self._refresh_task = None
            if self._running and self._refresh_pending:
                self._request_refresh()

    async def _publish(self, text: str) -> None:
        client = getattr(self.adapter, "_client", None)
        if client is None or getattr(client, "user", None) is None:
            raise RuntimeError("Discord client is not ready")
        import discord

        await client.change_presence(
            activity=discord.CustomActivity(name=text),
            status=discord.Status.online,
        )
