import asyncio
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


MODULE_PATH = Path(__file__).parents[1] / "overlays" / "discord_presence.py"
SPEC = importlib.util.spec_from_file_location("discord_presence", MODULE_PATH)
assert SPEC and SPEC.loader
PRESENCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PRESENCE
SPEC.loader.exec_module(PRESENCE)


class FakePsutil:
    def __init__(self):
        self.cpu_interval = "unset"
        self.disk_path = None

    def cpu_percent(self, interval):
        self.cpu_interval = interval
        return 3.75

    @staticmethod
    def virtual_memory():
        return SimpleNamespace(percent=11.64)

    def disk_usage(self, path):
        self.disk_path = path
        gib = 1024**3
        return SimpleNamespace(used=15.291 * gib, total=207 * gib)


class RecordingController(PRESENCE.DiscordPresenceController):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.published = []

    async def _publish(self, text):
        self.published.append(text)


class DiscordPresencePureTests(unittest.TestCase):
    def test_korean_subject_particle(self):
        self.assertEqual(PRESENCE.korean_subject_particle("쩨봇"), "이")
        self.assertEqual(PRESENCE.korean_subject_particle("헤르메스"), "가")
        self.assertEqual(PRESENCE.korean_subject_particle("Hermes"), "가")

    def test_active_activity_text_uses_bot_name_and_priority_label(self):
        self.assertEqual(
            PRESENCE.active_activity_text("쩨봇", "approval"),
            "쩨봇이 승인 대기 중...",
        )
        self.assertEqual(
            PRESENCE.active_activity_text("헤르메스", "thinking"),
            "헤르메스가 생각 중...",
        )

    def test_system_snapshot_and_format(self):
        fake = FakePsutil()
        snapshot = PRESENCE.collect_system_snapshot(fake)
        self.assertIsNone(fake.cpu_interval)
        self.assertEqual(fake.disk_path, "/")
        self.assertEqual(
            PRESENCE.format_system_activity(snapshot),
            "⚡3.8% 🧠11.6% 💾15.29/207GB",
        )

    def test_usage_windows_are_selected_by_duration_and_clamped(self):
        payload = {
            "rate_limit": {
                "primary_window": {
                    "used_percent": 18.2,
                    "limit_window_seconds": 5 * 3600,
                },
                "secondary_window": {
                    "used_percent": 57.4,
                    "limit_window_seconds": 7 * 86400,
                },
            }
        }
        parsed = PRESENCE.parse_codex_usage_payload(payload)
        self.assertEqual(
            parsed,
            PRESENCE.UsageSnapshot(
                five_hour_remaining=82,
                weekly_remaining=43,
            ),
        )
        self.assertEqual(
            PRESENCE.format_usage_activity(parsed),
            "⏱️ 5h 82% / 주간 43%",
        )

    def test_missing_five_hour_window_is_rendered_as_unlimited(self):
        payload = {
            "rate_limit": {
                "primary_window": {
                    "used_percent": 54,
                    "limit_window_seconds": 7 * 86400,
                },
                "secondary_window": None,
            }
        }
        parsed = PRESENCE.parse_codex_usage_payload(payload)
        self.assertEqual(parsed, PRESENCE.UsageSnapshot(None, 46))
        self.assertEqual(
            PRESENCE.format_usage_activity(parsed),
            "⏱️ 5h ∞ / 주간 46%",
        )

    def test_missing_weekly_window_is_rendered_as_unlimited(self):
        payload = {
            "rate_limit": {
                "primary_window": {
                    "used_percent": 10,
                    "limit_window_seconds": 5 * 3600,
                },
                "secondary_window": None,
            }
        }
        parsed = PRESENCE.parse_codex_usage_payload(payload)
        self.assertEqual(parsed, PRESENCE.UsageSnapshot(90, None))
        self.assertEqual(
            PRESENCE.format_usage_activity(parsed),
            "⏱️ 5h 90% / 주간 ∞",
        )

    def test_both_absent_windows_are_rendered_as_unlimited(self):
        payload = {
            "rate_limit": {
                "primary_window": None,
                "secondary_window": None,
            }
        }
        parsed = PRESENCE.parse_codex_usage_payload(payload)
        self.assertEqual(parsed, PRESENCE.UsageSnapshot(None, None))
        self.assertEqual(
            PRESENCE.format_usage_activity(parsed),
            "⏱️ 5h ∞ / 주간 ∞",
        )

    def test_window_positions_do_not_override_durations(self):
        payload = {
            "rate_limit": {
                "primary_window": {
                    "used_percent": 57.4,
                    "limit_window_seconds": 7 * 86400,
                },
                "secondary_window": {
                    "used_percent": 18.2,
                    "limit_window_seconds": 5 * 3600,
                },
            }
        }
        self.assertEqual(
            PRESENCE.parse_codex_usage_payload(payload),
            PRESENCE.UsageSnapshot(82, 43),
        )

    def test_durationless_two_window_response_uses_positional_fallback(self):
        payload = {
            "rate_limit": {
                "primary_window": {"used_percent": 10},
                "secondary_window": {"used_percent": 20},
            }
        }
        self.assertEqual(
            PRESENCE.parse_codex_usage_payload(payload),
            PRESENCE.UsageSnapshot(90, 80),
        )

    def test_usage_requires_a_recognized_weekly_window(self):
        payload = {
            "rate_limit": {
                "primary_window": {
                    "used_percent": 10,
                    "limit_window_seconds": 5 * 3600,
                }
            }
        }
        self.assertIsNone(PRESENCE.parse_codex_usage_payload(payload))
        self.assertIsNone(PRESENCE.parse_codex_usage_payload(None))

    def test_usage_rejects_non_finite_percentages(self):
        for used in (float("nan"), float("inf"), float("-inf")):
            payload = {
                "rate_limit": {
                    "primary_window": {
                        "used_percent": used,
                        "limit_window_seconds": 5 * 3600,
                    },
                    "secondary_window": {
                        "used_percent": 20,
                        "limit_window_seconds": 7 * 86400,
                    },
                }
            }
            self.assertIsNone(PRESENCE.parse_codex_usage_payload(payload))

    def test_state_priority_and_generation_cleanup(self):
        controller = PRESENCE.DiscordPresenceController(SimpleNamespace())
        controller.turn_started("session-a", 1)
        controller.turn_started("session-b", 1)
        self.assertEqual(controller.current_state(), "thinking")

        controller.tool_started("session-a", 1, "tool-1")
        self.assertEqual(controller.current_state(), "tool")
        controller._responses.add("session-b")
        self.assertEqual(controller.current_state(), "response")
        controller._approvals.add("session-a")
        self.assertEqual(controller.current_state(), "approval")

        controller.turn_finished("session-a", 1)
        self.assertEqual(controller.current_state(), "response")
        controller.turn_finished("session-b", 1)
        self.assertEqual(controller.current_state(), "idle")

    def test_stale_generation_cannot_clear_new_turn(self):
        controller = PRESENCE.DiscordPresenceController(SimpleNamespace())
        controller.turn_started("same-session", 1)
        controller.turn_started("same-session", 2)
        controller.tool_started("same-session", 2, "tool-new")
        controller.turn_finished("same-session", 1)
        self.assertEqual(controller.current_state(), "tool")
        controller.turn_finished("same-session", 2)
        self.assertEqual(controller.current_state(), "idle")


class DiscordPresenceAsyncTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def adapter(name="쩨봇"):
        user = SimpleNamespace(
            name="portal-name",
            display_name="global-name",
            global_name="global-name",
        )
        guild = SimpleNamespace(me=SimpleNamespace(display_name=name))
        client = SimpleNamespace(user=user, guilds=[guild])
        return SimpleNamespace(_client=client)

    async def test_start_is_idempotent_and_idle_rotates(self):
        controller = RecordingController(
            self.adapter(),
            usage_fetcher=lambda: PRESENCE.UsageSnapshot(82, 43),
            system_collector=lambda: PRESENCE.SystemSnapshot(3.8, 11.6, 15.29, 207),
            idle_rotation_seconds=0.03,
            min_update_seconds=0,
            usage_refresh_seconds=60,
        )
        await controller.start()
        idle_task = controller._idle_task
        usage_task = controller._usage_task
        await controller.start()
        self.assertIs(controller._idle_task, idle_task)
        self.assertIs(controller._usage_task, usage_task)
        await asyncio.sleep(0.08)
        self.assertIn("⚡3.8% 🧠11.6% 💾15.29/207GB", controller.published)
        self.assertIn("⏱️ 5h 82% / 주간 43%", controller.published)
        await controller.stop()

    async def test_active_state_pauses_idle_and_returns_to_system_first(self):
        controller = RecordingController(
            self.adapter(),
            usage_fetcher=lambda: PRESENCE.UsageSnapshot(82, 43),
            system_collector=lambda: PRESENCE.SystemSnapshot(3.8, 11.6, 15.29, 207),
            idle_rotation_seconds=0.02,
            min_update_seconds=0,
            usage_refresh_seconds=60,
        )
        await controller.start()
        await asyncio.sleep(0.03)
        controller.turn_started("session", 1)
        await asyncio.sleep(0.02)
        self.assertEqual(controller.published[-1], "쩨봇이 생각 중...")
        controller.tool_started("session", 1, "tool")
        await asyncio.sleep(0.02)
        self.assertEqual(controller.published[-1], "쩨봇이 도구 실행 중...")
        controller.turn_finished("session", 1)
        await asyncio.sleep(0.02)
        self.assertEqual(
            controller.published[-1],
            "⚡3.8% 🧠11.6% 💾15.29/207GB",
        )
        await controller.stop()

    async def test_usage_failure_sets_fallback(self):
        def fail():
            raise RuntimeError("offline")

        controller = RecordingController(
            self.adapter(),
            usage_fetcher=fail,
            system_collector=lambda: PRESENCE.SystemSnapshot(1, 2, 3, 4),
            min_update_seconds=0,
        )
        controller._running = True
        controller._loop = asyncio.get_running_loop()
        success = await controller._refresh_usage()
        self.assertFalse(success)
        self.assertEqual(controller.usage_text, PRESENCE.USAGE_UNAVAILABLE)
        await controller.stop()

    async def test_none_usage_result_sets_fallback(self):
        controller = RecordingController(
            self.adapter(),
            usage_fetcher=lambda: None,
            system_collector=lambda: PRESENCE.SystemSnapshot(1, 2, 3, 4),
            min_update_seconds=0,
        )
        controller._running = True
        controller._loop = asyncio.get_running_loop()
        success = await controller._refresh_usage()
        self.assertFalse(success)
        self.assertEqual(controller.usage_text, PRESENCE.USAGE_UNAVAILABLE)
        await controller.stop()

    async def test_publish_failures_do_not_escape(self):
        class FailingController(RecordingController):
            async def _publish(self, text):
                raise RuntimeError("Discord offline")

        controller = FailingController(
            self.adapter(),
            usage_fetcher=lambda: PRESENCE.UsageSnapshot(82, 43),
            system_collector=lambda: PRESENCE.SystemSnapshot(1, 2, 3, 4),
            min_update_seconds=0,
            presence_retry_seconds=0.01,
            usage_refresh_seconds=60,
        )
        await controller.start()
        await asyncio.sleep(0.02)
        self.assertTrue(controller._running)
        await controller.stop()


if __name__ == "__main__":
    unittest.main()
