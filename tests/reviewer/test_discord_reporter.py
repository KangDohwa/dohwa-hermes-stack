import json
import unittest
import urllib.error
from unittest.mock import patch

from reviewer.discord_reporter import (
    EMBED_DESCRIPTION_UNITS,
    EMBED_FIELD_VALUE_UNITS,
    EMBED_TITLE_UNITS,
    EMBED_TOTAL_UNITS,
    DiscordReporter,
    _discord_units,
    _embed_units,
)


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit):
        return b'{"id":"123"}'


class DiscordReporterTests(unittest.TestCase):
    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_disables_mentions_and_limits_payload(self, mocked):
        reporter = DiscordReporter("https://discord.com/api/webhooks/0/not-a-real-webhook-token")
        message_id = reporter.send(
            event="@everyone merged",
            repository="example/example-repo",
            pull_number=1,
            pull_url="https://github.com/example/example-repo/pull/1",
            title="Title",
            head_sha="a" * 40,
            summary="ok",
        )
        self.assertEqual(message_id, "123")
        request = mocked.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(payload["allowed_mentions"], {"parse": []})
        self.assertIn("wait=true", request.full_url)

    @patch("urllib.request.urlopen", return_value=FakeResponse())
    def test_long_unicode_summary_is_truncated_within_embed_limits(self, mocked):
        reporter = DiscordReporter("https://discord.com/api/webhooks/0/not-a-real-webhook-token")
        reporter.send(
            event="검토 완료 " + "😀" * 2_000,
            repository="example/example-repo",
            pull_number=2,
            pull_url="https://github.com/example/example-repo/pull/2",
            title="😀" * 1_000,
            head_sha="b" * 40,
            summary="😀" * 10_000,
        )
        payload = json.loads(mocked.call_args.args[0].data)
        embed = payload["embeds"][0]
        self.assertLessEqual(_discord_units(embed["title"]), EMBED_TITLE_UNITS)
        self.assertLessEqual(
            _discord_units(embed["description"]),
            EMBED_DESCRIPTION_UNITS,
        )
        self.assertLessEqual(
            _discord_units(embed["fields"][0]["value"]),
            EMBED_FIELD_VALUE_UNITS,
        )
        self.assertLessEqual(_embed_units(embed), EMBED_TOTAL_UNITS)
        self.assertIn("일부 생략됨", embed["description"])

    @patch("urllib.request.urlopen")
    def test_bad_request_retries_once_with_compact_summary(self, mocked):
        mocked.side_effect = [
            urllib.error.HTTPError(
                "https://discord.com/api/webhooks/0/not-a-real-webhook-token",
                400,
                "Bad Request",
                {},
                None,
            ),
            FakeResponse(),
        ]
        reporter = DiscordReporter("https://discord.com/api/webhooks/0/not-a-real-webhook-token")
        message_id = reporter.send(
            event="검토 완료",
            repository="example/example-repo",
            pull_number=3,
            pull_url="https://github.com/example/example-repo/pull/3",
            title="Title",
            head_sha="c" * 40,
            summary="long summary " * 1_000,
        )
        self.assertEqual(message_id, "123")
        self.assertEqual(mocked.call_count, 2)
        compact_payload = json.loads(mocked.call_args_list[1].args[0].data)
        compact_description = compact_payload["embeds"][0]["description"]
        self.assertIn("축약 보고로 재전송", compact_description)
        self.assertLessEqual(_embed_units(compact_payload["embeds"][0]), EMBED_TOTAL_UNITS)

    @patch("urllib.request.urlopen")
    def test_compact_bad_request_is_propagated_without_third_attempt(self, mocked):
        mocked.side_effect = [
            urllib.error.HTTPError(
                "https://discord.com/api/webhooks/0/not-a-real-webhook-token",
                400,
                "Bad Request",
                {},
                None,
            ),
            urllib.error.HTTPError(
                "https://discord.com/api/webhooks/0/not-a-real-webhook-token",
                400,
                "Bad Request",
                {},
                None,
            ),
        ]
        reporter = DiscordReporter("https://discord.com/api/webhooks/0/not-a-real-webhook-token")
        with self.assertRaises(urllib.error.HTTPError):
            reporter.send(
                event="검토 완료",
                repository="example/example-repo",
                pull_number=4,
                pull_url="https://github.com/example/example-repo/pull/4",
                title="Title",
                head_sha="d" * 40,
                summary="summary",
            )
        self.assertEqual(mocked.call_count, 2)

    @patch("urllib.request.urlopen")
    def test_non_bad_request_is_not_retried(self, mocked):
        mocked.side_effect = urllib.error.HTTPError(
            "https://discord.com/api/webhooks/0/not-a-real-webhook-token",
            429,
            "Too Many Requests",
            {},
            None,
        )
        reporter = DiscordReporter("https://discord.com/api/webhooks/0/not-a-real-webhook-token")
        with self.assertRaises(urllib.error.HTTPError):
            reporter.send(
                event="검토 완료",
                repository="example/example-repo",
                pull_number=5,
                pull_url="https://github.com/example/example-repo/pull/5",
                title="Title",
                head_sha="d" * 40,
                summary="summary",
            )
        self.assertEqual(mocked.call_count, 1)


if __name__ == "__main__":
    unittest.main()
