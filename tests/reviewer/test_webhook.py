import asyncio
import json
import unittest

from reviewer.webhook import (
    InvalidPayload,
    InvalidSignature,
    PayloadTooLarge,
    parse_webhook,
    read_limited_body,
    signature_for,
    verify_signature,
)


SECRET = "not-a-real-webhook-secret"
MAX_WEBHOOK_BYTES = 2 * 1024 * 1024


def body_for(**overrides):
    payload = {
        "action": "opened",
        "installation": {"id": 321},
        "repository": {"id": 456, "full_name": "example/example-repo"},
        "number": 7,
        "pull_request": {
            "number": 7,
            "draft": False,
            "merged": False,
            "merge_commit_sha": None,
            "base": {"sha": "b" * 40},
            "head": {"sha": "a" * 40},
        },
    }
    payload.update(overrides)
    return json.dumps(payload, separators=(",", ":")).encode()


class SignatureTests(unittest.TestCase):
    def test_raw_body_hmac_sha256_is_verified(self):
        raw_body = body_for()
        signature = signature_for(raw_body, SECRET)
        self.assertTrue(signature.startswith("sha256="))
        verify_signature(raw_body, signature, SECRET)

    def test_modified_raw_body_is_rejected(self):
        raw_body = body_for()
        signature = signature_for(raw_body, SECRET)
        with self.assertRaises(InvalidSignature):
            verify_signature(raw_body + b" ", signature, SECRET)

    def test_missing_or_wrong_algorithm_is_rejected(self):
        for signature in (None, "", "sha1=abc"):
            with self.subTest(signature=signature):
                with self.assertRaises(InvalidSignature):
                    verify_signature(body_for(), signature, SECRET)

    def test_empty_secret_is_rejected(self):
        with self.assertRaises(InvalidSignature):
            signature_for(body_for(), "")


class ParseWebhookTests(unittest.TestCase):
    def test_pull_request_identity_is_parsed_after_signature_check(self):
        raw_body = body_for()
        event = parse_webhook(
            {
                "x-github-delivery": "delivery-1",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": signature_for(raw_body, SECRET),
            },
            raw_body,
            SECRET,
        )
        self.assertEqual(event.delivery_id, "delivery-1")
        self.assertEqual(event.repository_id, 456)
        self.assertEqual(event.repository, "example/example-repo")
        self.assertEqual(event.pull_number, 7)
        self.assertEqual(event.head_sha, "a" * 40)
        self.assertEqual(event.base_sha, "b" * 40)
        self.assertIsNone(event.merge_sha)
        self.assertEqual(
            event.idempotency_key,
            f"example/example-repo/7/{'a' * 40}",
        )

    def test_merged_pull_request_includes_valid_merge_sha(self):
        merge_sha = "c" * 40
        raw_body = body_for(
            action="closed",
            pull_request={
                "number": 7,
                "draft": False,
                "merged": True,
                "merge_commit_sha": merge_sha,
                "base": {"sha": "b" * 40},
                "head": {"sha": "a" * 40},
            },
        )
        event = parse_webhook(
            {
                "X-GitHub-Delivery": "delivery-merged",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": signature_for(raw_body, SECRET),
            },
            raw_body,
            SECRET,
        )
        self.assertTrue(event.is_merged)
        self.assertEqual(merge_sha, event.merge_sha)

    def test_merged_pull_request_requires_merge_sha(self):
        raw_body = body_for(
            action="closed",
            pull_request={
                "number": 7,
                "draft": False,
                "merged": True,
                "merge_commit_sha": None,
                "base": {"sha": "b" * 40},
                "head": {"sha": "a" * 40},
            },
        )
        with self.assertRaisesRegex(InvalidPayload, "missing merge SHA"):
            parse_webhook(
                {
                    "X-GitHub-Delivery": "delivery-merged-missing-sha",
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": signature_for(raw_body, SECRET),
                },
                raw_body,
                SECRET,
            )

    def test_invalid_json_with_valid_signature_is_rejected(self):
        raw_body = b"{not-json"
        with self.assertRaises(InvalidPayload):
            parse_webhook(
                {
                    "X-GitHub-Delivery": "delivery-2",
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": signature_for(raw_body, SECRET),
                },
                raw_body,
                SECRET,
            )

    def test_missing_delivery_is_rejected(self):
        raw_body = body_for()
        with self.assertRaises(InvalidPayload):
            parse_webhook(
                {
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": signature_for(raw_body, SECRET),
                },
                raw_body,
                SECRET,
            )

    def test_pull_request_without_exact_identity_is_rejected(self):
        raw_body = body_for(repository={})
        with self.assertRaises(InvalidPayload):
            parse_webhook(
                {
                    "X-GitHub-Delivery": "delivery-3",
                    "X-GitHub-Event": "pull_request",
                    "X-Hub-Signature-256": signature_for(raw_body, SECRET),
                },
                raw_body,
                SECRET,
            )


class LimitedBodyTests(unittest.TestCase):
    def test_stream_body_is_bounded_before_full_buffering(self):
        class Request:
            async def stream(self):
                yield b"a" * MAX_WEBHOOK_BYTES
                yield b"b"

        with self.assertRaises(PayloadTooLarge):
            asyncio.run(
                read_limited_body(
                    Request().stream(), maximum_bytes=MAX_WEBHOOK_BYTES
                )
            )

    def test_stream_body_at_limit_is_accepted(self):
        class Request:
            async def stream(self):
                yield b"a" * (MAX_WEBHOOK_BYTES // 2)
                yield b"b" * (MAX_WEBHOOK_BYTES // 2)

        body = asyncio.run(
            read_limited_body(Request().stream(), maximum_bytes=MAX_WEBHOOK_BYTES)
        )
        self.assertEqual(MAX_WEBHOOK_BYTES, len(body))


if __name__ == "__main__":
    unittest.main()
