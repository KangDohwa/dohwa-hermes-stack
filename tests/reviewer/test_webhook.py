import asyncio
import hashlib
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


def label_body_for(action="labeled", **overrides):
    payload = {
        "action": action,
        "installation": {"id": 321},
        "repository": {"id": 456, "full_name": "example/example-repo"},
        "number": 7,
        "label": {
            "id": 654,
            "node_id": "LA_label_654",
            "name": "hermes:merge-approved",
        },
        "sender": {
            "id": 987,
            "node_id": "U_sender_987",
            "login": "approver",
            "type": "User",
        },
        "pull_request": {
            "number": 7,
            "updated_at": "2026-07-25T01:02:03Z",
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

    def test_label_actions_preserve_strict_signed_evidence(self):
        for action in ("labeled", "unlabeled"):
            with self.subTest(action=action):
                raw_body = label_body_for(action)
                event = parse_webhook(
                    {
                        "X-GitHub-Delivery": f"delivery-{action}",
                        "X-GitHub-Event": "pull_request",
                        "X-Hub-Signature-256": signature_for(raw_body, SECRET),
                    },
                    raw_body,
                    SECRET,
                )

                self.assertEqual(action, event.action)
                self.assertEqual(654, event.label_id)
                self.assertEqual("LA_label_654", event.label_node_id)
                self.assertEqual("hermes:merge-approved", event.label_name)
                self.assertEqual(987, event.sender_id)
                self.assertEqual("U_sender_987", event.sender_node_id)
                self.assertEqual("approver", event.sender_login)
                self.assertEqual("User", event.sender_type)
                self.assertEqual("2026-07-25T01:02:03Z", event.pull_updated_at)
                self.assertEqual(
                    hashlib.sha256(raw_body).hexdigest(), event.payload_sha256
                )

    def test_label_action_rejects_missing_or_invalid_signed_evidence(self):
        valid = json.loads(label_body_for())
        mutations = (
            lambda value: value["repository"].pop("id"),
            lambda value: value["installation"].update(id=True),
            lambda value: value["label"].update(id=0),
            lambda value: value["label"].pop("node_id"),
            lambda value: value["label"].update(name=""),
            lambda value: value["sender"].update(id=False),
            lambda value: value["sender"].pop("node_id"),
            lambda value: value["sender"].pop("login"),
            lambda value: value["sender"].pop("type"),
            lambda value: value["pull_request"].pop("updated_at"),
            lambda value: value["pull_request"].update(updated_at="not-a-time"),
            lambda value: value["pull_request"]["base"].update(sha="B" * 40),
            lambda value: value["pull_request"]["head"].update(sha="a" * 64),
            lambda value: value["pull_request"].update(
                updated_at="2026-07-25T01:02:03+00:00"
            ),
            lambda value: value["pull_request"].update(
                updated_at="2026-07-25T01:02:03.000Z"
            ),
            lambda value: value["pull_request"].update(
                updated_at="2026-07-25T01:02:03z"
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                payload = json.loads(json.dumps(valid))
                mutate(payload)
                raw_body = json.dumps(payload, separators=(",", ":")).encode()
                with self.assertRaisesRegex(InvalidPayload, "signed event evidence"):
                    parse_webhook(
                        {
                            "X-GitHub-Delivery": f"invalid-label-{index}",
                            "X-GitHub-Event": "pull_request",
                            "X-Hub-Signature-256": signature_for(raw_body, SECRET),
                        },
                        raw_body,
                        SECRET,
                    )

    def test_non_user_label_actor_is_preserved_as_signed_order_evidence(self):
        payload = json.loads(label_body_for(action="unlabeled"))
        payload["sender"].update(
            id=123,
            node_id="B_bot_123",
            login="example-app[bot]",
            type="Bot",
        )
        raw_body = json.dumps(payload, separators=(",", ":")).encode()

        event = parse_webhook(
            {
                "X-GitHub-Delivery": "delivery-bot-unlabeled",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": signature_for(raw_body, SECRET),
            },
            raw_body,
            SECRET,
        )

        self.assertEqual("Bot", event.sender_type)
        self.assertEqual(123, event.sender_id)

    def test_non_label_action_remains_compatible_without_label_evidence(self):
        raw_body = body_for(action="synchronize")
        event = parse_webhook(
            {
                "X-GitHub-Delivery": "delivery-synchronize",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": signature_for(raw_body, SECRET),
            },
            raw_body,
            SECRET,
        )

        self.assertEqual("synchronize", event.action)
        self.assertIsNone(event.label_id)
        self.assertIsNone(event.sender_id)
        self.assertIsNone(event.pull_updated_at)


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
