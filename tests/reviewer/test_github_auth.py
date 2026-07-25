import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from unittest import mock
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from reviewer.github_auth import GitHubAppAuth, GitHubAuthError


class FakeResponse:
    def __init__(self, payload, status=200, headers=None):
        self.payload = json.dumps(payload).encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload

    def getcode(self):
        return self.status


def decode_segment(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


class GitHubAppAuthTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.key_path = Path(self.tempdir.name) / "github-app.pem"
        self.key_path.write_bytes(pem)
        self.now = 1_721_779_200.0

    def make_auth(self, urlopen=None):
        return GitHubAppAuth(
            12345,
            self.key_path,
            ["example/example-repo"],
            urlopen=urlopen or (lambda *args, **kwargs: None),
            clock=lambda: self.now,
        )

    def test_app_jwt_is_rs256_signed_and_has_bounded_lifetime(self):
        token = self.make_auth().create_app_jwt()
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        header = json.loads(decode_segment(encoded_header))
        payload = json.loads(decode_segment(encoded_payload))

        self.assertEqual(header, {"alg": "RS256", "typ": "JWT"})
        self.assertEqual(payload["iss"], "12345")
        self.assertEqual(payload["iat"], int(self.now) - 60)
        self.assertEqual(payload["exp"], int(self.now) + 540)
        self.private_key.public_key().verify(
            decode_segment(encoded_signature),
            f"{encoded_header}.{encoded_payload}".encode("ascii"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def test_repository_allowlist_is_case_insensitive_and_fails_closed(self):
        auth = self.make_auth()
        self.assertEqual(
            auth.require_allowed_repository("EXAMPLE/EXAMPLE-REPO"),
            "example/example-repo",
        )
        with self.assertRaises(GitHubAuthError):
            auth.require_allowed_repository("example/unapproved")
        with self.assertRaises(ValueError):
            auth.require_allowed_repository("invalid")

    def test_installation_is_auto_discovered_and_token_is_cached(self):
        calls = []

        def urlopen(api_request, timeout):
            calls.append(api_request)
            if api_request.full_url.endswith("/repos/example/example-repo/installation"):
                return FakeResponse({"id": 9876})
            if api_request.full_url.endswith(
                "/app/installations/9876/access_tokens"
            ):
                return FakeResponse(
                    {
                        "token": "not-a-real-installation-token",
                        "expires_at": "2024-07-24T01:00:00Z",
                    },
                    status=201,
                )
            self.fail(f"unexpected URL: {api_request.full_url}")

        auth = self.make_auth(urlopen)
        first = auth.installation_token_for_repository("example/example-repo")
        second = auth.installation_token_for_repository("example/example-repo")

        self.assertEqual(first, "not-a-real-installation-token")
        self.assertEqual(second, first)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].method, "GET")
        self.assertEqual(calls[1].method, "POST")
        self.assertEqual(json.loads(calls[1].data), {})
        for call in calls:
            self.assertTrue(call.get_header("Authorization").startswith("Bearer "))
            self.assertNotIn("not-a-real-installation-token", str(call.header_items()))

    def test_token_is_refreshed_before_expiry(self):
        token_count = 0

        def urlopen(api_request, timeout):
            nonlocal token_count
            if api_request.full_url.endswith("/installation"):
                return FakeResponse({"id": 9876})
            token_count += 1
            expires = datetime.fromtimestamp(
                self.now + 600, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z")
            return FakeResponse(
                {"token": f"not-a-real-token-{token_count}", "expires_at": expires},
                status=201,
            )

        auth = self.make_auth(urlopen)
        self.assertEqual(
            auth.installation_token_for_repository("example/example-repo"), "not-a-real-token-1"
        )
        self.now += 301
        self.assertEqual(
            auth.installation_token_for_repository("example/example-repo"), "not-a-real-token-2"
        )

    def test_missing_private_key_fails_without_network(self):
        auth = GitHubAppAuth(
            12345,
            Path(self.tempdir.name) / "missing.pem",
            ["example/example-repo"],
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(GitHubAuthError, "unable to load"):
            auth.create_app_jwt()

    def test_disallowed_repository_does_not_make_network_request(self):
        called = False

        def urlopen(*args, **kwargs):
            nonlocal called
            called = True

        auth = self.make_auth(urlopen)
        with self.assertRaises(GitHubAuthError):
            auth.installation_token_for_repository("Other/repository")
        self.assertFalse(called)

    def test_environment_requires_explicit_allowlist(self):
        with mock.patch.dict(os.environ, {"GITHUB_APP_ID": "123"}, clear=True):
            with self.assertRaisesRegex(GitHubAuthError, "GITHUB_REPOSITORY_ALLOWLIST"):
                GitHubAppAuth.from_environment()


if __name__ == "__main__":
    unittest.main()
