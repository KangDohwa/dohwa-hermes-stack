from pathlib import Path
import tempfile
import unittest

from reviewer.config import Settings


class ConfigTests(unittest.TestCase):
    def test_rejects_repo_outside_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key = base / "key.pem"
            secret = base / "secret"
            key.write_text("not-a-real-private-key", encoding="utf-8")
            secret.write_text("not-a-real-webhook-secret", encoding="utf-8")
            env = {
                "GITHUB_APP_ID": "123",
                "GITHUB_APP_SLUG": "example-reviewer",
                "GITHUB_APP_PRIVATE_KEY_FILE": str(key),
                "GITHUB_WEBHOOK_SECRET_FILE": str(secret),
                "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/0/not-a-real-webhook-token",
                "GITHUB_REPOSITORY_ALLOWLIST": "example/example-repo",
                "REVIEWER_REPOSITORIES": "example/example-repo,example/other-repo",
            }
            with self.assertRaisesRegex(ValueError, "allowlist"):
                Settings.from_env(env)

    def test_requires_explicit_repository_allowlists(self):
        env = {
            "GITHUB_APP_ID": "123",
            "GITHUB_APP_SLUG": "example-reviewer",
        }
        with self.assertRaisesRegex(ValueError, "GITHUB_REPOSITORY_ALLOWLIST"):
            Settings.from_env(env)

    def test_rejects_non_slug_app_identity(self):
        env = {
            "GITHUB_APP_ID": "123",
            "GITHUB_APP_SLUG": "Example Reviewer",
        }
        with self.assertRaisesRegex(ValueError, "lowercase GitHub App slug"):
            Settings.from_env(env)


if __name__ == "__main__":
    unittest.main()
