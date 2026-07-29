from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "compose.reviewer.yaml"


class ReviewerComposeSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
        cls.services = cls.compose["services"]

    def test_no_service_publishes_host_ports(self) -> None:
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertNotIn("ports", service)
                self.assertNotIn("network_mode", service) if name in {
                    "review-orchestrator",
                    "cloudflared",
                } else None

    def test_all_services_have_container_hardening(self) -> None:
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertTrue(service["read_only"])
                self.assertEqual(["ALL"], service["cap_drop"])
                self.assertIn("no-new-privileges:true", service["security_opt"])
                self.assertGreater(service["pids_limit"], 0)
                self.assertGreater(service["cpus"], 0)
                self.assertRegex(str(service["mem_limit"]), r"^\d+[mg]$")

    def test_orchestrator_secrets_are_read_only_and_scoped(self) -> None:
        volumes = self.services["review-orchestrator"]["volumes"]
        secret_root = "${REVIEWER_SECRET_ROOT:?set REVIEWER_SECRET_ROOT}/"
        secret_mounts = [mount for mount in volumes if str(mount).startswith(secret_root)]

        self.assertEqual(2, len(secret_mounts))
        self.assertTrue(all(str(mount).endswith(":ro") for mount in secret_mounts))

        cloudflare_mounts = self.services["cloudflared"].get("volumes", [])
        self.assertEqual(1, len(cloudflare_mounts))
        self.assertIn("cloudflare-tunnel-token", str(cloudflare_mounts[0]))
        self.assertTrue(str(cloudflare_mounts[0]).endswith(":ro"))

        for name in ("review-analyzer", "review-executor"):
            with self.subTest(service=name):
                self.assertFalse(
                    any(secret_root in str(mount) for mount in self.services[name].get("volumes", []))
                )

    def test_tunnel_token_is_only_in_cloudflared_environment(self) -> None:
        cloudflared = self.services["cloudflared"]
        self.assertNotIn("environment", cloudflared)
        self.assertIn("--token-file", cloudflared["command"])
        self.assertIn("--loglevel", cloudflared["command"])

        for name, service in self.services.items():
            if name == "cloudflared":
                continue
            with self.subTest(service=name):
                environment_text = str(service.get("environment", {})) + str(service.get("command", []))
                self.assertNotIn("TUNNEL_TOKEN", environment_text)
                self.assertNotIn("CLOUDFLARE_TUNNEL_TOKEN", environment_text)

    def test_runtime_env_is_not_mounted_into_any_container(self) -> None:
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertFalse(
                    any("runtime.env" in str(mount) for mount in service.get("volumes", []))
                )

    def test_executor_has_no_network_and_analyzer_is_separate(self) -> None:
        self.assertEqual("none", self.services["review-executor"]["network_mode"])
        analyzer_networks = self.services["review-analyzer"]["networks"]
        self.assertEqual(["analyzer-egress"], analyzer_networks)
        self.assertNotIn("reviewer-ingress", analyzer_networks)
        self.assertNotIn("reviewer-egress", analyzer_networks)

    def test_internal_ingress_network_separates_tunnel_and_origin(self) -> None:
        self.assertTrue(self.compose["networks"]["reviewer-ingress"]["internal"])
        for name in ("review-orchestrator", "cloudflared"):
            with self.subTest(service=name):
                self.assertIn("reviewer-ingress", self.services[name]["networks"])

    def test_executor_checkout_is_ephemeral_and_has_no_extra_output_mount(self) -> None:
        mounts = {
            mount["target"]: mount
            for mount in self.services["review-executor"]["volumes"]
        }
        self.assertNotIn("/work", mounts)
        self.assertNotIn("/results", mounts)
        work_tmpfs = next(
            value
            for value in self.services["review-executor"]["tmpfs"]
            if value.startswith("/work:")
        )
        self.assertIn("size=768m", work_tmpfs)
        self.assertIn("nosuid", work_tmpfs)
        self.assertIn("nodev", work_tmpfs)

    def test_untrusted_executor_cannot_write_other_worker_spool(self) -> None:
        analyzer_volumes = str(self.services["review-analyzer"]["volumes"])
        executor_volumes = str(self.services["review-executor"]["volumes"])
        self.assertIn("spool/analyzer", analyzer_volumes)
        self.assertNotIn("spool/executor", analyzer_volumes)
        self.assertIn("spool/executor", executor_volumes)
        self.assertNotIn("spool/analyzer", executor_volumes)
        self.assertEqual("0:0", self.services["review-executor"]["user"])
        self.assertEqual(
            {"DAC_OVERRIDE", "SETUID", "SETGID", "KILL"},
            set(self.services["review-executor"]["cap_add"]),
        )

    def test_runtime_is_comment_only_and_scoped_to_public_target(self) -> None:
        environment = self.services["review-orchestrator"]["environment"]
        self.assertEqual("${REVIEWER_MODE:-comment}", environment["REVIEWER_MODE"])
        self.assertEqual("${REVIEWER_APPROVER_IDS:-}", environment["REVIEWER_APPROVER_IDS"])
        self.assertEqual(
            "${REVIEWER_APPROVAL_LABEL:-hermes:merge-approved}",
            environment["REVIEWER_APPROVAL_LABEL"],
        )
        self.assertEqual(
            "${REVIEWER_REPOSITORIES:-KangDohwa/dohwa-hermes-stack}",
            environment["REVIEWER_REPOSITORIES"],
        )
        self.assertEqual(
            "${GITHUB_REPOSITORY_ALLOWLIST:-KangDohwa/dohwa-hermes-stack}",
            environment["GITHUB_REPOSITORY_ALLOWLIST"],
        )

    def test_dockerfiles_drop_root_and_have_expected_entrypoints(self) -> None:
        expectations = {
            "Dockerfile.orchestrator": 'CMD ["uvicorn", "reviewer.orchestrator:app"',
            "Dockerfile.analyzer": 'ENTRYPOINT ["/opt/hermes/.venv/bin/python", "-m", "reviewer.analyzer"]',
            "Dockerfile.executor": 'ENTRYPOINT ["python", "-m", "reviewer.executor"]',
        }
        for filename, expected in expectations.items():
            with self.subTest(dockerfile=filename):
                contents = (ROOT / "reviewer" / filename).read_text(encoding="utf-8")
                self.assertIn("USER 1001:1001", contents)
                self.assertIn(expected, contents)

        executor = (ROOT / "reviewer" / "Dockerfile.executor").read_text(encoding="utf-8")
        self.assertIn("requirements.executor.txt", executor)

        analyzer = (ROOT / "reviewer" / "Dockerfile.analyzer").read_text(encoding="utf-8")
        self.assertIn(
            "FROM nousresearch/hermes-agent:v2026.7.20@"
            "sha256:f7b35053268f532f98955195c909f15a230470fbcbdacaa9fdecb95707dad04a",
            analyzer,
        )
        self.assertNotIn("discord-strict-shared-mentions-presence", analyzer)


class DockerBuildContextTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = [
            line.strip()
            for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        cls.line_set = set(cls.lines)

    def test_context_is_deny_by_default(self) -> None:
        self.assertIn("*", self.line_set)
        self.assertIn("!Dockerfile.hermes", self.line_set)
        self.assertIn("!reviewer/**", self.line_set)
        self.assertIn("!overlays/discord_presence.py", self.line_set)
        self.assertIn("!patches/discord-dynamic-presence.patch", self.line_set)
        self.assertNotIn("!patches/discord-strict-shared-mentions.patch", self.line_set)

    def test_candidate_probe_is_only_ci_build_context_file(self) -> None:
        fence = [
            "!ci/",
            "ci/**",
            "!ci/candidate-sandbox/",
            "ci/candidate-sandbox/**",
            "!ci/candidate-sandbox/v1/",
            "ci/candidate-sandbox/v1/**",
            "!ci/candidate-sandbox/v1/probe_runtime.py",
        ]
        start = self.lines.index("!ci/")
        self.assertEqual(
            fence,
            self.lines[start : start + len(fence)],
        )

    def test_docker_context_contains_only_candidate_probe_under_ci(self) -> None:
        if shutil.which("docker") is None:
            self.skipTest("Docker CLI unavailable; ordered fence contract checked separately")
        if subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode:
            self.skipTest("Docker daemon unavailable; ordered fence contract checked separately")

        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            dockerfile = temporary_path / "Dockerfile"
            output = temporary_path / "output"
            dockerfile.write_text("FROM scratch\nCOPY . /context/\n", encoding="utf-8")
            output.mkdir()
            subprocess.run(
                [
                    "docker",
                    "build",
                    "--no-cache",
                    "--output",
                    f"type=local,dest={output}",
                    "--file",
                    str(dockerfile),
                    str(ROOT),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            context = output / "context"
            context_files = [
                path.relative_to(context)
                for path in context.rglob("*")
                if path.is_file()
            ]
            ci_files = sorted(
                path.as_posix() for path in context_files if path.parts[0] == "ci"
            )
            self.assertEqual(
                ["ci/candidate-sandbox/v1/probe_runtime.py"],
                ci_files,
            )
            for name in ("data", "workspace", "backups", ".git", ".github"):
                with self.subTest(path=name):
                    self.assertFalse((context / name).exists())
            for path in context_files:
                with self.subTest(path=path):
                    self.assertFalse({"spool", "sessions", "tokens"} & set(path.parts))
                    self.assertNotIn(path.name, {".env", "auth.json", "token"})
                    self.assertFalse(path.name.startswith(".env."))
                    self.assertNotIn(
                        path.suffix,
                        {".db", ".key", ".log", ".pem", ".sqlite", ".sqlite3", ".token"},
                    )

    def test_candidate_useradd_is_absolute_under_restricted_path(self) -> None:
        contents = (
            ROOT / "ci" / "candidate-sandbox" / "v1" / "Containerfile"
        ).read_text(encoding="utf-8")
        path_value = next(
            line.split()[0]
            for line in contents.splitlines()
            if line.strip().startswith("PATH=")
        )
        self.assertEqual("PATH=/usr/local/bin:/usr/bin:/bin", path_value)
        self.assertIn("&& /usr/sbin/useradd --uid 65532", contents)

    def test_runtime_and_vcs_state_are_excluded(self) -> None:
        for pattern in ("data/", "workspace/", "backups/", ".git/", ".github/"):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, self.line_set)

    def test_credentials_and_generated_files_are_excluded(self) -> None:
        for pattern in (
            "**/.env",
            "**/.env.*",
            "**/*.env",
            "**/*.key",
            "**/*.pem",
            "**/*.token",
            "**/__pycache__/",
            "**/*.py[cod]",
        ):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, self.line_set)


class GatewayImageContractTests(unittest.TestCase):
    def test_gateway_base_is_pinned_to_v2026_7_20_manifest(self) -> None:
        dockerfile = (ROOT / "Dockerfile.hermes").read_text(encoding="utf-8")
        self.assertIn(
            "FROM nousresearch/hermes-agent:v2026.7.20@"
            "sha256:f7b35053268f532f98955195c909f15a230470fbcbdacaa9fdecb95707dad04a",
            dockerfile,
        )
        self.assertNotIn("discord-strict-shared-mentions", dockerfile)

    def test_gateway_compose_uses_presence_only_image(self) -> None:
        compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
        gateway = compose["services"]["gateway"]
        self.assertEqual(
            "${HERMES_IMAGE:-dohwa-hermes-stack:local}", gateway["image"]
        )
        environment = gateway.get("environment", {})
        self.assertFalse(any(key.startswith("HERMES_SHARED_") for key in environment))
        self.assertNotIn("HERMES_DISCORD_BOT_USER_ID", environment)
        self.assertNotIn("HERMES_DISCORD_BOT_ROLE_ID", environment)
        self.assertFalse(
            any("shared_channel_policy" in str(mount) for mount in gateway["volumes"])
        )

    def test_presence_patch_targets_v2026_7_20_sources(self) -> None:
        patch = (ROOT / "patches" / "discord-dynamic-presence.patch").read_text(
            encoding="utf-8"
        )
        self.assertIn("index f59e006..", patch)
        self.assertIn("index 215ae0d..", patch)
        self.assertIn("gateway_tool_complete_callback", patch)
        self.assertIn("DiscordPresenceController", patch)
        self.assertIn(
            "msg = await channel.send(**send_kwargs)\n"
            "             view._message = msg  # store for on_timeout expiration editing\n"
            "+            try:\n"
            "+                self._presence.watch_approval(session_key)",
            patch,
        )


if __name__ == "__main__":
    unittest.main()
