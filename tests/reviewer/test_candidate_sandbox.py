from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "ci" / "candidate-sandbox" / "v1"
MANIFEST = SANDBOX / "manifest.json"
WORKFLOW = ROOT / ".github" / "workflows" / "dohwa-candidate-ci.yml"
SPEC = importlib.util.spec_from_file_location("candidate_sandboxlib", SANDBOX / "sandboxlib.py")
assert SPEC is not None and SPEC.loader is not None
sandboxlib = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sandboxlib
SPEC.loader.exec_module(sandboxlib)


class ManifestTests(unittest.TestCase):
    def copy_w0(self, temporary: str) -> Path:
        root = Path(temporary)
        shutil.copytree(ROOT / "ci", root / "ci")
        return root

    def mutate(self, root: Path, callback) -> Path:
        path = root / "ci" / "candidate-sandbox" / "v1" / "manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        callback(value)
        path.write_bytes(sandboxlib.canonical_json(value))
        return path

    def test_committed_manifest_is_canonical_and_static_valid(self):
        loaded = sandboxlib.load_manifest(MANIFEST, w0_root=ROOT)
        self.assertEqual("candidate-sandbox/v1", loaded.value["profile_id"])
        self.assertFalse(loaded.value["provisioned"])
        self.assertEqual(
            MANIFEST.read_bytes(),
            sandboxlib.canonical_json(json.loads(MANIFEST.read_text(encoding="utf-8"))),
        )
        self.assertEqual(
            {"schema", "seccomp", "apparmor", "cosign_key", "command_profile"},
            set(loaded.assets),
        )

    def test_unprovisioned_manifest_fails_closed_for_runtime(self):
        with self.assertRaisesRegex(sandboxlib.ValidationError, "not provisioned"):
            sandboxlib.load_manifest(MANIFEST, w0_root=ROOT, require_provisioned=True)

    def test_manifest_must_be_exact_w0_path_and_canonical_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            external = Path(temporary) / "manifest.json"
            external.write_bytes(MANIFEST.read_bytes())
            with self.assertRaisesRegex(sandboxlib.ValidationError, "exact W0"):
                sandboxlib.load_manifest(external, w0_root=ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_w0(temporary)
            path = root / "ci" / "candidate-sandbox" / "v1" / "manifest.json"
            path.write_bytes(path.read_bytes() + b" \n")
            with self.assertRaisesRegex(sandboxlib.ValidationError, "not canonical"):
                sandboxlib.load_manifest(path, w0_root=root)

    def test_unknown_keys_and_unsafe_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_w0(temporary)
            path = self.mutate(root, lambda value: value.update({"unexpected": True}))
            with self.assertRaisesRegex(sandboxlib.ValidationError, "keys mismatch"):
                sandboxlib.load_manifest(path, w0_root=root)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_w0(temporary)
            path = self.mutate(
                root,
                lambda value: value["limits"].update({"swap_bytes": value["limits"]["memory_bytes"] + 1}),
            )
            with self.assertRaisesRegex(sandboxlib.ValidationError, "swap must equal"):
                sandboxlib.load_manifest(path, w0_root=root)

    def test_asset_digest_traversal_and_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_w0(temporary)
            seccomp = root / "ci" / "candidate-sandbox" / "v1" / "seccomp.json"
            seccomp.write_bytes(seccomp.read_bytes() + b"x")
            with self.assertRaisesRegex(sandboxlib.ValidationError, "digest mismatch"):
                sandboxlib.load_manifest(root / "ci/candidate-sandbox/v1/manifest.json", w0_root=root)
        with self.assertRaisesRegex(sandboxlib.ValidationError, "unsafe component"):
            sandboxlib.resolve_w0_asset(ROOT, "ci/../compose.yaml")
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_w0(temporary)
            seccomp = root / "ci" / "candidate-sandbox" / "v1" / "seccomp.json"
            target = root / "target"
            target.write_bytes(seccomp.read_bytes())
            seccomp.unlink()
            seccomp.symlink_to(target)
            with self.assertRaisesRegex(sandboxlib.ValidationError, "symlink"):
                sandboxlib.load_manifest(root / "ci/candidate-sandbox/v1/manifest.json", w0_root=root)

    def test_command_profile_forbids_shell_launchers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copy_w0(temporary)
            profile = root / "ci" / "profiles" / "hermes-v1.json"
            value = json.loads(profile.read_text(encoding="utf-8"))
            value["commands"] = [["sh", "-c", "true"]]
            profile.write_bytes(sandboxlib.canonical_json(value))
            profile_digest = sandboxlib.sha256_file(profile)
            path = self.mutate(
                root,
                lambda manifest: manifest["assets"]["command_profile"].update({"sha256": profile_digest}),
            )
            with self.assertRaisesRegex(sandboxlib.ValidationError, "shell"):
                sandboxlib.load_manifest(path, w0_root=root)

    def test_schema_and_security_assets_are_strict(self):
        schema = json.loads((SANDBOX / "sandbox-profile.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            {"schema", "profile_id", "provisioned", "runner", "runtime", "image", "assets", "security", "limits"},
            set(schema["required"]),
        )
        seccomp = json.loads((SANDBOX / "seccomp.json").read_text(encoding="utf-8"))
        denied = set(seccomp["syscalls"][0]["names"])
        self.assertTrue({"mount", "unshare", "setns", "bpf", "ptrace"}.issubset(denied))
        apparmor = (SANDBOX / "apparmor.profile").read_text(encoding="utf-8")
        self.assertIn("profile dohwa-ci-candidate-v1", apparmor)
        self.assertIn("deny network", apparmor)
        self.assertIn("deny /work/.apparmor-probe", apparmor)


class StateAndOutputTests(unittest.TestCase):
    def test_cleanup_state_machine_is_atomic_and_rejects_skips(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"
            sandboxlib.transition_state(state, "INIT")
            sandboxlib.transition_state(state, "PROBING")
            sandboxlib.transition_state(state, "PROBED")
            sandboxlib.transition_state(state, "RUNNING")
            sandboxlib.transition_state(state, "TERMINATED")
            sandboxlib.transition_state(state, "CLEANING")
            final = sandboxlib.transition_state(state, "CLEANED")
            self.assertEqual(6, final["sequence"])
            self.assertEqual(0, stat.S_IMODE(state.stat().st_mode) & 0o077)
            with self.assertRaisesRegex(sandboxlib.ValidationError, "invalid cleanup transition"):
                sandboxlib.transition_state(state, "RUNNING")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(sandboxlib.ValidationError, "start at INIT"):
                sandboxlib.transition_state(Path(temporary) / "state.json", "RUNNING")

    def test_output_is_bounded_base64_and_command_fenced(self):
        with tempfile.TemporaryDirectory() as temporary:
            stdout = Path(temporary) / "stdout"
            stderr = Path(temporary) / "stderr"
            stdout.write_bytes(b"::error::owned\n\x1b[31mred")
            stderr.write_bytes(b"::set-output name=x::owned")
            lines = sandboxlib.mediate_output(stdout, stderr, capture_limit=65_536, report_limit=4096)
            rendered = "\n".join(sandboxlib.command_fence(lines))
            self.assertNotIn("::error::owned", rendered)
            self.assertNotIn("::set-output", rendered)
            self.assertIn("DOHWA_CANDIDATE_LOG_V1 stdout", rendered)
            self.assertTrue(rendered.startswith("::stop-commands::"))

    def test_oversize_or_nonregular_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            stdout = Path(temporary) / "stdout"
            stderr = Path(temporary) / "stderr"
            stdout.write_bytes(b"x" * 2049)
            stderr.write_bytes(b"")
            with self.assertRaisesRegex(sandboxlib.ValidationError, "capture limit"):
                sandboxlib.mediate_output(stdout, stderr, capture_limit=2048, report_limit=1024)
            stdout.unlink()
            stdout.mkdir()
            with self.assertRaisesRegex(sandboxlib.ValidationError, "regular file"):
                sandboxlib.mediate_output(stdout, stderr, capture_limit=2048, report_limit=1024)


class FailClosedProbeTests(unittest.TestCase):
    def test_host_probe_refuses_unprovisioned_profile_before_runtime_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            completed = subprocess.run(
                [
                    sys.executable, str(SANDBOX / "probe_host.py"),
                    "--manifest", str(MANIFEST), "--w0-root", str(ROOT),
                    "--expected-digest", sandboxlib.sha256_file(MANIFEST),
                    "--request-id", "a" * 64, "--descriptor-digest", "b" * 64,
                    "--candidate-sha", "c" * 40, "--workflow-sha", "d" * 40,
                    "--review-context-id", "review-context:test", "--trusted-root", str(root),
                    "--storage-root", str(root / "storage"), "--run-root", str(root / "runroot"),
                    "--receipt", str(root / "receipt.json"), "--state", str(root / "state.json"),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
            )
            self.assertEqual(1, completed.returncode)
            self.assertNotIn(b"/usr/bin/podman", completed.stdout + completed.stderr)
            state, _ = sandboxlib.read_canonical_json(root / "state.json")
            self.assertEqual("FAILED", state["state"])
            self.assertFalse((root / "receipt.json").exists())

    def test_containerfile_is_digest_pinned_and_nonroot(self):
        contents = (SANDBOX / "Containerfile").read_text(encoding="utf-8")
        self.assertRegex(contents.splitlines()[0], r"^FROM .+@sha256:[0-9a-f]{64}$")
        self.assertIn("USER 65532:65532", contents)
        self.assertIn("probe-runtime", contents)


class WorkflowTests(unittest.TestCase):
    def test_workflow_has_minimal_permissions_and_no_external_actions(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        workflow = yaml.safe_load(text)
        self.assertEqual("read", workflow["permissions"]["contents"])
        self.assertEqual("none", workflow["permissions"]["id-token"])
        job = workflow["jobs"]["candidate-foundation"]
        self.assertEqual("ubuntu-24.04", job["runs-on"])
        self.assertEqual("read", job["permissions"]["contents"])
        self.assertEqual("none", job["permissions"]["id-token"])
        self.assertNotIn("uses:", text)
        self.assertIn('echo "::add-mask::$auth_header"', text)
        self.assertIn("http.extraheader=AUTHORIZATION: basic $auth_header", text)
        self.assertIn("unset FETCH_TOKEN auth_header", text)
        self.assertNotIn("AUTHORIZATION: bearer $FETCH_TOKEN", text)
        for forbidden in ("pull_request_target", "git push", "updateRefs", "actions/cache", "upload-artifact"):
            self.assertNotIn(forbidden, text)

    def test_workflow_dispatch_contract_and_run_name_are_exact(self):
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        triggers = workflow.get("on", workflow.get(True))
        self.assertEqual(
            {"base_sha", "head_sha", "merge_descriptor", "review_context_id", "ci_request_id"},
            set(triggers["workflow_dispatch"]["inputs"]),
        )
        self.assertEqual(
            "dohwa-candidate-ci:${{ inputs.ci_request_id }}",
            workflow["run-name"],
        )
        text = WORKFLOW.read_text(encoding="utf-8")
        for forbidden_input in (
            "inputs.workflow_sha", "inputs.manifest_sha256", "inputs.candidate_sha",
            "inputs.source_archive_sha256", "inputs.descriptor_sha256",
        ):
            self.assertNotIn(forbidden_input, text)

    def test_candidate_gate_is_after_mandatory_provisioned_probe(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(text.index("--require-provisioned"), text.index("probe_host.py"))
        self.assertLess(text.index("probe_host.py"), text.index("gate_candidate.py"))
        self.assertIn("CANDIDATE_SOURCE_PIPELINE_UNAVAILABLE", (SANDBOX / "gate_candidate.py").read_text(encoding="utf-8"))
        self.assertIn("MergeDescriptor.from_canonical_bytes", text)
        self.assertIn('descriptor.workflow_sha != os.environ["GITHUB_SHA"]', text)
        self.assertIn('manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()', text)
        self.assertIn('--expected-digest "$manifest_sha256"', text)


if __name__ == "__main__":
    unittest.main()
