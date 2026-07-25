#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import resource
import secrets
import subprocess
import sys
import tempfile
import time

from sandboxlib import (
    ValidationError,
    canonical_json,
    load_manifest,
    sha256_file,
    transition_state,
    write_json_atomic,
)


REQUEST_ID = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SAFE_CONTEXT = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")
RUNTIME_CHECKS = {
    "apparmor_deny", "apparmor_label", "capabilities_empty", "cgroup_cpu",
    "cgroup_memory", "cgroup_pids", "environment_scrubbed", "network_blocked",
    "no_new_privileges", "private_namespaces", "read_only_rootfs", "rlimit_core",
    "rlimit_fsize", "rlimit_memlock", "rlimit_nofile", "rlimit_nproc",
    "seccomp_deny", "seccomp_mode", "tmpfs_bytes", "tmpfs_inodes",
}


def _bounded_run(command: list[str], *, timeout: int, maximum_output: int = 1_048_576) -> bytes:
    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (maximum_output, maximum_output))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

    with tempfile.TemporaryFile() as output:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            preexec_fn=limits,
        )
        if completed.returncode != 0:
            raise ValidationError("trusted runtime command failed")
        size = output.seek(0, os.SEEK_END)
        if size > maximum_output:
            raise ValidationError("trusted runtime command exceeded output limit")
        output.seek(0)
        return output.read()


def _subid_has_exact(path: Path, user: str, start: int, count: int) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return False
    matches = [line.split(":") for line in lines if line.startswith(f"{user}:")]
    return matches == [[user, str(start), str(count)]]


def _current_cgroup() -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            relative = fields[2].lstrip("/")
            root = Path("/sys/fs/cgroup")
            candidate = (root / relative).resolve()
            if candidate == root or root not in candidate.parents:
                raise ValidationError("current cgroup escapes cgroup v2 root")
            return candidate
    raise ValidationError("unified cgroup v2 membership is unavailable")


def _apparmor_enforced(profile: str) -> bool:
    try:
        profiles = Path("/sys/kernel/security/apparmor/profiles").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return f"{profile} (enforce)" in profiles.splitlines()


def _podman_prefix(loaded, storage_root: Path, run_root: Path) -> list[str]:
    runtime = loaded.value["runtime"]
    return [
        runtime["podman"]["path"],
        "--root", str(storage_root),
        "--runroot", str(run_root),
        "--runtime", runtime["crun"]["path"],
    ]


def _validate_root(path: Path, trusted_root: Path, expected_name: str) -> Path:
    root = trusted_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved.parent != root or resolved.name != expected_name or path.is_symlink():
        raise ValidationError(f"{expected_name} must be an exact direct child of trusted root")
    return resolved


def _active_runtime_probe(loaded, request_id: str, storage_root: Path, run_root: Path) -> dict[str, object]:
    value = loaded.value
    limits = value["limits"]
    security = value["security"]
    runtime = value["runtime"]
    image = value["image"]
    prefix = _podman_prefix(loaded, storage_root, run_root)

    _bounded_run([
        runtime["cosign"]["path"], "verify", "--key", str(loaded.assets["cosign_key"]),
        "--output", "json", image["reference"],
    ], timeout=120)
    _bounded_run([*prefix, "pull", "--quiet", image["reference"]], timeout=180)
    inspect = json.loads(_bounded_run([
        *prefix, "image", "inspect", image["reference"], "--format", "json",
    ], timeout=30).decode("utf-8"))
    if not isinstance(inspect, list) or len(inspect) != 1:
        raise ValidationError("image inspect result is ambiguous")
    repo_digests = inspect[0].get("RepoDigests") if isinstance(inspect[0], dict) else None
    if not isinstance(repo_digests, list) or not any(
        isinstance(item, str) and item.endswith("@" + image["digest"]) for item in repo_digests
    ):
        raise ValidationError("pulled image digest mismatch")

    host_namespaces = []
    for namespace in security["required_namespaces"]:
        host_namespaces.append(f"{namespace}={os.stat('/proc/self/ns/' + namespace).st_ino}")
    name = f"dohwa-probe-{request_id[:16]}"
    command = [
        *prefix, "run", "--rm", "--name", name,
        "--label", f"io.dohwa.ci_request_id={request_id}",
        "--pull", "never", "--network", "none", "--ipc", "private", "--pid", "private",
        "--uts", "private", "--cgroupns", "private", "--userns", "private",
        "--read-only", "--image-volume", "ignore", "--cap-drop", "all",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={loaded.assets['seccomp']}",
        "--security-opt", f"apparmor={security['apparmor_profile']}",
        "--http-proxy=false", "--memory", str(limits["memory_bytes"]),
        "--memory-swap", str(limits["swap_bytes"]), "--pids-limit", str(limits["pids"]),
        "--cpus", str(limits["cpu_quota"]), "--user", "65532:65532",
        "--tmpfs", f"/work:rw,nosuid,nodev,size={limits['tmpfs_bytes']},nr_inodes={limits['tmpfs_inodes']},mode=0700,notmpcopyup",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits['tmpfs_bytes']},nr_inodes={limits['tmpfs_inodes']},mode=0700,notmpcopyup",
        "--ulimit", "core=0:0", "--ulimit", f"fsize={limits['file_bytes']}:{limits['file_bytes']}",
        "--ulimit", f"nofile={limits['nofile']}:{limits['nofile']}",
        "--ulimit", f"nproc={limits['nproc']}:{limits['nproc']}",
        "--ulimit", f"memlock={limits['memlock_bytes']}:{limits['memlock_bytes']}",
        image["reference"], "/usr/bin/env", "-i", "HOME=/tmp/home", "TMPDIR=/tmp",
        "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin",
        "/opt/dohwa/bin/probe-runtime", "--expected-apparmor", security["apparmor_profile"],
        "--memory", str(limits["memory_bytes"]), "--pids", str(limits["pids"]),
        "--tmpfs-bytes", str(limits["tmpfs_bytes"]), "--tmpfs-inodes", str(limits["tmpfs_inodes"]),
        "--file-bytes", str(limits["file_bytes"]), "--nofile", str(limits["nofile"]),
        "--nproc", str(limits["nproc"]), "--memlock", str(limits["memlock_bytes"]),
        *sum((["--host-namespace", item] for item in host_namespaces), []),
    ]
    try:
        raw = _bounded_run(command, timeout=min(limits["timeout_seconds"], 180), maximum_output=65_536)
    finally:
        subprocess.run([*prefix, "kill", name], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15)
        subprocess.run([*prefix, "rm", "--force", name], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15)
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("runtime probe did not return strict JSON") from exc
    if raw != canonical_json(result) or not isinstance(result, dict) or set(result) != {"schema", "checks"}:
        raise ValidationError("runtime probe response is not canonical v1")
    checks = result.get("checks")
    if result.get("schema") != "candidate-runtime-probe/v1" or not isinstance(checks, dict):
        raise ValidationError("runtime probe response identity mismatch")
    if set(checks) != RUNTIME_CHECKS or any(checks[name] is not True for name in RUNTIME_CHECKS):
        raise ValidationError("one or more effective isolation probes failed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--w0-root", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--descriptor-digest", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--review-context-id", required=True)
    parser.add_argument("--trusted-root", required=True, type=Path)
    parser.add_argument("--storage-root", required=True, type=Path)
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if (
            REQUEST_ID.fullmatch(arguments.request_id) is None
            or REQUEST_ID.fullmatch(arguments.descriptor_digest) is None
            or SHA1.fullmatch(arguments.candidate_sha) is None
            or SHA1.fullmatch(arguments.workflow_sha) is None
            or SAFE_CONTEXT.fullmatch(arguments.review_context_id) is None
        ):
            raise ValidationError("invalid immutable probe context")
        transition_state(arguments.state, "INIT")
        transition_state(arguments.state, "PROBING")
        loaded = load_manifest(
            arguments.manifest, w0_root=arguments.w0_root,
            expected_digest=arguments.expected_digest, require_provisioned=True,
        )
        runner = loaded.value["runner"]
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValidationError("host platform does not match manifest")
        if os.geteuid() == 0 or getpass.getuser() != runner["unprivileged_user"]:
            raise ValidationError("probe must run as the dedicated unprivileged user")
        account = pwd.getpwnam(runner["unprivileged_user"])
        if account.pw_uid != runner["uid"] or account.pw_gid == 0:
            raise ValidationError("dedicated account identity mismatch")
        if not _subid_has_exact(Path("/etc/subuid"), account.pw_name, runner["subid_start"], runner["subid_count"]):
            raise ValidationError("subuid mapping mismatch")
        if not _subid_has_exact(Path("/etc/subgid"), account.pw_name, runner["subid_start"], runner["subid_count"]):
            raise ValidationError("subgid mapping mismatch")
        trusted_root = arguments.trusted_root.resolve(strict=True)
        storage_root = _validate_root(arguments.storage_root, trusted_root, "storage")
        run_root = _validate_root(arguments.run_root, trusted_root, "runroot")
        for name, binary in loaded.value["runtime"].items():
            binary_path = Path(binary["path"])
            if binary_path.is_symlink() or sha256_file(binary_path, maximum_bytes=256 * 1024 * 1024) != binary["sha256"]:
                raise ValidationError(f"{name} binary identity mismatch")
        cgroup = _current_cgroup()
        controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="utf-8").split())
        if not {"cpu", "memory", "pids"}.issubset(controllers):
            raise ValidationError("required cgroup v2 controllers are unavailable")
        if not (cgroup / "cgroup.kill").exists() or not os.access(cgroup / "cgroup.kill", os.W_OK):
            raise ValidationError("delegated writable cgroup.kill is unavailable")
        if not _apparmor_enforced(loaded.value["security"]["apparmor_profile"]):
            raise ValidationError("AppArmor profile is not loaded in enforce mode")
        info_raw = _bounded_run([*_podman_prefix(loaded, storage_root, run_root), "info", "--format", "json"], timeout=30)
        info = json.loads(info_raw.decode("utf-8"))
        host = info.get("host") if isinstance(info, dict) else None
        security = host.get("security") if isinstance(host, dict) else None
        oci_runtime = host.get("ociRuntime") if isinstance(host, dict) else None
        if not isinstance(security, dict) or security.get("rootless") is not True or security.get("seccompEnabled") is not True or security.get("apparmorEnabled") is not True:
            raise ValidationError("Podman rootless security features are ineffective")
        if host.get("cgroupVersion") != "v2" or not isinstance(oci_runtime, dict) or oci_runtime.get("name") != "crun":
            raise ValidationError("Podman cgroup/runtime identity mismatch")
        active = _active_runtime_probe(loaded, arguments.request_id, storage_root, run_root)
        receipt = {
            "schema": "candidate-host-probe-receipt/v1",
            "request_id": arguments.request_id,
            "descriptor_digest": arguments.descriptor_digest,
            "candidate_sha": arguments.candidate_sha,
            "workflow_sha": arguments.workflow_sha,
            "review_context_id": arguments.review_context_id,
            "manifest_sha256": loaded.digest,
            "command_profile_sha256": loaded.value["assets"]["command_profile"]["sha256"],
            "probe_sha256": hashlib.sha256(canonical_json(active)).hexdigest(),
            "nonce": secrets.token_hex(32),
            "created_at_epoch": int(time.time()),
            "status": "passed",
        }
        write_json_atomic(arguments.receipt, receipt)
        transition_state(arguments.state, "PROBED", detail="all effective probes passed")
        print(json.dumps({"ok": True, "manifest_sha256": loaded.digest}, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        try:
            transition_state(arguments.state, "FAILED", detail="host probe failed closed")
        except (OSError, ValidationError):
            pass
        print('{"error":"CANDIDATE_RUNTIME_ISOLATION_UNAVAILABLE","ok":false}')
        return 1


if __name__ == "__main__":
    sys.exit(main())
