from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Any


HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
ZERO_DIGEST = "0" * 64
MAX_JSON_BYTES = 1_048_576
ASSET_NAMES = {"schema", "seccomp", "apparmor", "cosign_key", "command_profile"}
STATE_TRANSITIONS = {
    "INIT": {"PROBING", "FAILED"},
    "PROBING": {"PROBED", "FAILED"},
    "PROBED": {"RUNNING", "CLEANING", "FAILED"},
    "RUNNING": {"TERMINATED", "FAILED"},
    "TERMINATED": {"MEDIATED", "CLEANING", "FAILED"},
    "MEDIATED": {"CLEANING", "FAILED"},
    "FAILED": {"CLEANING"},
    "CLEANING": {"CLEANED", "FAILED_CLEANUP"},
    "CLEANED": set(),
    "FAILED_CLEANUP": set(),
}


class ValidationError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValidationError(
            f"{label} keys mismatch: missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be an object")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValidationError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _digest(value: Any, label: str, *, allow_zero: bool) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ValidationError(f"{label} must be lowercase sha256 hex")
    if not allow_zero and value == ZERO_DIGEST:
        raise ValidationError(f"{label} must not be the unprovisioned digest")
    return value


def read_canonical_json(path: Path, *, maximum_bytes: int = MAX_JSON_BYTES) -> tuple[dict[str, Any], bytes]:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"JSON input is not a regular file: {path}")
    if metadata.st_size > maximum_bytes:
        raise ValidationError(f"JSON input exceeds {maximum_bytes} bytes: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"JSON root must be an object: {path}")
    if raw != canonical_json(value):
        raise ValidationError(f"JSON bytes are not canonical: {path}")
    return value, raw


def resolve_w0_asset(w0_root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or len(relative) > 240:
        raise ValidationError("asset path is empty or too long")
    if relative.startswith("/") or "\\" in relative or "\x00" in relative:
        raise ValidationError("asset path must be a POSIX repository-relative path")
    parts = Path(relative).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ValidationError("asset path contains an unsafe component")
    root = w0_root.resolve(strict=True)
    candidate = root.joinpath(*parts)
    current = root
    for part in parts:
        current = current / part
        metadata = current.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValidationError(f"asset path contains a symlink: {relative}")
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents:
        raise ValidationError("asset path escapes W0 root")
    if not resolved.is_file():
        raise ValidationError("asset must be a regular file")
    return resolved


def sha256_file(path: Path, *, maximum_bytes: int = 16 * 1024 * 1024) -> str:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
        raise ValidationError(f"asset is not a bounded regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_command_profile(path: Path, expected_digest: str) -> dict[str, Any]:
    profile, raw = read_canonical_json(path)
    if sha256_bytes(raw) != expected_digest:
        raise ValidationError("command profile digest mismatch")
    _exact_keys(profile, {"schema", "profile_id", "commands"}, "command profile")
    if profile["schema"] != "candidate-command-profile/v1":
        raise ValidationError("unsupported command profile schema")
    if not isinstance(profile["profile_id"], str) or SAFE_ID.fullmatch(profile["profile_id"]) is None:
        raise ValidationError("invalid command profile id")
    commands = profile["commands"]
    if not isinstance(commands, list) or not 1 <= len(commands) <= 16:
        raise ValidationError("commands must contain 1..16 argv arrays")
    for command in commands:
        if (
            not isinstance(command, list)
            or not 1 <= len(command) <= 32
            or not all(isinstance(part, str) and 0 < len(part) <= 512 and "\x00" not in part for part in command)
        ):
            raise ValidationError("each command must be a bounded argv string array")
        if command[0] in {"sh", "bash", "dash", "zsh", "sudo", "env"}:
            raise ValidationError("shell and privilege launchers are forbidden")
    return profile


@dataclass(frozen=True)
class LoadedManifest:
    value: dict[str, Any]
    digest: str
    assets: dict[str, Path]
    command_profile: dict[str, Any]


def load_manifest(
    manifest_path: Path,
    *,
    w0_root: Path,
    expected_digest: str | None = None,
    require_provisioned: bool = False,
) -> LoadedManifest:
    expected_manifest = resolve_w0_asset(
        w0_root, "ci/candidate-sandbox/v1/manifest.json"
    )
    if manifest_path.resolve(strict=True) != expected_manifest:
        raise ValidationError("manifest must be the exact W0 profile manifest")
    manifest, raw = read_canonical_json(manifest_path)
    manifest_digest = sha256_bytes(raw)
    if expected_digest is not None and manifest_digest != _digest(expected_digest, "expected manifest digest", allow_zero=False):
        raise ValidationError("manifest digest mismatch")
    _exact_keys(
        manifest,
        {"schema", "profile_id", "provisioned", "runner", "runtime", "image", "assets", "security", "limits"},
        "manifest",
    )
    if manifest["schema"] != "sandbox-profile-manifest/v1" or manifest["profile_id"] != "candidate-sandbox/v1":
        raise ValidationError("unsupported sandbox manifest identity")
    if not isinstance(manifest["provisioned"], bool):
        raise ValidationError("provisioned must be boolean")
    provisioned = manifest["provisioned"]
    if require_provisioned and not provisioned:
        raise ValidationError("candidate sandbox profile is not provisioned")

    runner = _object(manifest["runner"], "runner")
    _exact_keys(runner, {"label", "architecture", "unprivileged_user", "uid", "subid_start", "subid_count"}, "runner")
    if runner["label"] != "ubuntu-24.04" or runner["architecture"] != "x86_64":
        raise ValidationError("candidate-sandbox/v1 is pinned to ubuntu-24.04 x86_64")
    if not isinstance(runner["unprivileged_user"], str) or re.fullmatch(r"[a-z][a-z0-9-]{2,31}", runner["unprivileged_user"]) is None:
        raise ValidationError("invalid unprivileged user")
    _integer(runner["uid"], 10_000, 60_000, "runner.uid")
    _integer(runner["subid_start"], 100_000, 2_000_000_000, "runner.subid_start")
    if runner["subid_count"] != 65_536:
        raise ValidationError("runner.subid_count must be 65536")

    runtime = _object(manifest["runtime"], "runtime")
    _exact_keys(runtime, {"podman", "crun", "cosign"}, "runtime")
    for name in ("podman", "crun", "cosign"):
        binary = _object(runtime[name], f"runtime.{name}")
        _exact_keys(binary, {"path", "sha256"}, f"runtime.{name}")
        if not isinstance(binary["path"], str) or not binary["path"].startswith("/") or "\x00" in binary["path"]:
            raise ValidationError(f"runtime.{name}.path must be absolute")
        _digest(binary["sha256"], f"runtime.{name}.sha256", allow_zero=not provisioned)

    assets_value = _object(manifest["assets"], "assets")
    if set(assets_value) != ASSET_NAMES:
        raise ValidationError("manifest assets must be the exact v1 asset set")
    assets: dict[str, Path] = {}
    for name, raw_asset in assets_value.items():
        asset = _object(raw_asset, f"assets.{name}")
        _exact_keys(asset, {"path", "sha256"}, f"assets.{name}")
        expected = _digest(asset["sha256"], f"assets.{name}.sha256", allow_zero=False)
        resolved = resolve_w0_asset(w0_root, asset["path"])
        if sha256_file(resolved) != expected:
            raise ValidationError(f"asset digest mismatch: {name}")
        assets[name] = resolved

    image = _object(manifest["image"], "image")
    _exact_keys(image, {"reference", "digest", "cosign_key_asset"}, "image")
    if image["cosign_key_asset"] != "cosign_key":
        raise ValidationError("image must use the W0 cosign key asset")
    if not isinstance(image["reference"], str) or len(image["reference"]) > 512:
        raise ValidationError("invalid image reference")
    if not isinstance(image["digest"], str) or not image["digest"].startswith("sha256:"):
        raise ValidationError("image digest must use sha256")
    image_hex = _digest(image["digest"][7:], "image.digest", allow_zero=not provisioned)
    if provisioned:
        if not image["reference"].endswith(f"@sha256:{image_hex}"):
            raise ValidationError("image reference is not digest pinned")
        if not assets["cosign_key"].read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise ValidationError("provisioned cosign key is not PEM public key bytes")
    elif image["reference"] != "UNPROVISIONED" or image_hex != ZERO_DIGEST:
        raise ValidationError("unprovisioned image fields must use explicit sentinels")

    security = _object(manifest["security"], "security")
    _exact_keys(
        security,
        {"apparmor_profile", "capabilities", "network", "no_new_privileges", "read_only_rootfs", "required_namespaces", "seccomp_probe_syscall"},
        "security",
    )
    if security["apparmor_profile"] != "dohwa-ci-candidate-v1":
        raise ValidationError("unexpected AppArmor profile")
    if security["capabilities"] != [] or security["network"] != "none":
        raise ValidationError("capabilities must be empty and network must be none")
    if security["no_new_privileges"] is not True or security["read_only_rootfs"] is not True:
        raise ValidationError("no-new-privileges and read-only rootfs are mandatory")
    if security["seccomp_probe_syscall"] != "unshare":
        raise ValidationError("unexpected seccomp deny probe")
    namespaces = security["required_namespaces"]
    if not isinstance(namespaces, list) or set(namespaces) != {"user", "pid", "mnt", "net", "ipc", "uts"} or len(namespaces) != 6:
        raise ValidationError("all six private namespaces are required exactly once")

    limits = _object(manifest["limits"], "limits")
    expected_limit_keys = {
        "cpu_quota", "memory_bytes", "swap_bytes", "pids", "tmpfs_bytes", "tmpfs_inodes",
        "timeout_seconds", "output_capture_bytes", "output_report_bytes", "file_bytes", "nofile", "nproc", "memlock_bytes",
    }
    _exact_keys(limits, expected_limit_keys, "limits")
    if not isinstance(limits["cpu_quota"], (int, float)) or isinstance(limits["cpu_quota"], bool) or not 0 < limits["cpu_quota"] <= 2:
        raise ValidationError("limits.cpu_quota must be in (0, 2]")
    _integer(limits["memory_bytes"], 128 * 1024 * 1024, 2 * 1024 * 1024 * 1024, "limits.memory_bytes")
    _integer(limits["swap_bytes"], 128 * 1024 * 1024, 2 * 1024 * 1024 * 1024, "limits.swap_bytes")
    _integer(limits["pids"], 16, 256, "limits.pids")
    _integer(limits["tmpfs_bytes"], 16 * 1024 * 1024, 1024 * 1024 * 1024, "limits.tmpfs_bytes")
    _integer(limits["tmpfs_inodes"], 256, 65_536, "limits.tmpfs_inodes")
    _integer(limits["timeout_seconds"], 30, 1200, "limits.timeout_seconds")
    _integer(limits["output_capture_bytes"], 65_536, 8 * 1024 * 1024, "limits.output_capture_bytes")
    _integer(limits["output_report_bytes"], 1024, 65_536, "limits.output_report_bytes")
    _integer(limits["file_bytes"], 65_536, 16 * 1024 * 1024, "limits.file_bytes")
    _integer(limits["nofile"], 64, 1024, "limits.nofile")
    _integer(limits["nproc"], 16, 256, "limits.nproc")
    _integer(limits["memlock_bytes"], 0, 1024 * 1024, "limits.memlock_bytes")
    if limits["swap_bytes"] != limits["memory_bytes"]:
        raise ValidationError("swap must equal memory to disable additional swap")
    if limits["output_report_bytes"] > limits["output_capture_bytes"]:
        raise ValidationError("reported output cannot exceed captured output")
    if limits["nproc"] > limits["pids"]:
        raise ValidationError("RLIMIT_NPROC cannot exceed cgroup pids limit")

    command_profile = validate_command_profile(
        assets["command_profile"], assets_value["command_profile"]["sha256"]
    )
    return LoadedManifest(manifest, manifest_digest, assets, command_profile)


def write_json_atomic(path: Path, value: dict[str, Any], *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def transition_state(path: Path, target: str, *, detail: str = "") -> dict[str, Any]:
    if target not in STATE_TRANSITIONS:
        raise ValidationError("unknown cleanup state")
    if path.exists():
        current, _ = read_canonical_json(path, maximum_bytes=65_536)
        _exact_keys(current, {"schema", "state", "sequence", "detail"}, "cleanup state")
        source = current["state"]
        sequence = _integer(current["sequence"], 0, 1_000_000, "cleanup state sequence")
    else:
        source = None
        sequence = -1
    if source is None:
        if target != "INIT":
            raise ValidationError("cleanup state must start at INIT")
    elif target not in STATE_TRANSITIONS.get(source, set()):
        raise ValidationError(f"invalid cleanup transition: {source} -> {target}")
    if not isinstance(detail, str) or len(detail) > 512 or any(ord(character) < 32 for character in detail):
        raise ValidationError("cleanup detail must be bounded printable text")
    value = {"schema": "candidate-cleanup-state/v1", "state": target, "sequence": sequence + 1, "detail": detail}
    write_json_atomic(path, value)
    return value


def mediate_output(
    stdout_path: Path,
    stderr_path: Path,
    *,
    capture_limit: int,
    report_limit: int,
) -> list[str]:
    if not 1024 <= report_limit <= capture_limit <= 8 * 1024 * 1024:
        raise ValidationError("invalid output mediation limits")
    rendered: list[str] = []
    for stream, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError(f"{stream} capture is not a regular file")
        if metadata.st_size > capture_limit:
            raise ValidationError(f"{stream} exceeded capture limit")
        with path.open("rb") as handle:
            handle.seek(max(0, metadata.st_size - report_limit))
            encoded = base64.b64encode(handle.read(report_limit)).decode("ascii")
        if not encoded:
            encoded = "-"
        chunks = [encoded[index:index + 768] for index in range(0, len(encoded), 768)]
        rendered.extend(
            f"DOHWA_CANDIDATE_LOG_V1 {stream} {index + 1}/{len(chunks)} {chunk}"
            for index, chunk in enumerate(chunks)
        )
    return rendered


def command_fence(lines: list[str]) -> list[str]:
    payload = "\n".join(lines)
    while True:
        token = secrets.token_hex(32)
        if token not in payload:
            return [f"::stop-commands::{token}", *lines, f"::{token}::"]
