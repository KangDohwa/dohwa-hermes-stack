#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

from sandboxlib import ValidationError, load_manifest, transition_state


REQUEST_ID = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")


def _safe_resource(path: Path, trusted_root: Path, name: str) -> Path:
    trusted = trusted_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved.parent != trusted or resolved.name != name or path.is_symlink():
        raise ValidationError("cleanup resource path is outside trusted run root")
    return resolved


def _kill_cgroup_for_pid(process_id: int) -> None:
    if process_id <= 1:
        return
    try:
        lines = Path(f"/proc/{process_id}/cgroup").read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3 or fields[:2] != ["0", ""]:
            continue
        cgroup = (Path("/sys/fs/cgroup") / fields[2].lstrip("/")).resolve()
        root = Path("/sys/fs/cgroup").resolve()
        if root not in cgroup.parents:
            raise ValidationError("container cgroup escapes v2 root")
        kill = cgroup / "cgroup.kill"
        if kill.exists():
            kill.write_text("1", encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--w0-root", required=True, type=Path)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--trusted-root", required=True, type=Path)
    parser.add_argument("--storage-root", required=True, type=Path)
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    arguments = parser.parse_args()
    failed = False
    try:
        if REQUEST_ID.fullmatch(arguments.request_id) is None:
            raise ValidationError("invalid request id")
        loaded = load_manifest(arguments.manifest, w0_root=arguments.w0_root, expected_digest=arguments.expected_digest)
        storage = _safe_resource(arguments.storage_root, arguments.trusted_root, "storage")
        runroot = _safe_resource(arguments.run_root, arguments.trusted_root, "runroot")
        transition_state(arguments.state, "CLEANING", detail="trusted teardown started")
        prefix = [loaded.value["runtime"]["podman"]["path"], "--root", str(storage), "--runroot", str(runroot), "--runtime", loaded.value["runtime"]["crun"]["path"]]
        listed = subprocess.run(
            [*prefix, "ps", "--all", "--quiet", "--filter", f"label=io.dohwa.ci_request_id={arguments.request_id}"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=30, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        if listed.returncode != 0 or len(listed.stdout) > 65_536:
            raise ValidationError("could not enumerate run containers")
        identifiers = [line.decode("ascii") for line in listed.stdout.splitlines()]
        if any(CONTAINER_ID.fullmatch(identifier) is None for identifier in identifiers):
            raise ValidationError("Podman returned an invalid container id")
        for identifier in identifiers:
            inspected = subprocess.run(
                [*prefix, "inspect", identifier, "--format", "{{.State.Pid}}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                check=False, timeout=15, env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            if inspected.returncode == 0 and inspected.stdout.strip().isdigit():
                _kill_cgroup_for_pid(int(inspected.stdout.strip()))
            subprocess.run([*prefix, "kill", identifier], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15)
            removed = subprocess.run([*prefix, "rm", "--force", identifier], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)
            if removed.returncode != 0:
                raise ValidationError("container removal failed")
        verify = subprocess.run(
            [*prefix, "ps", "--all", "--quiet"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=30,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        if verify.returncode != 0 or verify.stdout.strip():
            raise ValidationError("rootless run storage still contains containers")
    except (OSError, ValueError, subprocess.SubprocessError):
        failed = True
    finally:
        for resource in (arguments.storage_root, arguments.run_root):
            try:
                safe = _safe_resource(resource, arguments.trusted_root, resource.name)
                shutil.rmtree(safe)
            except (OSError, ValidationError):
                failed = True
        try:
            transition_state(
                arguments.state,
                "FAILED_CLEANUP" if failed else "CLEANED",
                detail="cleanup could not prove zero residual state" if failed else "zero containers and run storage removed",
            )
        except (OSError, ValidationError):
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
