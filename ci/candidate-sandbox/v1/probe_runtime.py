#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import resource
import signal
import socket
import sys


CHECK_NAMES = {
    "apparmor_deny", "apparmor_label", "capabilities_empty", "cgroup_cpu",
    "cgroup_memory", "cgroup_pids", "environment_scrubbed", "network_blocked",
    "no_new_privileges", "private_namespaces", "read_only_rootfs", "rlimit_core",
    "rlimit_fsize", "rlimit_memlock", "rlimit_nofile", "rlimit_nproc",
    "seccomp_deny", "seccomp_mode", "tmpfs_bytes", "tmpfs_inodes",
}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _status() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def _mount(path: str) -> tuple[set[str], set[str]]:
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        if fields[4] == path:
            return set(fields[5].split(",")), set(right.split()[2].split(","))
    return set(), set()


def _size(value: str) -> int | None:
    multiplier = 1
    if value.endswith("k"):
        multiplier, value = 1024, value[:-1]
    elif value.endswith("m"):
        multiplier, value = 1024 * 1024, value[:-1]
    elif value.endswith("g"):
        multiplier, value = 1024 * 1024 * 1024, value[:-1]
    try:
        return int(value) * multiplier
    except ValueError:
        return None


def _option(options: set[str], name: str) -> str | None:
    prefix = name + "="
    for option in options:
        if option.startswith(prefix):
            return option[len(prefix):]
    return None


def _cgroup_value(name: str) -> str | None:
    try:
        return (Path("/sys/fs/cgroup") / name).read_text(encoding="ascii").strip()
    except OSError:
        return None


def _seccomp_denied() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = libc.unshare(0x10000000)
    return result == -1 and ctypes.get_errno() in {errno.EPERM, errno.EACCES}


def _apparmor_denied() -> bool:
    try:
        Path("/work/.apparmor-probe").write_text("denied", encoding="ascii")
    except PermissionError:
        return True
    except OSError:
        return False
    return False


def _network_blocked() -> bool:
    forbidden_environment = any(
        key.upper().endswith("_PROXY") or key.upper() in {"ALL_PROXY", "NO_PROXY"}
        for key in os.environ
    )
    if forbidden_environment:
        return False
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError:
        return True
    try:
        probe.settimeout(0.1)
        return probe.connect_ex(("1.1.1.1", 443)) != 0
    finally:
        probe.close()


def _fsize_exhausted(expected: int) -> bool:
    path = Path("/tmp/fsize-probe")
    try:
        with path.open("wb", buffering=0) as handle:
            chunk = b"0" * 65_536
            for _ in range(expected // len(chunk) + 2):
                handle.write(chunk)
    except OSError as exc:
        return exc.errno == errno.EFBIG
    finally:
        path.unlink(missing_ok=True)
    return False


def _nofile_exhausted(expected: int) -> bool:
    descriptors: list[int] = []
    failed = False
    try:
        for _ in range(expected + 8):
            descriptors.append(os.open("/dev/null", os.O_RDONLY))
    except OSError as exc:
        failed = exc.errno == errno.EMFILE
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return failed


def _pids_exhausted(expected: int) -> bool:
    children: list[int] = []
    failed = False
    try:
        for _ in range(expected + 8):
            try:
                child = os.fork()
            except OSError as exc:
                failed = exc.errno == errno.EAGAIN
                break
            if child == 0:
                signal.pause()
                os._exit(0)
            children.append(child)
    finally:
        for child in children:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for child in children:
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
    return failed


def _tmpfs_bytes_exhausted(expected: int) -> bool:
    directory = Path("/work/byte-probe")
    directory.mkdir()
    chunk = b"0" * 65_536
    failed = False
    created: list[Path] = []
    try:
        for index in range(expected // len(chunk) + 64):
            path = directory / str(index)
            created.append(path)
            try:
                path.write_bytes(chunk)
            except OSError as exc:
                failed = exc.errno in {errno.ENOSPC, errno.EDQUOT}
                break
    finally:
        for path in created:
            path.unlink(missing_ok=True)
        directory.rmdir()
    return failed


def _tmpfs_inodes_exhausted(expected: int) -> bool:
    directory = Path("/work/inode-probe")
    directory.mkdir()
    failed = False
    created: list[Path] = []
    try:
        for index in range(expected + 64):
            path = directory / str(index)
            try:
                path.touch(exist_ok=False)
                created.append(path)
            except OSError as exc:
                failed = exc.errno in {errno.ENOSPC, errno.EDQUOT}
                break
    finally:
        for path in created:
            path.unlink(missing_ok=True)
        directory.rmdir()
    return failed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-apparmor", required=True)
    parser.add_argument("--memory", required=True, type=int)
    parser.add_argument("--pids", required=True, type=int)
    parser.add_argument("--tmpfs-bytes", required=True, type=int)
    parser.add_argument("--tmpfs-inodes", required=True, type=int)
    parser.add_argument("--file-bytes", required=True, type=int)
    parser.add_argument("--nofile", required=True, type=int)
    parser.add_argument("--nproc", required=True, type=int)
    parser.add_argument("--memlock", required=True, type=int)
    parser.add_argument("--host-namespace", action="append", default=[])
    arguments = parser.parse_args()

    status = _status()
    expected_namespaces = dict(item.split("=", 1) for item in arguments.host_namespace)
    private_namespaces = len(expected_namespaces) == 6 and all(
        str(os.stat(f"/proc/self/ns/{name}").st_ino) != inode
        for name, inode in expected_namespaces.items()
        if name in {"user", "pid", "mnt", "net", "ipc", "uts"}
    )
    root_mount, _ = _mount("/")
    _, work_options = _mount("/work")
    work_size = _size(_option(work_options, "size") or "")
    try:
        work_inodes = int(_option(work_options, "nr_inodes") or "-1")
    except ValueError:
        work_inodes = -1
    apparmor_label = Path("/proc/self/attr/current").read_text(encoding="utf-8").strip()
    forbidden_prefixes = ("GITHUB_", "ACTIONS_", "RUNNER_", "CI_")
    allowed_environment = {"HOME", "TMPDIR", "LANG", "LC_ALL", "PATH", "HOSTNAME", "container"}
    environment_scrubbed = all(
        key in allowed_environment and not key.startswith(forbidden_prefixes)
        and not key.upper().endswith("_PROXY")
        for key in os.environ
    )
    cgroup_memory = _cgroup_value("memory.max") == str(arguments.memory)
    cgroup_memory = cgroup_memory and _cgroup_value("memory.swap.max") in {"0", str(arguments.memory)}
    cgroup_pids = _cgroup_value("pids.max") == str(arguments.pids)
    cpu = _cgroup_value("cpu.max")
    cgroup_cpu = isinstance(cpu, str) and len(cpu.split()) == 2 and cpu.split()[0].isdigit() and cpu.split()[1].isdigit()

    checks = {
        "apparmor_deny": _apparmor_denied(),
        "apparmor_label": arguments.expected_apparmor in apparmor_label,
        "capabilities_empty": int(status.get("CapEff", "1"), 16) == 0,
        "cgroup_cpu": cgroup_cpu,
        "cgroup_memory": cgroup_memory,
        "cgroup_pids": cgroup_pids and _pids_exhausted(arguments.pids),
        "environment_scrubbed": environment_scrubbed,
        "network_blocked": _network_blocked(),
        "no_new_privileges": status.get("NoNewPrivs") == "1",
        "private_namespaces": private_namespaces,
        "read_only_rootfs": "ro" in root_mount,
        "rlimit_core": resource.getrlimit(resource.RLIMIT_CORE) == (0, 0),
        "rlimit_fsize": resource.getrlimit(resource.RLIMIT_FSIZE) == (arguments.file_bytes, arguments.file_bytes) and _fsize_exhausted(arguments.file_bytes),
        "rlimit_memlock": resource.getrlimit(resource.RLIMIT_MEMLOCK) == (arguments.memlock, arguments.memlock),
        "rlimit_nofile": resource.getrlimit(resource.RLIMIT_NOFILE) == (arguments.nofile, arguments.nofile) and _nofile_exhausted(arguments.nofile),
        "rlimit_nproc": resource.getrlimit(resource.RLIMIT_NPROC) == (arguments.nproc, arguments.nproc),
        "seccomp_deny": _seccomp_denied(),
        "seccomp_mode": status.get("Seccomp") == "2",
        "tmpfs_bytes": work_size == arguments.tmpfs_bytes and _tmpfs_bytes_exhausted(arguments.tmpfs_bytes),
        "tmpfs_inodes": work_inodes == arguments.tmpfs_inodes and _tmpfs_inodes_exhausted(arguments.tmpfs_inodes),
    }
    if set(checks) != CHECK_NAMES:
        return 1
    sys.stdout.buffer.write(_canonical({"schema": "candidate-runtime-probe/v1", "checks": checks}))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
