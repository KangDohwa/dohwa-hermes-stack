from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any

from reviewer.policy import load_policies
from reviewer.safe_archive import extract_github_tarball
from reviewer.spool import read_attachment, read_json, write_json_atomic


TEST_UID = 65534
TEST_GID = 65534
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
ATTACHMENT_NAME = re.compile(r"^[1-9][0-9]*-[0-9a-f]{40}\.tar\.gz$")


class ProcessSweepError(RuntimeError):
    pass


def _drop_test_privileges() -> None:
    os.setgroups([])
    os.setgid(TEST_GID)
    os.setuid(TEST_UID)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))


def _run_command(
    command: tuple[str, ...],
    *,
    checkout: Path,
    environment: dict[str, str],
    timeout: int,
    drop_privileges: bool,
    sweep_test_uid: bool,
) -> tuple[int, str]:
    with tempfile.TemporaryFile() as output_file:
        process = subprocess.Popen(
            list(command),
            cwd=checkout,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=output_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            preexec_fn=_drop_test_privileges if drop_privileges else None,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            output = _read_output_tail(output_file)
            raise subprocess.TimeoutExpired(command, timeout, output=output) from exc
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                if sweep_test_uid:
                    _sweep_test_uid_processes()
        return process.returncode, _read_output_tail(output_file)


def _read_output_tail(output_file: Any, maximum: int = 20_000) -> str:
    output_file.flush()
    size = output_file.seek(0, os.SEEK_END)
    output_file.seek(max(0, size - maximum))
    return output_file.read(maximum).decode("utf-8", errors="replace")


def _test_uid_processes(proc_root: Path = Path("/proc")) -> list[int]:
    processes: list[int] = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        state = ""
        uids: tuple[int, ...] = ()
        for line in status.splitlines():
            if line.startswith("State:"):
                state = line.split(maxsplit=1)[1] if len(line.split(maxsplit=1)) == 2 else ""
            elif line.startswith("Uid:"):
                try:
                    uids = tuple(int(value) for value in line.split()[1:5])
                except ValueError:
                    uids = ()
        if state.startswith("Z"):
            continue
        if TEST_UID in uids:
            processes.append(int(entry.name))
    return processes


def _sweep_test_uid_processes(
    *,
    proc_root: Path = Path("/proc"),
    maximum_rounds: int = 50,
) -> None:
    for _ in range(maximum_rounds):
        processes = _test_uid_processes(proc_root)
        if not processes:
            return
        for process_id in processes:
            try:
                os.kill(process_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise ProcessSweepError(
                    f"permission denied terminating isolated test process {process_id}"
                ) from exc
        time.sleep(0.02)
    remaining = _test_uid_processes(proc_root)
    if remaining:
        raise ProcessSweepError(
            f"could not terminate isolated test processes: {remaining[:8]}"
        )


def _archive_from_request(payload: dict[str, Any], attachment_root: Path) -> bytes:
    value = payload.get("archive")
    if not isinstance(value, dict):
        raise ValueError("archive metadata must be an object")
    name = value.get("name")
    size = value.get("size")
    digest = value.get("sha256")
    if not isinstance(name, str):
        raise ValueError("archive name is required")
    if not isinstance(size, int) or isinstance(size, bool):
        raise ValueError("archive size must be an integer")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("archive sha256 must be lowercase hexadecimal")
    archive = read_attachment(
        attachment_root,
        name,
        expected_size=size,
        maximum_bytes=MAX_ARCHIVE_BYTES,
    )
    if not hmac.compare_digest(hashlib.sha256(archive).hexdigest(), digest):
        raise ValueError("archive sha256 does not match request")
    return archive


def _make_writable_paths(checkout: Path, paths: tuple[str, ...]) -> None:
    resolved_checkout = checkout.resolve()
    for relative in paths:
        writable = checkout / relative
        resolved = writable.resolve()
        if resolved == resolved_checkout or resolved_checkout not in resolved.parents:
            raise ValueError("writable test path escapes checkout")
        if writable.exists() and not writable.is_dir():
            raise ValueError("writable test path is not a directory")
        writable.mkdir(parents=True, exist_ok=True)
        writable.chmod(0o777)


def _validate_spool_directory(path: Path) -> None:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"executor spool path is not a directory: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o007:
        raise RuntimeError(f"executor spool directory is accessible to test UID: {path}")


def _cleanup_orphaned_attachments(
    incoming: Path,
    *,
    minimum_age_seconds: int = 60 * 60,
    now: float | None = None,
) -> None:
    current_time = time.time() if now is None else now
    for attachment in incoming.glob("*.tar.gz"):
        if ATTACHMENT_NAME.fullmatch(attachment.name) is None:
            continue
        request = incoming / f"{attachment.name[:-7]}.json"
        if request.exists():
            continue
        try:
            metadata = attachment.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode):
            continue
        if current_time - metadata.st_mtime < minimum_age_seconds:
            continue
        attachment.unlink(missing_ok=True)


def execute(
    payload: dict[str, Any],
    *,
    work_root: Path,
    attachment_root: Path,
    policy_path: Path,
    drop_privileges: bool = True,
    sweep_test_uid: bool = False,
) -> dict[str, Any]:
    if drop_privileges and os.geteuid() != 0:
        raise RuntimeError("executor must start as root to isolate test subprocesses")
    repository = str(payload.get("repository") or "")
    policies = load_policies(policy_path)
    if repository not in policies:
        raise ValueError("repository is not allowlisted")
    policy = policies[repository]
    requested = payload.get("commands")
    if not isinstance(requested, list):
        raise ValueError("commands must be an array")
    commands = [tuple(str(part) for part in command) for command in requested if isinstance(command, list)]
    if tuple(commands) != policy.test_commands:
        raise ValueError("commands do not exactly match policy")
    timeout = min(max(int(payload.get("timeout_seconds") or 1), 1), policy.timeout_minutes * 60)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": "/tmp/pycache",
        "HOME": "/tmp/reviewer-home",
    }
    work_root.mkdir(parents=True, exist_ok=True)
    if drop_privileges:
        work_root.chmod(0o755)
    checkout = Path(tempfile.mkdtemp(prefix="checkout-", dir=work_root))
    checkout.chmod(0o755)
    try:
        archive = _archive_from_request(payload, attachment_root)
        extract_github_tarball(archive, checkout)
        _make_writable_paths(checkout, policy.writable_test_paths)
        if sweep_test_uid:
            _sweep_test_uid_processes()
        results: list[dict[str, str]] = []
        deadline = time.monotonic() + timeout
        for command in commands:
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                returncode, command_output = _run_command(
                    command,
                    checkout=checkout,
                    environment=environment,
                    timeout=remaining,
                    drop_privileges=drop_privileges,
                    sweep_test_uid=sweep_test_uid,
                )
                output = command_output[-20_000:]
                results.append({
                    "command": " ".join(command),
                    "result": "passed" if returncode == 0 else "failed",
                    "detail": output,
                })
                if returncode != 0:
                    break
            except subprocess.TimeoutExpired as exc:
                output = str(exc.stdout or "")[-20_000:]
                results.append({"command": " ".join(command), "result": "failed", "detail": "timeout\n" + output})
                break
        return {"tests": results, "all_passed": len(results) == len(commands) and all(item["result"] == "passed" for item in results)}
    finally:
        try:
            if sweep_test_uid:
                _sweep_test_uid_processes()
        finally:
            shutil.rmtree(checkout)


def run() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("executor must run as root and drop test subprocess privileges")
    spool = Path(os.environ.get("REVIEWER_SPOOL", "/var/lib/hermes-reviewer/spool"))
    incoming = spool / "executor" / "in"
    outgoing = spool / "executor" / "out"
    incoming.mkdir(parents=True, exist_ok=True)
    outgoing.mkdir(parents=True, exist_ok=True)
    _validate_spool_directory(incoming)
    _validate_spool_directory(outgoing)
    work_root = Path(os.environ.get("REVIEWER_WORK_ROOT", "/work"))
    policy_path = Path(os.environ.get("REVIEWER_POLICY", "/app/reviewer/policies/central.yml"))
    while True:
        _cleanup_orphaned_attachments(incoming)
        for request_path in sorted(incoming.glob("*.json")):
            output = outgoing / request_path.name
            attachment_path = incoming / f"{request_path.stem}.tar.gz"
            if output.exists():
                attachment_path.unlink(missing_ok=True)
                request_path.unlink(missing_ok=True)
                continue
            fatal_isolation_error: ProcessSweepError | None = None
            try:
                payload = read_json(request_path)
                archive_value = payload.get("archive")
                if (
                    not isinstance(archive_value, dict)
                    or archive_value.get("name") != attachment_path.name
                ):
                    raise ValueError("archive name is not bound to request filename")
                response = {
                    "ok": True,
                    "result": execute(
                        payload,
                        work_root=work_root,
                        attachment_root=incoming,
                        policy_path=policy_path,
                        sweep_test_uid=True,
                    ),
                }
            except ProcessSweepError as exc:
                fatal_isolation_error = exc
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:2_000]}
            except Exception as exc:
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:2_000]}
            finally:
                attachment_path.unlink(missing_ok=True)
            write_json_atomic(output, response)
            os.chmod(output, 0o644)
            request_path.unlink(missing_ok=True)
            if fatal_isolation_error is not None:
                raise fatal_isolation_error
        time.sleep(1)


if __name__ == "__main__":
    run()
