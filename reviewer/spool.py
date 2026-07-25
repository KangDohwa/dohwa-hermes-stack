from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any


def _validate_attachment_name(name: str) -> str:
    if not name or name in {".", ".."} or Path(name).name != name:
        raise ValueError("attachment name must be a plain filename")
    return name


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_bytes_atomic(path: Path, payload: bytes) -> None:
    _validate_attachment_name(path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_json(path: Path, *, maximum_bytes: int = 8_000_000) -> dict[str, Any]:
    if path.stat().st_size > maximum_bytes:
        raise ValueError("spool payload is too large")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("spool payload must be a JSON object")
    return value


def read_attachment(
    directory: Path,
    name: str,
    *,
    expected_size: int,
    maximum_bytes: int,
) -> bytes:
    safe_name = _validate_attachment_name(name)
    if expected_size < 0 or expected_size > maximum_bytes:
        raise ValueError("attachment size is outside the allowed range")
    descriptor = os.open(
        directory / safe_name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("attachment must be a regular file")
        if metadata.st_size != expected_size or metadata.st_size > maximum_bytes:
            raise ValueError("attachment size does not match request")
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("attachment ended before expected size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("attachment exceeds expected size")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
