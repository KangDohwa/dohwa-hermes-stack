from __future__ import annotations

import io
from pathlib import Path
import shutil
import tarfile


def extract_github_tarball(raw: bytes, destination: Path) -> None:
    total = 0
    count = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive.getmembers():
            count += 1
            if count > 20_000:
                raise ValueError("archive has too many entries")
            parts = Path(member.name).parts
            if len(parts) < 2:
                continue
            relative = Path(*parts[1:])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe archive path")
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError("archive contains a link or special file")
            total += member.size
            if total > 500 * 1024 * 1024:
                raise ValueError("expanded archive exceeds size limit")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("archive member could not be read")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as handle:
                shutil.copyfileobj(source, handle, length=1024 * 1024)
