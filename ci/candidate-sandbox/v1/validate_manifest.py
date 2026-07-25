#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from sandboxlib import ValidationError, load_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--w0-root", required=True, type=Path)
    parser.add_argument("--expected-digest")
    parser.add_argument("--require-provisioned", action="store_true")
    arguments = parser.parse_args()
    try:
        loaded = load_manifest(
            arguments.manifest,
            w0_root=arguments.w0_root,
            expected_digest=arguments.expected_digest,
            require_provisioned=arguments.require_provisioned,
        )
    except (OSError, ValidationError) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}, separators=(",", ":")))
        return 1
    print(json.dumps({
        "ok": True,
        "manifest_sha256": loaded.digest,
        "profile_id": loaded.value["profile_id"],
        "provisioned": loaded.value["provisioned"],
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
