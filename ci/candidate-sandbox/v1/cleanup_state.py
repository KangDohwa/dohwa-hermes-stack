#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from sandboxlib import ValidationError, transition_state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--to", required=True)
    parser.add_argument("--detail", default="")
    arguments = parser.parse_args()
    try:
        result = transition_state(arguments.state, arguments.to, detail=arguments.detail)
    except (OSError, ValidationError) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}, separators=(",", ":")))
        return 1
    print(json.dumps({"ok": True, "state": result["state"], "sequence": result["sequence"]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
