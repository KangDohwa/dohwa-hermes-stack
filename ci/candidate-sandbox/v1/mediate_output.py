#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from sandboxlib import ValidationError, command_fence, mediate_output, transition_state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdout", required=True, type=Path)
    parser.add_argument("--stderr", required=True, type=Path)
    parser.add_argument("--capture-limit", required=True, type=int)
    parser.add_argument("--report-limit", required=True, type=int)
    parser.add_argument("--state", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        lines = mediate_output(
            arguments.stdout,
            arguments.stderr,
            capture_limit=arguments.capture_limit,
            report_limit=arguments.report_limit,
        )
        for line in command_fence(lines):
            print(line)
        transition_state(arguments.state, "MEDIATED", detail="bounded output encoded")
    except (OSError, ValidationError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
