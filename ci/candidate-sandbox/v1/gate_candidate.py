#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
import time

from sandboxlib import ValidationError, load_manifest, read_canonical_json, transition_state


REQUEST_ID = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SAFE_CONTEXT = re.compile(r"^[A-Za-z0-9._:/-]{1,256}$")


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
            raise ValidationError("invalid immutable candidate context")
        loaded = load_manifest(
            arguments.manifest, w0_root=arguments.w0_root,
            expected_digest=arguments.expected_digest, require_provisioned=True,
        )
        metadata = arguments.receipt.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValidationError("probe receipt ownership or mode is unsafe")
        receipt, _ = read_canonical_json(arguments.receipt, maximum_bytes=65_536)
        expected = {
            "schema", "request_id", "manifest_sha256", "command_profile_sha256",
            "descriptor_digest", "candidate_sha", "workflow_sha", "review_context_id",
            "probe_sha256", "nonce", "created_at_epoch", "status",
        }
        if set(receipt) != expected:
            raise ValidationError("probe receipt keys mismatch")
        if (
            receipt["schema"] != "candidate-host-probe-receipt/v1"
            or receipt["status"] != "passed"
            or receipt["request_id"] != arguments.request_id
            or receipt["descriptor_digest"] != arguments.descriptor_digest
            or receipt["candidate_sha"] != arguments.candidate_sha
            or receipt["workflow_sha"] != arguments.workflow_sha
            or receipt["review_context_id"] != arguments.review_context_id
            or receipt["manifest_sha256"] != loaded.digest
            or receipt["command_profile_sha256"] != loaded.value["assets"]["command_profile"]["sha256"]
            or not isinstance(receipt["created_at_epoch"], int)
            or not 0 <= int(time.time()) - receipt["created_at_epoch"] <= 300
            or not isinstance(receipt["nonce"], str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt["nonce"]) is None
            or not isinstance(receipt["probe_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt["probe_sha256"]) is None
        ):
            raise ValidationError("probe receipt is stale or not context bound")
        # Stage 1 local/static foundation deliberately has no exact-M import path yet.
        # A valid probe receipt is necessary but never sufficient to execute candidate code.
        transition_state(arguments.state, "FAILED", detail="exact-M source pipeline is not implemented")
        print("CANDIDATE_SOURCE_PIPELINE_UNAVAILABLE")
        return 1
    except (OSError, ValidationError):
        try:
            transition_state(arguments.state, "FAILED", detail="candidate gate failed closed")
        except (OSError, ValidationError):
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
