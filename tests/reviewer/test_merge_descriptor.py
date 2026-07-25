from dataclasses import replace
import json
import unittest

from reviewer.merge_descriptor import CIRequestInputs, MergeDescriptor


BASE = "1" * 40
HEAD = "2" * 40
MERGE_BASE = "3" * 40
TREE = "4" * 40
WORKFLOW = "5" * 40
GOLDEN_CANDIDATE = "dd398ae1a24644e810f3b43f6e7a9a7c99c48a77"
GOLDEN_DIGEST = "f8d31a5af9d1049c9ec6a23e095f8734117bcb37c1531f363332015484060df9"
GOLDEN_INPUT_DIGEST = "d55c5985886b74672a1e17d11c5a3c38ca026780f9c3fcb896c8cd227c225cfb"


def descriptor(**overrides):
    values = {
        "repository_id": 42,
        "pull_number": 7,
        "base_oid": BASE,
        "head_oid": HEAD,
        "merge_base_oid": MERGE_BASE,
        "tree_oid": TREE,
        "message": "Merge exact review context\n",
        "author_name": "Example Reviewer",
        "author_email": "bot@example.invalid",
        "committer_name": "Example Reviewer",
        "committer_email": "bot@example.invalid",
        "timestamp": 1_760_000_000,
        "ci_profile": "python-v1",
        "workflow_sha": WORKFLOW,
        "git_profile": "hardened-git/v1",
        "policy_version": "policy-v1",
    }
    values.update(overrides)
    return MergeDescriptor.build(**values)


def ci_inputs(value):
    return CIRequestInputs(
        request_id="a" * 64,
        review_context_id="review-context-7",
        repository_id=value.repository_id,
        pull_number=value.pull_number,
        descriptor_digest=value.digest,
        base_oid=value.base_oid,
        head_oid=value.head_oid,
        candidate_oid=value.candidate_oid,
        workflow_id=12345,
        workflow_path=".github/workflows/targeted-ci.yml",
        workflow_sha=value.workflow_sha,
        workflow_definition_sha256="6" * 64,
        ci_profile=value.ci_profile,
        sandbox_profile="candidate-sandbox/v1",
        expected_actor="example-reviewer[bot]",
        expected_installation_id=99,
        dispatch_not_before="2026-07-25T00:00:00Z",
    )


class MergeDescriptorTests(unittest.TestCase):
    def test_golden_candidate_payload_and_descriptor_digest(self):
        value = descriptor()

        self.assertEqual(GOLDEN_CANDIDATE, value.candidate_oid)
        self.assertEqual(GOLDEN_DIGEST, value.digest)
        self.assertEqual([BASE, HEAD], value.to_mapping()["parents"])
        self.assertIn(b"parent " + BASE.encode() + b"\nparent " + HEAD.encode(), value.raw_commit_bytes)
        self.assertTrue(value.raw_commit_bytes.endswith(b"Merge exact review context\n"))

        restored = MergeDescriptor.from_canonical_bytes(value.canonical_bytes)
        self.assertEqual(value, restored)
        self.assertEqual(value.canonical_bytes, restored.canonical_bytes)

    def test_rejects_noncanonical_sha_parent_order_and_extra_fields(self):
        with self.assertRaisesRegex(ValueError, "lowercase SHA-1"):
            descriptor(base_oid="A" * 40)

        mapping = descriptor().to_mapping()
        mapping["parents"] = [HEAD, BASE]
        with self.assertRaisesRegex(ValueError, "ordered"):
            MergeDescriptor.from_mapping(mapping)

        mapping = descriptor().to_mapping()
        mapping["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "extra"):
            MergeDescriptor.from_mapping(mapping)

    def test_rejects_noncanonical_utf8_lf_time_and_bytes(self):
        with self.assertRaisesRegex(ValueError, "end with LF"):
            descriptor(message="missing terminator")
        with self.assertRaisesRegex(ValueError, "forbidden byte"):
            descriptor(message="windows\r\n")
        with self.assertRaisesRegex(ValueError, "integer second"):
            descriptor(timestamp=1_760_000_000.5)

        value = descriptor()
        noncanonical = json.dumps(value.to_mapping(), ensure_ascii=False).encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "not canonical"):
            MergeDescriptor.from_canonical_bytes(noncanonical)

    def test_one_byte_policy_mutation_changes_descriptor_digest(self):
        original = descriptor(policy_version="policy-v1")
        mutated = descriptor(policy_version="policy-v2")

        self.assertEqual(original.candidate_oid, mutated.candidate_oid)
        self.assertNotEqual(original.digest, mutated.digest)

    def test_ci_inputs_have_strict_canonical_golden_form(self):
        value = ci_inputs(descriptor())
        self.assertEqual(GOLDEN_INPUT_DIGEST, value.digest)
        self.assertEqual(
            value,
            CIRequestInputs.from_canonical_bytes(value.canonical_bytes),
        )

        mapping = value.to_mapping()
        mapping["extra"] = "no"
        with self.assertRaisesRegex(ValueError, "extra"):
            CIRequestInputs.from_mapping(mapping)
        with self.assertRaisesRegex(ValueError, "64 lowercase"):
            CIRequestInputs(
                request_id="A" * 64,
                review_context_id=value.review_context_id,
                repository_id=value.repository_id,
                pull_number=value.pull_number,
                descriptor_digest=value.descriptor_digest,
                base_oid=value.base_oid,
                head_oid=value.head_oid,
                candidate_oid=value.candidate_oid,
                workflow_id=value.workflow_id,
                workflow_path=value.workflow_path,
                workflow_sha=value.workflow_sha,
                workflow_definition_sha256=value.workflow_definition_sha256,
                ci_profile=value.ci_profile,
                sandbox_profile=value.sandbox_profile,
                expected_actor=value.expected_actor,
                expected_installation_id=value.expected_installation_id,
                dispatch_not_before=value.dispatch_not_before,
            )

    def test_ci_durable_identity_mutations_change_digest(self):
        original = ci_inputs(descriptor())
        mutations = (
            replace(original, review_context_id="review-context-8"),
            replace(original, expected_actor="other-bot[bot]"),
            replace(original, expected_installation_id=100),
            replace(original, workflow_definition_sha256="7" * 64),
            replace(original, dispatch_not_before="2026-07-25T00:00:01Z"),
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                self.assertNotEqual(original.digest, mutated.digest)

    def test_ci_durable_identity_fields_are_strict(self):
        value = ci_inputs(descriptor())
        invalid = (
            ("review_context_id", "review context 7", "safe ASCII"),
            ("expected_actor", "Dohwa Bot", "GitHub login"),
            ("expected_actor", "bad--actor", "GitHub login"),
            ("expected_installation_id", 0, "positive integer"),
            ("workflow_definition_sha256", "A" * 64, "lowercase SHA-256"),
            ("dispatch_not_before", "2026-07-25T00:00:00+00:00", "UTC second"),
            ("dispatch_not_before", "2026-02-30T00:00:00Z", "UTC second"),
        )
        for field, replacement, message in invalid:
            with self.subTest(field=field, replacement=replacement):
                with self.assertRaisesRegex(ValueError, message):
                    replace(value, **{field: replacement})


if __name__ == "__main__":
    unittest.main()
