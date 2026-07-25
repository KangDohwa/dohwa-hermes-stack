from datetime import datetime, timezone
import json
import unittest
from urllib import error, parse

from reviewer.github_auth import GitHubAuthError
from reviewer.github_client import (
    GitHubAPIError,
    GitHubClient,
    GitHubClockObservation,
    GitHubClockDateStatus,
    WorkflowIdentity,
)


REPOSITORY = "example/example-repo"
HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"
BASE_SHA = "1" * 40
WORKFLOW_SHA = "2" * 40
WORKFLOW_ID = 321
WORKFLOW_PATH = ".github/workflows/dohwa-candidate-ci.yml"
WORKFLOW_DISPATCH_REF = "refs/heads/dohwa-workflow/v1"
WORKFLOW_DEFINITION = b"name: pinned workflow\n"
WORKFLOW_DEFINITION_SHA256 = "67da2b5043e83f47e4817708a1eb3d0ed3aef552e2d3eba3188f4923a7ccabf9"
CI_REQUEST_ID = "a" * 64
STARTED_AT = datetime(2026, 7, 25, 0, 0, tzinfo=timezone.utc)
FINISHED_AT = datetime(2026, 7, 25, 0, 10, tzinfo=timezone.utc)


class FakeAuth:
    def __init__(self):
        self.token_repositories = []
        self.installation_repositories = []

    def require_allowed_repository(self, repository):
        if repository.casefold() != REPOSITORY.casefold():
            raise GitHubAuthError("not allowlisted")
        return REPOSITORY

    def installation_token_for_repository(self, repository):
        self.token_repositories.append(repository)
        return "installation-token"

    def installation_id_for_repository(self, repository):
        self.installation_repositories.append(repository)
        return 99


class FakeResponse:
    def __init__(self, payload, status=200, headers=None):
        self.payload = json.dumps(payload).encode("utf-8")
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        if size is not None and size >= 0:
            result, self.payload = self.payload[:size], self.payload[size:]
            return result
        return self.payload

    def getcode(self):
        return self.status


class RecordingTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, api_request, timeout):
        self.requests.append(api_request)
        if not self.responses:
            raise AssertionError(f"unexpected request: {api_request.full_url}")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class BinaryResponse(FakeResponse):
    def __init__(self, payload, status=200, headers=None):
        self.payload = payload
        self.status = status
        self.headers = headers or {}


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class GitHubClientTests(unittest.TestCase):
    def make_client(self, responses, **kwargs):
        self.auth = FakeAuth()
        self.transport = RecordingTransport(responses)
        return GitHubClient(
            self.auth,
            urlopen=self.transport,
            redirect_urlopen=self.transport,
            **kwargs,
        )

    @staticmethod
    def request_json(api_request):
        return json.loads(api_request.data.decode("utf-8"))

    def make_actions_client(self, responses, **kwargs):
        self.auth = FakeAuth()
        self.transport = RecordingTransport(responses)
        return GitHubClient(
            self.auth,
            urlopen=self.transport,
            redirect_urlopen=self.transport,
            allowed_workflows={
                REPOSITORY: {
                    WORKFLOW_ID: WorkflowIdentity(
                        path=WORKFLOW_PATH,
                        revision=WORKFLOW_SHA,
                        definition_sha256=WORKFLOW_DEFINITION_SHA256,
                        dispatch_ref=WORKFLOW_DISPATCH_REF,
                    )
                }
            },
            **kwargs,
        )

    def test_repository_installation_id_delegates_to_auth(self):
        client = self.make_client([])

        self.assertEqual(99, client.installation_id_for_repository(REPOSITORY))
        self.assertEqual([REPOSITORY], self.auth.installation_repositories)

    def test_merge_base_uses_exact_compare_and_requires_pinned_sha(self):
        merge_base_sha = "3" * 40
        client = self.make_client(
            [FakeResponse({"merge_base_commit": {"sha": merge_base_sha}})]
        )

        result = client.get_merge_base_sha(
            REPOSITORY,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
        )

        self.assertEqual(merge_base_sha, result)
        api_request = self.transport.requests[0]
        self.assertEqual("GET", api_request.method)
        self.assertTrue(
            api_request.full_url.endswith(
                f"/compare/{BASE_SHA}...{HEAD_SHA}"
            )
        )

    def test_merge_base_rejects_missing_or_noncanonical_sha(self):
        for payload in (
            {},
            {"merge_base_commit": {}},
            {"merge_base_commit": {"sha": "A" * 40}},
            {"merge_base_commit": {"sha": "3" * 39}},
        ):
            with self.subTest(payload=payload):
                client = self.make_client([FakeResponse(payload)])
                with self.assertRaisesRegex(GitHubAPIError, "merge base"):
                    client.get_merge_base_sha(
                        REPOSITORY,
                        base_sha=BASE_SHA,
                        head_sha=HEAD_SHA,
                    )

    @staticmethod
    def workflow_ref(**overrides):
        value = {
            "ref": WORKFLOW_DISPATCH_REF,
            "object": {"type": "commit", "sha": WORKFLOW_SHA},
        }
        value.update(overrides)
        return value

    @staticmethod
    def workflow_inputs(**overrides):
        inputs = {
            "base_sha": BASE_SHA,
            "head_sha": HEAD_SHA,
            "merge_descriptor": "canonical-merge-descriptor",
            "review_context_id": "review-context-7",
            "ci_request_id": CI_REQUEST_ID,
        }
        inputs.update(overrides)
        return inputs

    @staticmethod
    def workflow_run(run_id=1, **overrides):
        value = {
            "id": run_id,
            "display_title": f"dohwa-candidate-ci:{CI_REQUEST_ID}",
            "event": "workflow_dispatch",
            "actor": {"login": "example-reviewer[bot]"},
            "triggering_actor": {"login": "example-reviewer[bot]"},
            "repository": {"id": 99, "full_name": REPOSITORY},
            "workflow_id": WORKFLOW_ID,
            "path": WORKFLOW_PATH,
            "head_branch": "dohwa-workflow/v1",
            "head_sha": WORKFLOW_SHA,
            "created_at": "2026-07-25T00:01:00Z",
            "run_attempt": 1,
        }
        value.update(overrides)
        return value

    @staticmethod
    def label_timeline_event(
        event_id,
        cursor,
        *,
        typename="LabeledEvent",
        created_at="2026-07-25T01:02:03Z",
        actor_type="User",
        actor_node_id="U_sender_987",
        actor_database_id=987,
        actor_login="approver",
    ):
        return {
            "cursor": cursor,
            "node": {
                "__typename": typename,
                "id": event_id,
                "createdAt": created_at,
                "actor": None if actor_type is None else {
                    "__typename": actor_type,
                    "id": actor_node_id,
                    "databaseId": actor_database_id,
                    "login": actor_login,
                },
                "label": {
                    "id": "LA_label_654",
                    "name": "hermes:merge-approved",
                },
            },
        }

    @staticmethod
    def label_timeline_response(
        edges,
        *,
        total_count=None,
        updated_at="2026-07-25T01:03:00Z",
        has_next_page=False,
        end_cursor=None,
        repository_name=REPOSITORY,
    ):
        return FakeResponse(
            {
                "data": {
                    "repository": {
                        "id": "R_repo_99",
                        "databaseId": 99,
                        "nameWithOwner": repository_name,
                        "pullRequest": {
                            "number": 7,
                            "timelineItems": {
                                "updatedAt": updated_at,
                                "filteredCount": len(edges) if total_count is None else total_count,
                                "edges": edges,
                                "pageInfo": {
                                    "hasNextPage": has_next_page,
                                    "endCursor": end_cursor,
                                },
                            },
                        },
                    },
                },
            }
        )


    def test_workflow_identity_requires_canonical_pinned_values(self):
        invalid = (
            {"path": "other.yml"},
            {"revision": "A" * 40},
            {"revision": "3" * 39},
            {"definition_sha256": "C" * 64},
            {"definition_sha256": "c" * 63},
            {"dispatch_ref": "dohwa-workflow/v1"},
            {"dispatch_ref": "refs/tags/dohwa-workflow/v1"},
            {"dispatch_ref": "refs/heads/dohwa-workflow/../main"},
            {"dispatch_ref": "refs/heads/dohwa-workflow//v1"},
            {"dispatch_ref": "refs/heads/dohwa-workflow/@{v1"},
            {"dispatch_ref": "refs/heads/dohwa-workflow/.hidden"},
            {"dispatch_ref": "refs/heads/dohwa-workflow/v1."},
            {"dispatch_ref": "refs/heads/dohwa-workflow/v1/"},
            {"dispatch_ref": "refs/heads/dohwa-workflow/v1.lock"},
            {"dispatch_ref": "refs/heads/" + "x" * 245},
        )
        base = {
            "path": WORKFLOW_PATH,
            "revision": WORKFLOW_SHA,
            "definition_sha256": WORKFLOW_DEFINITION_SHA256,
            "dispatch_ref": WORKFLOW_DISPATCH_REF,
        }
        for override in invalid:
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    WorkflowIdentity(**{**base, **override})

    def test_workflow_allowlist_rejects_legacy_path_only_identity(self):
        with self.assertRaisesRegex(ValueError, "WorkflowIdentity"):
            GitHubClient(
                FakeAuth(),
                urlopen=RecordingTransport([]),
                allowed_workflows={REPOSITORY: {WORKFLOW_ID: WORKFLOW_PATH}},
            )

    def test_actions_runtime_is_unconfigured_and_fail_closed_by_default(self):
        client = self.make_client([])
        with self.assertRaisesRegex(GitHubAPIError, "not allowlisted"):
            client.dispatch_workflow(
                REPOSITORY,
                WORKFLOW_ID,
                workflow_revision=WORKFLOW_SHA,
                workflow_definition=WORKFLOW_DEFINITION,
                inputs=self.workflow_inputs(),
            )
        self.assertEqual(self.transport.requests, [])

    def test_dispatch_workflow_uses_only_allowlisted_id_and_strict_inputs(self):
        client = self.make_actions_client(
            [FakeResponse(self.workflow_ref()), BinaryResponse(b"", status=204)]
        )

        result = client.dispatch_workflow(
            REPOSITORY,
            WORKFLOW_ID,
            workflow_revision=WORKFLOW_SHA,
            workflow_definition=WORKFLOW_DEFINITION,
            inputs=self.workflow_inputs(),
        )

        self.assertIsNone(result)
        ref_request, api_request = self.transport.requests
        self.assertEqual(ref_request.method, "GET")
        self.assertTrue(
            ref_request.full_url.endswith("/git/ref/heads/dohwa-workflow/v1")
        )
        self.assertEqual(api_request.method, "POST")
        self.assertTrue(
            api_request.full_url.endswith(
                f"/actions/workflows/{WORKFLOW_ID}/dispatches"
            )
        )
        self.assertEqual(
            self.request_json(api_request),
            {"ref": WORKFLOW_DISPATCH_REF, "inputs": self.workflow_inputs()},
        )

    def test_dispatch_workflow_requires_204(self):
        client = self.make_actions_client(
            [FakeResponse(self.workflow_ref()), FakeResponse({}, status=200)]
        )
        with self.assertRaises(GitHubAPIError):
            client.dispatch_workflow(
                REPOSITORY,
                WORKFLOW_ID,
                workflow_revision=WORKFLOW_SHA,
                workflow_definition=WORKFLOW_DEFINITION,
                inputs=self.workflow_inputs(),
            )

    def test_dispatch_workflow_rejects_changed_ref_before_dispatch(self):
        mismatches = (
            {"ref": "refs/heads/main"},
            {"object": {"type": "tag", "sha": WORKFLOW_SHA}},
            {"object": {"type": "commit", "sha": "3" * 40}},
            {"object": None},
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                client = self.make_actions_client(
                    [FakeResponse(self.workflow_ref(**mismatch))]
                )
                with self.assertRaisesRegex(
                    GitHubAPIError, "IMMUTABLE_WORKFLOW_REF_MISMATCH"
                ):
                    client.dispatch_workflow(
                        REPOSITORY,
                        WORKFLOW_ID,
                        workflow_revision=WORKFLOW_SHA,
                        workflow_definition=WORKFLOW_DEFINITION,
                        inputs=self.workflow_inputs(),
                    )
                self.assertEqual(len(self.transport.requests), 1)
                self.assertEqual(self.transport.requests[0].method, "GET")

    def test_dispatch_workflow_rejects_unapproved_identity_before_network(self):
        invalid_cases = (
            {
                "workflow_id": 999,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(),
            },
            {
                "workflow_id": 0,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": "main",
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": "3" * 40,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": b"tampered workflow",
                "inputs": self.workflow_inputs(),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(base_sha="main"),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(head_sha="main"),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(ci_request_id="A" * 64),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": {**self.workflow_inputs(), "extra": "forbidden"},
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(review_context_id="has space"),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(review_context_id="한글"),
            },
            {
                "workflow_id": WORKFLOW_ID,
                "revision": WORKFLOW_SHA,
                "definition": WORKFLOW_DEFINITION,
                "inputs": self.workflow_inputs(review_context_id="x" * 257),
            },
        )
        for case in invalid_cases:
            with self.subTest(case=case):
                client = self.make_actions_client([])
                with self.assertRaises((ValueError, GitHubAPIError)):
                    client.dispatch_workflow(
                        REPOSITORY,
                        case["workflow_id"],
                        workflow_revision=case["revision"],
                        workflow_definition=case["definition"],
                        inputs=case["inputs"],
                    )
                self.assertEqual(self.transport.requests, [])

    def test_dispatch_rejects_invalid_definition_bytes_before_network(self):
        invalid_definitions = (None, bytearray(WORKFLOW_DEFINITION), b"", b"x" * 9)
        for definition in invalid_definitions:
            with self.subTest(definition=definition):
                client = self.make_actions_client(
                    [], max_workflow_definition_bytes=8
                )
                with self.assertRaises(ValueError):
                    client.dispatch_workflow(
                        REPOSITORY,
                        WORKFLOW_ID,
                        workflow_revision=WORKFLOW_SHA,
                        workflow_definition=definition,
                        inputs=self.workflow_inputs(),
                    )
                self.assertEqual(self.transport.requests, [])

    def test_workflow_run_listing_paginates_and_checks_continuity(self):
        first_page = [
            self.workflow_run(
                index + 1,
                display_title=f"unrelated-{index}",
                created_at="2026-07-25T00:02:00Z",
            )
            for index in range(100)
        ]
        last_run = self.workflow_run(101, display_title="unrelated-last")
        client = self.make_actions_client(
            [
                FakeResponse({"total_count": 101, "workflow_runs": first_page}),
                FakeResponse({"total_count": 101, "workflow_runs": [last_run]}),
            ]
        )

        runs = client.list_workflow_runs(
            REPOSITORY, WORKFLOW_ID, not_before=STARTED_AT
        )

        self.assertEqual(len(runs), 101)
        queries = [parse.parse_qs(parse.urlsplit(req.full_url).query) for req in self.transport.requests]
        self.assertEqual(queries[0]["event"], ["workflow_dispatch"])
        self.assertEqual(queries[0]["page"], ["1"])
        self.assertEqual(queries[1]["page"], ["2"])

    def test_workflow_run_listing_fails_closed_at_github_search_cap(self):
        client = self.make_actions_client(
            [FakeResponse({"total_count": 1000, "workflow_runs": []})]
        )
        with self.assertRaisesRegex(GitHubAPIError, "CI_RUN_PAGINATION_LIMIT"):
            client.list_workflow_runs(
                REPOSITORY, WORKFLOW_ID, not_before=STARTED_AT
            )

    def test_workflow_run_listing_fails_closed_on_discontinuity(self):
        first_page = [
            self.workflow_run(
                index + 1,
                display_title=f"unrelated-{index}",
                created_at="2026-07-25T00:02:00Z",
            )
            for index in range(100)
        ]
        client = self.make_actions_client(
            [
                FakeResponse({"total_count": 101, "workflow_runs": first_page}),
                FakeResponse(
                    {"total_count": 101, "workflow_runs": [self.workflow_run(100)]}
                ),
            ]
        )

        with self.assertRaisesRegex(
            GitHubAPIError, "CI_RUN_PAGINATION_DISCONTINUITY"
        ):
            client.list_workflow_runs(
                REPOSITORY, WORKFLOW_ID, not_before=STARTED_AT
            )

    def test_correlate_workflow_run_polls_bounded_for_delayed_visibility(self):
        clock = FakeClock()
        exact = self.workflow_run()
        client = self.make_actions_client(
            [
                FakeResponse({"total_count": 0, "workflow_runs": []}),
                FakeResponse({"total_count": 1, "workflow_runs": [exact]}),
                FakeResponse({"total_count": 1, "workflow_runs": [exact]}),
            ],
            sleeper=clock.sleep,
            monotonic=clock.monotonic,
        )

        result = client.correlate_workflow_run(
            REPOSITORY,
            WORKFLOW_ID,
            ci_request_id=CI_REQUEST_ID,
            expected_actor="example-reviewer[bot]",
            expected_repository_id=99,
            not_before=STARTED_AT,
            not_after=FINISHED_AT,
            visibility_timeout_seconds=2,
            settling_window_seconds=1,
            poll_interval_seconds=1,
        )

        self.assertEqual(result["id"], 1)
        self.assertEqual(clock.sleeps, [1.0, 1.0])

    def test_correlation_rejects_early_candidate_late_duplicate(self):
        clock = FakeClock()
        client = self.make_actions_client(
            [
                FakeResponse(
                    {"total_count": 1, "workflow_runs": [self.workflow_run(1)]}
                ),
                FakeResponse(
                    {
                        "total_count": 2,
                        "workflow_runs": [self.workflow_run(1), self.workflow_run(2)],
                    }
                ),
            ],
            sleeper=clock.sleep,
            monotonic=clock.monotonic,
        )

        with self.assertRaisesRegex(GitHubAPIError, "CI_RUN_CORRELATION_AMBIGUOUS"):
            client.correlate_workflow_run(
                REPOSITORY,
                WORKFLOW_ID,
                ci_request_id=CI_REQUEST_ID,
                expected_actor="example-reviewer[bot]",
                expected_repository_id=99,
                not_before=STARTED_AT,
                not_after=FINISHED_AT,
                visibility_timeout_seconds=30,
                settling_window_seconds=2,
                poll_interval_seconds=10,
            )

        self.assertEqual(clock.sleeps, [10.0])
        self.assertEqual(len(self.transport.requests), 2)

    def test_correlation_late_first_appearance_gets_full_settling_window(self):
        clock = FakeClock()
        empty_payload = {"total_count": 0, "workflow_runs": []}
        candidate_payload = {
            "total_count": 1,
            "workflow_runs": [self.workflow_run(1)],
        }
        client = self.make_actions_client(
            [
                FakeResponse(empty_payload),
                FakeResponse(empty_payload),
                FakeResponse(candidate_payload),
                FakeResponse(candidate_payload),
            ],
            sleeper=clock.sleep,
            monotonic=clock.monotonic,
        )

        result = client.correlate_workflow_run(
            REPOSITORY,
            WORKFLOW_ID,
            ci_request_id=CI_REQUEST_ID,
            expected_actor="example-reviewer[bot]",
            expected_repository_id=99,
            not_before=STARTED_AT,
            not_after=FINISHED_AT,
            visibility_timeout_seconds=10,
            settling_window_seconds=4,
            poll_interval_seconds=5,
        )

        self.assertEqual(result["id"], 1)
        self.assertEqual(clock.sleeps, [5.0, 5.0, 4.0])
        self.assertEqual(len(self.transport.requests), 4)

    def test_correlation_accepts_stable_single_after_default_settling_window(self):
        clock = FakeClock()
        snapshots = [
            {"total_count": 1, "workflow_runs": [self.workflow_run(1)]},
            {
                "total_count": 2,
                "workflow_runs": [
                    self.workflow_run(2, display_title="unrelated"),
                    self.workflow_run(1),
                ],
            },
            {
                "total_count": 2,
                "workflow_runs": [
                    self.workflow_run(2, display_title="unrelated"),
                    self.workflow_run(1),
                ],
            },
        ]
        client = self.make_actions_client(
            [FakeResponse(snapshot) for snapshot in snapshots],
            sleeper=clock.sleep,
            monotonic=clock.monotonic,
        )

        result = client.correlate_workflow_run(
            REPOSITORY,
            WORKFLOW_ID,
            ci_request_id=CI_REQUEST_ID,
            expected_actor="example-reviewer[bot]",
            expected_repository_id=99,
            not_before=STARTED_AT,
            not_after=FINISHED_AT,
            visibility_timeout_seconds=2,
            poll_interval_seconds=1,
        )

        self.assertEqual(result["id"], 1)
        self.assertEqual(clock.sleeps, [1.0, 1.0])
        self.assertEqual(len(self.transport.requests), 3)

    def test_correlation_rejects_candidate_identity_changes_during_settling(self):
        mutations = (
            self.workflow_run(1, run_attempt=2),
            self.workflow_run(2),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                clock = FakeClock()
                client = self.make_actions_client(
                    [
                        FakeResponse(
                            {
                                "total_count": 1,
                                "workflow_runs": [self.workflow_run(1)],
                            }
                        ),
                        FakeResponse(
                            {"total_count": 1, "workflow_runs": [mutation]}
                        ),
                    ],
                    sleeper=clock.sleep,
                    monotonic=clock.monotonic,
                )

                with self.assertRaisesRegex(
                    GitHubAPIError, "CI_RUN_CORRELATION_UNSTABLE"
                ):
                    client.correlate_workflow_run(
                        REPOSITORY,
                        WORKFLOW_ID,
                        ci_request_id=CI_REQUEST_ID,
                        expected_actor="example-reviewer[bot]",
                        expected_repository_id=99,
                        not_before=STARTED_AT,
                        not_after=FINISHED_AT,
                        poll_interval_seconds=1,
                    )
                self.assertEqual(clock.sleeps, [1.0])
                self.assertEqual(len(self.transport.requests), 2)

    def test_correlation_requires_positive_safety_windows(self):
        invalid_windows = (
            {"visibility_timeout_seconds": 0},
            {"settling_window_seconds": 0},
        )
        for override in invalid_windows:
            with self.subTest(override=override):
                client = self.make_actions_client([])
                with self.assertRaises(ValueError):
                    client.correlate_workflow_run(
                        REPOSITORY,
                        WORKFLOW_ID,
                        ci_request_id=CI_REQUEST_ID,
                        expected_actor="example-reviewer[bot]",
                        expected_repository_id=99,
                        not_before=STARTED_AT,
                        not_after=FINISHED_AT,
                        **override,
                    )
                self.assertEqual(self.transport.requests, [])

    def test_correlation_rejects_alternate_valid_w0_before_network(self):
        client = self.make_actions_client([])
        with self.assertRaisesRegex(
            GitHubAPIError, "IMMUTABLE_WORKFLOW_IDENTITY_MISMATCH"
        ):
            client.correlate_workflow_run(
                REPOSITORY,
                WORKFLOW_ID,
                ci_request_id=CI_REQUEST_ID,
                workflow_revision="3" * 40,
                expected_actor="example-reviewer[bot]",
                expected_repository_id=99,
                not_before=STARTED_AT,
                not_after=FINISHED_AT,
            )
        self.assertEqual(self.transport.requests, [])

    def test_correlate_workflow_run_matches_exact_immutable_identity(self):
        clock = FakeClock()
        exact = self.workflow_run()
        payload = {
            "total_count": 2,
            "workflow_runs": [
                self.workflow_run(2, display_title="unrelated"),
                exact,
            ],
        }
        client = self.make_actions_client(
            [FakeResponse(payload), FakeResponse(payload)],
            sleeper=clock.sleep,
            monotonic=clock.monotonic,
        )

        result = client.correlate_workflow_run(
            REPOSITORY,
            WORKFLOW_ID,
            ci_request_id=CI_REQUEST_ID,
            workflow_revision=WORKFLOW_SHA,
            expected_actor="example-reviewer[bot]",
            expected_repository_id=99,
            not_before=STARTED_AT,
            not_after=FINISHED_AT,
            visibility_timeout_seconds=1,
            settling_window_seconds=1,
            poll_interval_seconds=1,
        )

        self.assertEqual(result["id"], 1)
        self.assertEqual(result["head_sha"], WORKFLOW_SHA)
        self.assertEqual(result["path"], WORKFLOW_PATH)
        self.assertEqual(result["head_branch"], "dohwa-workflow/v1")
        self.assertEqual(clock.sleeps, [1.0])

    def test_correlate_workflow_run_reports_not_found_and_ambiguity(self):
        cases = (
            (
                {
                    "total_count": 1,
                    "workflow_runs": [self.workflow_run(display_title="other")],
                },
                "CI_RUN_NOT_FOUND",
                2,
                [1.0],
            ),
            (
                {
                    "total_count": 2,
                    "workflow_runs": [self.workflow_run(1), self.workflow_run(2)],
                },
                "CI_RUN_CORRELATION_AMBIGUOUS",
                1,
                [],
            ),
        )
        for payload, code, response_count, expected_sleeps in cases:
            with self.subTest(code=code):
                clock = FakeClock()
                client = self.make_actions_client(
                    [FakeResponse(payload) for _index in range(response_count)],
                    sleeper=clock.sleep,
                    monotonic=clock.monotonic,
                )
                with self.assertRaisesRegex(GitHubAPIError, code):
                    client.correlate_workflow_run(
                        REPOSITORY,
                        WORKFLOW_ID,
                        ci_request_id=CI_REQUEST_ID,
                        workflow_revision=WORKFLOW_SHA,
                        expected_actor="example-reviewer[bot]",
                        expected_repository_id=99,
                        not_before=STARTED_AT,
                        not_after=FINISHED_AT,
                        visibility_timeout_seconds=1,
                        settling_window_seconds=1,
                        poll_interval_seconds=1,
                    )
                self.assertEqual(clock.sleeps, expected_sleeps)

    def test_correlate_workflow_run_rejects_identity_mismatch(self):
        mismatches = (
            {"head_sha": "f" * 40},
            {"path": ".github/workflows/other.yml"},
            {"head_branch": "main"},
            {"actor": {"login": "someone"}},
            {"repository": {"id": 100, "full_name": REPOSITORY}},
            {"created_at": "2026-07-25T00:11:00Z"},
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                client = self.make_actions_client(
                    [
                        FakeResponse(
                            {
                                "total_count": 1,
                                "workflow_runs": [self.workflow_run(**mismatch)],
                            }
                        )
                    ]
                )
                with self.assertRaisesRegex(GitHubAPIError, "CI_RUN_IDENTITY_MISMATCH"):
                    client.correlate_workflow_run(
                        REPOSITORY,
                        WORKFLOW_ID,
                        ci_request_id=CI_REQUEST_ID,
                        workflow_revision=WORKFLOW_SHA,
                        expected_actor="example-reviewer[bot]",
                        expected_repository_id=99,
                        not_before=STARTED_AT,
                        not_after=FINISHED_AT,
                    )

    def test_correlation_security_failures_do_not_poll(self):
        cases = (
            (
                {
                    "total_count": 2,
                    "workflow_runs": [self.workflow_run(1), self.workflow_run(2)],
                },
                "CI_RUN_CORRELATION_AMBIGUOUS",
            ),
            (
                {
                    "total_count": 1,
                    "workflow_runs": [self.workflow_run(head_sha="f" * 40)],
                },
                "CI_RUN_IDENTITY_MISMATCH",
            ),
            (
                {"total_count": 1, "workflow_runs": "invalid"},
                "CI_RUN_PAGINATION_DISCONTINUITY",
            ),
        )
        for payload, code in cases:
            with self.subTest(code=code):
                clock = FakeClock()
                client = self.make_actions_client(
                    [FakeResponse(payload)],
                    sleeper=clock.sleep,
                    monotonic=clock.monotonic,
                )
                with self.assertRaisesRegex(GitHubAPIError, code):
                    client.correlate_workflow_run(
                        REPOSITORY,
                        WORKFLOW_ID,
                        ci_request_id=CI_REQUEST_ID,
                        expected_actor="example-reviewer[bot]",
                        expected_repository_id=99,
                        not_before=STARTED_AT,
                        not_after=FINISHED_AT,
                        visibility_timeout_seconds=10,
                        poll_interval_seconds=1,
                    )
                self.assertEqual(clock.sleeps, [])
                self.assertEqual(len(self.transport.requests), 1)

    def test_reads_pull_files_reviews_checks_and_status(self):
        files = [{"filename": f"file-{index}.py"} for index in range(100)]
        client = self.make_client(
            [
                FakeResponse({"number": 7}),
                FakeResponse(files),
                FakeResponse([{"filename": "last.py"}]),
                FakeResponse([{"state": "APPROVED"}]),
                FakeResponse(
                    {"check_runs": [{"name": f"check-{index}"} for index in range(100)]}
                ),
                FakeResponse({"check_runs": [{"name": "check-100"}]}),
                FakeResponse({"state": "success", "statuses": []}),
            ]
        )

        self.assertEqual(client.get_pull_request(REPOSITORY, 7)["number"], 7)
        self.assertEqual(len(client.list_pull_request_files(REPOSITORY, 7)), 101)
        self.assertEqual(
            client.list_pull_request_reviews(REPOSITORY, 7)[0]["state"],
            "APPROVED",
        )
        self.assertEqual(len(client.list_check_runs(REPOSITORY, HEAD_SHA)), 101)
        self.assertEqual(
            client.get_combined_status(REPOSITORY, HEAD_SHA)["state"], "success"
        )

        urls = [item.full_url for item in self.transport.requests]
        self.assertTrue(
            any("/pulls/7/files?per_page=100&page=1" in url for url in urls)
        )
        self.assertTrue(
            any(
                "/commits/" + HEAD_SHA + "/check-runs?per_page=100&page=2" in url
                for url in urls
            )
        )
        for api_request in self.transport.requests:
            self.assertEqual(
                api_request.get_header("Authorization"),
                "Bearer installation-token",
            )

    def test_list_open_pull_requests_paginates_with_open_state(self):
        first_page = [{"number": index + 1} for index in range(100)]
        client = self.make_client(
            [FakeResponse(first_page), FakeResponse([{"number": 101}])]
        )

        pulls = client.list_open_pull_requests(REPOSITORY)

        self.assertEqual(len(pulls), 101)
        self.assertIn(
            "/pulls?state=open&per_page=100&page=1",
            self.transport.requests[0].full_url,
        )
        self.assertIn(
            "/pulls?state=open&per_page=100&page=2",
            self.transport.requests[1].full_url,
        )

    def test_get_pull_request_diff_reads_raw_utf8_with_diff_accept_header(self):
        diff = "diff --git a/a.py b/a.py\n+한글\n"
        encoded = diff.encode("utf-8")
        client = self.make_client(
            [BinaryResponse(encoded, headers={"Content-Length": str(len(encoded))})]
        )

        self.assertEqual(client.get_pull_request_diff(REPOSITORY, 7), diff)
        api_request = self.transport.requests[0]
        self.assertEqual(api_request.get_header("Accept"), "application/vnd.github.diff")
        self.assertEqual(
            api_request.get_header("Authorization"), "Bearer installation-token"
        )
        self.assertTrue(api_request.full_url.endswith("/pulls/7"))

    def test_get_pull_request_diff_enforces_streamed_size_limit(self):
        self.auth = FakeAuth()
        self.transport = RecordingTransport([BinaryResponse(b"12345")])
        client = GitHubClient(
            self.auth,
            urlopen=self.transport,
            redirect_urlopen=self.transport,
            max_diff_bytes=4,
        )

        with self.assertRaisesRegex(GitHubAPIError, "size limit"):
            client.get_pull_request_diff(REPOSITORY, 7)

    def test_get_pull_request_diff_rejects_invalid_utf8(self):
        client = self.make_client([BinaryResponse(b"\xff\xfe")])
        with self.assertRaisesRegex(GitHubAPIError, "valid UTF-8"):
            client.get_pull_request_diff(REPOSITORY, 7)

    def test_get_pull_request_diff_validates_before_network(self):
        client = self.make_client([])
        with self.assertRaises(GitHubAuthError):
            client.get_pull_request_diff("Other/repository", 7)
        with self.assertRaises(ValueError):
            client.get_pull_request_diff(REPOSITORY, 0)
        self.assertEqual(self.transport.requests, [])

    def test_create_review_comment_and_labels(self):
        client = self.make_client(
            [
                FakeResponse({"id": 1}),
                FakeResponse({"id": 2}, status=201),
                FakeResponse([{"name": "hermes:reviewed"}]),
            ]
        )

        review = client.create_review(
            REPOSITORY,
            7,
            body="Reviewed",
            event="approve",
            comments=[{"path": "a.py", "line": 3, "side": "RIGHT", "body": "note"}],
            commit_id=HEAD_SHA,
        )
        comment = client.create_comment(REPOSITORY, 7, body="Summary")
        labels = client.add_labels(
            REPOSITORY, 7, ["hermes:reviewed", "hermes:reviewed"]
        )

        self.assertEqual(review["id"], 1)
        self.assertEqual(comment["id"], 2)
        self.assertEqual(labels[0]["name"], "hermes:reviewed")
        review_body = self.request_json(self.transport.requests[0])
        self.assertEqual(review_body["event"], "APPROVE")
        self.assertEqual(review_body["commit_id"], HEAD_SHA)
        self.assertEqual(
            self.request_json(self.transport.requests[2]),
            {"labels": ["hermes:reviewed"]},
        )

    def test_dismiss_review_requires_confirmed_terminal_response(self):
        client = self.make_client(
            [FakeResponse({"id": 17, "state": "DISMISSED"})]
        )

        result = client.dismiss_review(
            REPOSITORY,
            7,
            17,
            message="Exact review context changed",
        )

        self.assertEqual("DISMISSED", result["state"])
        request_value = self.transport.requests[0]
        self.assertEqual("PUT", request_value.method)
        self.assertTrue(request_value.full_url.endswith(
            "/pulls/7/reviews/17/dismissals"
        ))
        self.assertEqual(
            {"message": "Exact review context changed"},
            self.request_json(request_value),
        )

        client = self.make_client([FakeResponse({"id": 17, "state": "CHANGES_REQUESTED"})])
        with self.assertRaisesRegex(GitHubAPIError, "confirm"):
            client.dismiss_review(REPOSITORY, 7, 17, message="changed")

    def test_download_tarball_only_follows_trusted_codeload_without_auth(self):
        tarball = b"tarball-bytes"
        client = self.make_client(
            [
                BinaryResponse(
                    b"",
                    status=302,
                    headers={
                        "Location": (
                            "https://codeload.github.com/example/example-repo/"
                            f"legacy.tar.gz/{HEAD_SHA}"
                        )
                    },
                ),
                BinaryResponse(
                    tarball,
                    headers={"Content-Length": str(len(tarball))},
                ),
            ]
        )

        self.assertEqual(client.download_tarball(REPOSITORY, HEAD_SHA), tarball)
        api_request, codeload_request = self.transport.requests
        self.assertEqual(
            api_request.get_header("Authorization"), "Bearer installation-token"
        )
        self.assertIsNone(codeload_request.get_header("Authorization"))
        self.assertEqual(codeload_request.host, "codeload.github.com")

    def test_download_tarball_rejects_untrusted_redirect(self):
        client = self.make_client(
            [
                BinaryResponse(
                    b"",
                    status=302,
                    headers={"Location": "https://codeload.github.com.evil.test/a"},
                )
            ]
        )

        with self.assertRaisesRegex(GitHubAPIError, "not trusted"):
            client.download_tarball(REPOSITORY, HEAD_SHA)
        self.assertEqual(len(self.transport.requests), 1)

    def test_download_tarball_enforces_streamed_size_limit(self):
        self.auth = FakeAuth()
        self.transport = RecordingTransport(
            [
                BinaryResponse(
                    b"",
                    status=302,
                    headers={"Location": "https://codeload.github.com/a/b/tar.gz"},
                ),
                BinaryResponse(b"12345"),
            ]
        )
        client = GitHubClient(
            self.auth,
            urlopen=self.transport,
            redirect_urlopen=self.transport,
            max_tarball_bytes=4,
        )

        with self.assertRaisesRegex(GitHubAPIError, "size limit"):
            client.download_tarball(REPOSITORY, HEAD_SHA)

    def test_download_tarball_validates_allowlist_and_exact_sha_before_network(self):
        client = self.make_client([])
        with self.assertRaises(GitHubAuthError):
            client.download_tarball("Other/repository", HEAD_SHA)
        with self.assertRaises(ValueError):
            client.download_tarball(REPOSITORY, "main")
        self.assertEqual(self.transport.requests, [])

    def test_label_timeline_paginates_in_authoritative_edge_order(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        second = self.label_timeline_event(
            "UE_2",
            "cursor-2",
            typename="UnlabeledEvent",
            created_at="2026-07-25T01:02:04Z",
        )
        client = self.make_client(
            [
                self.label_timeline_response(
                    [first],
                    total_count=2,
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
                self.label_timeline_response(
                    [second], total_count=1, end_cursor="cursor-2"
                ),
                self.label_timeline_response(
                    [first],
                    total_count=2,
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
            ]
        )

        snapshot = client.list_pull_request_label_timeline(REPOSITORY, 7)

        self.assertEqual(99, snapshot.repository_database_id)
        self.assertEqual(2, snapshot.total_count)
        self.assertEqual(["labeled", "unlabeled"], [e.action for e in snapshot.events])
        self.assertEqual([1, 2], [e.ordinal for e in snapshot.events])
        self.assertIsNone(snapshot.events[0].predecessor_event_id)
        self.assertEqual("LE_1", snapshot.events[1].predecessor_event_id)
        requests = [self.request_json(item) for item in self.transport.requests]
        self.assertEqual([None, "cursor-1", None], [
            item["variables"]["after"] for item in requests
        ])
        self.assertEqual([100, 100, 1], [
            item["variables"]["first"] for item in requests
        ])
        self.assertIn("LABELED_EVENT", requests[0]["query"])
        self.assertIn("UNLABELED_EVENT", requests[0]["query"])

    def test_label_timeline_preserves_authenticated_http_date_observation(self):
        event = self.label_timeline_event("LE_1", "cursor-1")
        response_date = "Sat, 25 Jul 2026 01:03:00 GMT"
        responses = [
            self.label_timeline_response(
                [event], total_count=1, end_cursor="cursor-1"
            ),
            self.label_timeline_response(
                [event], total_count=1, end_cursor="cursor-1"
            ),
        ]
        for response in responses:
            response.headers["Date"] = response_date
        ticks = iter((10.0, 10.25, 20.0, 20.5))
        client = self.make_client(responses, monotonic=lambda: next(ticks))

        clock = client.list_pull_request_label_timeline(REPOSITORY, 7).clock

        self.assertEqual(GitHubClockDateStatus.VALID, clock.date_status)
        self.assertEqual(response_date, clock.response_date)
        self.assertEqual(1784941380, clock.server_date_epoch_seconds)
        self.assertEqual(20.0, clock.request_started_monotonic)
        self.assertEqual(20.5, clock.response_received_monotonic)
        self.assertEqual(0.5, clock.request_rtt_seconds)

    def test_clock_observation_rejects_inconsistent_date_and_epoch(self):
        with self.assertRaisesRegex(ValueError, "Date and parsed epoch differ"):
            GitHubClockObservation(
                response_date="Sat, 25 Jul 2026 01:03:00 GMT",
                server_date_epoch_seconds=0,
                request_started_monotonic=1.0,
                response_received_monotonic=1.5,
                request_rtt_seconds=0.5,
                date_status=GitHubClockDateStatus.VALID,
            )

    def test_label_timeline_clock_identifies_missing_malformed_and_slow_date(self):
        event = self.label_timeline_event("LE_1", "cursor-1")
        cases = (
            (None, (0.0, 0.1, 1.0, 1.1), GitHubClockDateStatus.MISSING, 0.1),
            (
                "Sat, 25 Jul 2026 01:03:00 UTC",
                (0.0, 0.1, 1.0, 1.1),
                GitHubClockDateStatus.MALFORMED,
                0.1,
            ),
            (
                "Sat, 25 Jul 2026 01:03:00 GMT",
                (0.0, 0.1, 1.0, 3.01),
                GitHubClockDateStatus.VALID,
                2.01,
            ),
        )
        for response_date, values, expected_status, expected_rtt in cases:
            with self.subTest(response_date=response_date, expected_rtt=expected_rtt):
                responses = [
                    self.label_timeline_response(
                        [event], total_count=1, end_cursor="cursor-1"
                    ),
                    self.label_timeline_response(
                        [event], total_count=1, end_cursor="cursor-1"
                    ),
                ]
                if response_date is not None:
                    for response in responses:
                        response.headers["Date"] = response_date
                ticks = iter(values)
                client = self.make_client(responses, monotonic=lambda: next(ticks))

                clock = client.list_pull_request_label_timeline(REPOSITORY, 7).clock

                self.assertEqual(expected_status, clock.date_status)
                self.assertAlmostEqual(expected_rtt, clock.request_rtt_seconds)
                if expected_status is not GitHubClockDateStatus.VALID:
                    self.assertIsNone(clock.server_date_epoch_seconds)

    def test_tied_label_timestamps_require_exact_second_full_traversal(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        second = self.label_timeline_event("LE_2", "cursor-2")
        initial = self.label_timeline_response(
            [first, second], total_count=2, end_cursor="cursor-2"
        )
        watermark = self.label_timeline_response(
            [first], total_count=2, has_next_page=True, end_cursor="cursor-1"
        )
        verified = self.label_timeline_response(
            [first, second], total_count=2, end_cursor="cursor-2"
        )
        client = self.make_client([initial, watermark, verified])

        snapshot = client.list_pull_request_label_timeline(REPOSITORY, 7)

        self.assertEqual(
            ["LE_1", "LE_2"], [event.event_id for event in snapshot.events]
        )
        requests = [self.request_json(item) for item in self.transport.requests]
        self.assertEqual(
            [100, 1, 100], [item["variables"]["first"] for item in requests]
        )

    def test_tied_label_timestamps_verify_decreasing_counts_across_pages(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        second = self.label_timeline_event("LE_2", "cursor-2")
        responses = [
            self.label_timeline_response(
                [first],
                total_count=2,
                has_next_page=True,
                end_cursor="cursor-1",
            ),
            self.label_timeline_response(
                [second], total_count=1, end_cursor="cursor-2"
            ),
            self.label_timeline_response(
                [first],
                total_count=2,
                has_next_page=True,
                end_cursor="cursor-1",
            ),
            self.label_timeline_response(
                [first],
                total_count=2,
                has_next_page=True,
                end_cursor="cursor-1",
            ),
            self.label_timeline_response(
                [second], total_count=1, end_cursor="cursor-2"
            ),
        ]
        client = self.make_client(responses)

        snapshot = client.list_pull_request_label_timeline(REPOSITORY, 7)

        self.assertEqual(2, snapshot.total_count)
        self.assertEqual(
            ["LE_1", "LE_2"], [event.event_id for event in snapshot.events]
        )
        requests = [self.request_json(item) for item in self.transport.requests]
        self.assertEqual(
            [None, "cursor-1", None, None, "cursor-1"],
            [item["variables"]["after"] for item in requests],
        )
        self.assertEqual(
            [100, 100, 1, 100, 100],
            [item["variables"]["first"] for item in requests],
        )

    def test_label_timeline_rejects_incorrect_remaining_count(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        second = self.label_timeline_event(
            "UE_2",
            "cursor-2",
            typename="UnlabeledEvent",
            created_at="2026-07-25T01:02:04Z",
        )
        client = self.make_client(
            [
                self.label_timeline_response(
                    [first],
                    total_count=2,
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
                self.label_timeline_response(
                    [second], total_count=2, end_cursor="cursor-2"
                ),
            ]
        )

        with self.assertRaisesRegex(GitHubAPIError, "count changed") as raised:
            client.list_pull_request_label_timeline(REPOSITORY, 7)

        self.assertEqual("LABEL_TIMELINE_DISCONTINUITY", raised.exception.code)

    def test_tied_label_timestamp_sequence_change_is_discontinuity(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        second = self.label_timeline_event("LE_2", "cursor-2")
        client = self.make_client(
            [
                self.label_timeline_response(
                    [first, second], total_count=2, end_cursor="cursor-2"
                ),
                self.label_timeline_response(
                    [first], total_count=2, has_next_page=True, end_cursor="cursor-1"
                ),
                self.label_timeline_response(
                    [second, first], total_count=2, end_cursor="cursor-1"
                ),
            ]
        )

        with self.assertRaises(GitHubAPIError) as raised:
            client.list_pull_request_label_timeline(REPOSITORY, 7)

        self.assertEqual("LABEL_TIMELINE_DISCONTINUITY", raised.exception.code)

    def test_label_timeline_preserves_all_actor_types_and_null(self):
        actor_cases = (
            ("Bot", "B_bot", 101, "app[bot]"),
            ("Mannequin", "M_imported", 102, "imported"),
            ("Organization", "O_org", 103, "example-org"),
            ("EnterpriseUserAccount", "E_enterprise", None, "enterprise-user"),
            ("User", "U_user", 104, "approver"),
            ("User", "U_ghost", 10137, "ghost"),
            (None, None, None, None),
        )
        for index, (actor_type, node_id, database_id, login) in enumerate(actor_cases):
            with self.subTest(actor_type=actor_type, login=login):
                edge = self.label_timeline_event(
                    f"LE_{index}",
                    f"cursor-{index}",
                    actor_type=actor_type,
                    actor_node_id=node_id,
                    actor_database_id=database_id,
                    actor_login=login,
                )
                response = self.label_timeline_response(
                    [edge], total_count=1, end_cursor=edge["cursor"]
                )
                client = self.make_client(
                    [
                        response,
                        self.label_timeline_response(
                            [edge], total_count=1, end_cursor=edge["cursor"]
                        ),
                    ]
                )
                event = client.list_pull_request_label_timeline(
                    REPOSITORY, 7
                ).events[0]
                self.assertEqual(actor_type, event.actor_type)
                self.assertEqual(node_id, event.actor_node_id)
                self.assertEqual(database_id, event.actor_database_id)
                self.assertEqual(login, event.actor_login)

    def test_label_timeline_rejects_cursor_and_event_repetition(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        duplicates = (
            self.label_timeline_event(
                "LE_1", "cursor-2", created_at="2026-07-25T01:02:04Z"
            ),
            self.label_timeline_event(
                "LE_2", "cursor-1", created_at="2026-07-25T01:02:04Z"
            ),
        )
        for duplicate in duplicates:
            with self.subTest(duplicate=duplicate):
                client = self.make_client(
                    [
                        self.label_timeline_response(
                            [first],
                            total_count=2,
                            has_next_page=True,
                            end_cursor="cursor-1",
                        ),
                        self.label_timeline_response(
                            [duplicate],
                            total_count=1,
                            end_cursor=duplicate["cursor"],
                        ),
                    ]
                )
                with self.assertRaisesRegex(GitHubAPIError, "repeated"):
                    client.list_pull_request_label_timeline(REPOSITORY, 7)

    def test_label_timeline_rejects_snapshot_change_and_backwards_order(self):
        first = self.label_timeline_event(
            "LE_1", "cursor-1", created_at="2026-07-25T01:02:04Z"
        )
        second = self.label_timeline_event(
            "LE_2", "cursor-2", created_at="2026-07-25T01:02:03Z"
        )
        cases = (
            [
                self.label_timeline_response(
                    [first],
                    total_count=2,
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
                self.label_timeline_response(
                    [second],
                    total_count=1,
                    updated_at="2026-07-25T01:04:00Z",
                    end_cursor="cursor-2",
                ),
            ],
            [
                self.label_timeline_response(
                    [first],
                    total_count=2,
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
                self.label_timeline_response(
                    [second], total_count=1, end_cursor="cursor-2"
                ),
            ],
        )
        for responses in cases:
            with self.subTest(responses=responses):
                client = self.make_client(responses)
                with self.assertRaises(GitHubAPIError):
                    client.list_pull_request_label_timeline(REPOSITORY, 7)

    def test_label_timeline_rejects_watermark_change(self):
        first = self.label_timeline_event("LE_1", "cursor-1")
        client = self.make_client(
            [
                self.label_timeline_response(
                    [first], total_count=1, end_cursor="cursor-1"
                ),
                self.label_timeline_response(
                    [first],
                    total_count=2,
                    updated_at="2026-07-25T01:04:00Z",
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
            ]
        )
        with self.assertRaisesRegex(GitHubAPIError, "verification completed"):
            client.list_pull_request_label_timeline(REPOSITORY, 7)

    def test_remove_label_url_encodes_name_and_validates_response(self):
        client = self.make_client(
            [
                FakeResponse(
                    [
                        {
                            "id": 1,
                            "node_id": "LA_remaining",
                            "name": "remaining",
                        }
                    ]
                )
            ]
        )

        result = client.remove_label(REPOSITORY, 7, "merge approved/now")

        self.assertEqual("remaining", result[0]["name"])
        api_request = self.transport.requests[0]
        self.assertEqual("DELETE", api_request.method)
        self.assertTrue(api_request.full_url.endswith(
            "/issues/7/labels/merge%20approved%2Fnow"
        ))

    def test_remove_label_404_and_timeout_are_not_success(self):
        failures = (
            FakeResponse({"message": "not found"}, status=404),
            error.URLError("timed out"),
        )
        for failure in failures:
            with self.subTest(failure=failure):
                client = self.make_client([failure])
                with self.assertRaises(GitHubAPIError):
                    client.remove_label(REPOSITORY, 7, "hermes:merge-approved")
                self.assertEqual(1, len(self.transport.requests))

    @staticmethod
    def review_threads_response(nodes, has_next_page=False, end_cursor=None):
        return FakeResponse(
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": nodes,
                                "pageInfo": {
                                    "hasNextPage": has_next_page,
                                    "endCursor": end_cursor,
                                },
                            }
                        }
                    }
                }
            }
        )

    def test_unresolved_review_threads_paginates_and_finds_unresolved(self):
        client = self.make_client(
            [
                self.review_threads_response(
                    [{"isResolved": True}],
                    has_next_page=True,
                    end_cursor="cursor-1",
                ),
                self.review_threads_response([{"isResolved": False}]),
            ]
        )

        self.assertTrue(client.has_unresolved_review_threads(REPOSITORY, 7))
        first = self.request_json(self.transport.requests[0])
        second = self.request_json(self.transport.requests[1])
        self.assertEqual(first["variables"]["after"], None)
        self.assertEqual(second["variables"]["after"], "cursor-1")
        self.assertEqual(second["variables"]["number"], 7)
        self.assertIn("reviewThreads(first: 100", second["query"])

    def test_review_threads_returns_false_when_all_are_resolved(self):
        client = self.make_client(
            [self.review_threads_response([{"isResolved": True}])]
        )
        self.assertFalse(client.has_unresolved_review_threads(REPOSITORY, 7))

    def test_review_threads_invalid_or_null_data_fails_closed(self):
        for payload in (
            {"data": {"repository": None}},
            {"data": {"repository": {"pullRequest": None}}},
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"isResolved": False}],
                                "pageInfo": {
                                    "hasNextPage": None,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [{"isResolved": None}],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    }
                }
            },
        ):
            with self.subTest(payload=payload):
                client = self.make_client([FakeResponse(payload)])
                with self.assertRaises(GitHubAPIError):
                    client.has_unresolved_review_threads(REPOSITORY, 7)

    def test_review_threads_rejects_repeated_cursor(self):
        client = self.make_client(
            [
                self.review_threads_response([], True, "same-cursor"),
                self.review_threads_response([], True, "same-cursor"),
            ]
        )
        with self.assertRaisesRegex(GitHubAPIError, "cursor"):
            client.has_unresolved_review_threads(REPOSITORY, 7)

    def test_review_threads_validates_before_network(self):
        client = self.make_client([])
        with self.assertRaises(GitHubAuthError):
            client.has_unresolved_review_threads("Other/repository", 7)
        with self.assertRaises(ValueError):
            client.has_unresolved_review_threads(REPOSITORY, 0)
        self.assertEqual(self.transport.requests, [])

    def test_convert_to_draft_uses_graphql_node_id(self):
        client = self.make_client(
            [
                FakeResponse({"node_id": "PR_node_7"}),
                FakeResponse(
                    {
                        "data": {
                            "convertPullRequestToDraft": {
                                "pullRequest": {
                                    "id": "PR_node_7",
                                    "isDraft": True,
                                }
                            }
                        }
                    }
                ),
            ]
        )

        result = client.convert_pull_request_to_draft(REPOSITORY, 7)

        self.assertTrue(result["isDraft"])
        graphql_request = self.transport.requests[1]
        graphql_body = self.request_json(graphql_request)
        self.assertEqual(
            graphql_body["variables"], {"pullRequestId": "PR_node_7"}
        )
        self.assertIn("convertPullRequestToDraft", graphql_body["query"])

    def test_graphql_errors_fail_closed(self):
        client = self.make_client(
            [FakeResponse({"errors": [{"message": "permission denied"}]})]
        )
        with self.assertRaisesRegex(GitHubAPIError, "permission denied"):
            client.convert_pull_request_to_draft(
                REPOSITORY, 7, pull_request_node_id="PR_node_7"
            )

    def test_squash_merge_rechecks_and_sends_exact_head_sha(self):
        client = self.make_client(
            [
                FakeResponse(
                    {
                        "state": "open",
                        "draft": False,
                        "head": {"sha": HEAD_SHA},
                    }
                ),
                FakeResponse(
                    {"merged": True, "sha": "f" * 40, "message": "merged"}
                ),
            ]
        )

        result = client.squash_merge(
            REPOSITORY,
            7,
            expected_head_sha=HEAD_SHA,
            commit_title="Title",
        )

        self.assertTrue(result["merged"])
        merge_request = self.transport.requests[1]
        self.assertEqual(merge_request.method, "PUT")
        self.assertEqual(
            self.request_json(merge_request),
            {
                "merge_method": "squash",
                "sha": HEAD_SHA,
                "commit_title": "Title",
            },
        )

    def test_squash_merge_aborts_before_write_when_sha_changed(self):
        client = self.make_client(
            [
                FakeResponse(
                    {
                        "state": "open",
                        "draft": False,
                        "head": {"sha": "f" * 40},
                    }
                )
            ]
        )

        with self.assertRaisesRegex(GitHubAPIError, "head SHA changed"):
            client.squash_merge(
                REPOSITORY, 7, expected_head_sha=HEAD_SHA
            )
        self.assertEqual(len(self.transport.requests), 1)

    def test_disallowed_repository_is_rejected_before_token_or_network(self):
        client = self.make_client([])
        with self.assertRaises(GitHubAuthError):
            client.get_pull_request("Other/repository", 1)
        self.assertEqual(self.auth.token_repositories, [])
        self.assertEqual(self.transport.requests, [])

    def test_input_validation_rejects_unsafe_merge_sha(self):
        client = self.make_client([])
        with self.assertRaises(ValueError):
            client.squash_merge(
                REPOSITORY, 7, expected_head_sha="main"
            )
        self.assertEqual(self.transport.requests, [])


if __name__ == "__main__":
    unittest.main()
