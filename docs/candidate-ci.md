# Candidate CI

## Status

Candidate CI is a **fail-closed foundation**, not an active execution or merge
service.

The checked-in sandbox manifest declares itself unprovisioned. Runtime binary
digests and the container image use explicit sentinel values. The workflow
requires a provisioned manifest, so it exits before candidate code or privileged
host setup can run.

Automatic merge is disabled. No verified atomic merge backend is enabled.

## Intended binding

The design binds CI evidence to:

- the exact reviewed base commit;
- the exact reviewed head commit;
- a canonical merge descriptor;
- an immutable review context;
- an immutable workflow definition; and
- a unique dispatch attempt.

The coordinator must independently verify these identities when dispatching and
when reading the result. A successful job associated with a different commit,
workflow revision, repository, or attempt is not valid evidence.

## Workflow envelope

The workflow is manually dispatched by an authorized integration. It validates
bounded identifiers and a canonical descriptor before doing any setup.
Dispatch uses an allowlisted full `refs/heads/...` name whose create, update,
delete, and recreation are denied to ordinary repository credentials. The
allowlisted App is the sole ruleset bypass actor. The coordinator still requires
the resulting run's head SHA and fetched workflow bytes to match the approved
workflow revision exactly.

Its token permissions are read-only and it does not request an identity token.
It does not use third-party Actions. Candidate execution must not receive
repository write credentials, environment secrets, the GitHub App private key,
or private reporting credentials.

## Intended sandbox

Provisioning the inactive path would require a reviewed manifest containing
immutable identities for:

- the container runtime and low-level runtime;
- the signed test image and verification key;
- the command profile;
- the seccomp and AppArmor policies; and
- every trusted helper used outside the candidate boundary.

The intended candidate environment has:

- a dedicated unprivileged host identity;
- private user, PID, mount, network, IPC, and UTS namespaces;
- no network;
- no Linux capabilities;
- `no-new-privileges`;
- a read-only root filesystem;
- bounded temporary storage, processes, CPU, memory, file sizes, and output; and
- deterministic cleanup.

These are requirements, not claims about the current unprovisioned manifest.

## Fail-closed invariants

Candidate code must not run when:

- a manifest or asset digest is missing or mismatched;
- the runtime or image is not pinned and verified;
- the workflow revision is mutable or cannot be authenticated;
- the reviewed base, head, or descriptor changed;
- more than one workflow run could match the request;
- the sandbox probes do not demonstrate the required isolation; or
- output cannot be safely bounded and mediated.

Candidate-controlled files cannot redefine the trusted manifest, command
profile, runtime identity, or cleanup code.

## Merge boundary

A CI result is evidence, not authorization.

Before any future automatic merge, a separately reviewed backend must consume
approval and CI exactly once, bind them to the reviewed base and head, and use
a server-side compare-and-swap operation that rejects changed refs atomically.
Ambiguous network outcomes require authoritative reconciliation and must not be
blindly retried.

Until that backend and its negative canaries are verified, a passing review or
CI result cannot trigger an unattended merge.

## Provisioning checklist

Enabling this path requires, at minimum:

1. replace every sentinel runtime and image identity with reviewed immutable
   values;
2. verify the image signature and all manifest asset digests;
3. run positive and negative isolation probes on the exact hosted runner image;
4. test cleanup after success, failure, timeout, and interruption;
5. prove workflow-run correlation under delayed and duplicate visibility;
6. prove that no candidate path receives secrets or write credentials;
7. independently review the atomic merge backend; and
8. obtain an explicit operational approval.

Changing the manifest's boolean flag alone is not provisioning.
