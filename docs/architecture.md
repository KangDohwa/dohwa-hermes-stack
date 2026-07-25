# Architecture

## Purpose and boundary

This repository packages local integrations around a pinned Hermes Agent
container image. It does not contain or mirror the upstream source tree.

There are two independent runtime planes:

1. the Hermes gateway, which receives chat events and runs the agent; and
2. the GitHub reviewer, which evaluates pull requests and publishes bounded
   review feedback.

Candidate CI is a third, currently inactive plane. Its checked-in files define
security contracts and fail-closed validation, but its runtime profile is not
provisioned.

## Gateway image

`Dockerfile.hermes` starts from an immutable upstream image reference. The
build:

1. installs the local Discord presence module;
2. checks and applies the reviewed upstream patches;
3. compiles each affected Python module; and
4. performs an import smoke test.

A changed upstream anchor makes the image build fail. This prevents an upgrade
from silently skipping a local security or lifecycle hook.

The gateway uses repository-relative mounts for runtime data and workspaces.
Their contents are outside the public source boundary and must remain ignored.

## Reviewer services

```text
                         +--------------------+
Signed repository event |                    |
------------------------>|    Orchestrator    |----> GitHub review
                         |                    |----> private report
                         +----------+---------+
                                    |
                         +----------+----------+
                         |                     |
                         v                     v
                  +-------------+       +---------------+
                  |  Analyzer   |       | Test executor |
                  | no App key  |       | no network    |
                  +-------------+       +---------------+
```

The orchestrator owns authenticated GitHub operations and durable state. It
verifies inbound signatures, fetches authoritative pull-request data, applies
the repository policy, and coordinates work.

The analyzer receives bounded, untrusted review material. It does not need the
GitHub App private key or webhook verification secret.

The executor receives a bounded source archive and an allowlisted command
profile. It runs without network access in a temporary work directory. Its
result is evidence for review, not authorization to merge.

## Trust boundaries

The following inputs are untrusted:

- webhook bodies before signature verification;
- pull-request titles, bodies, comments, branches, and patches;
- repository files and instructions;
- test output and generated archives; and
- model output.

The orchestrator validates identities, sizes, state transitions, and repository
allowlists before acting on those inputs. Analyzer or executor output cannot
mint a GitHub credential or bypass the operating mode.

Secrets belong only in the components that require them. The analyzer and
executor must not receive GitHub App private keys, webhook verification
secrets, or reporting credentials.

## State and recovery

Reviewer state and spool directories are runtime data. They are not portable
source artifacts and may contain repository metadata or review content.

Recovery must preserve the distinction between:

- a requested operation;
- a locally recorded intent;
- a request that may have reached an external service; and
- an authoritatively reconciled result.

Ambiguous external writes fail closed and require reconciliation. They are not
blindly retried.

## Current modes

The reviewer runs in comment mode. It may submit review feedback but does not
draft or merge pull requests.

Candidate CI is unprovisioned. Automatic merge is disabled. The architecture
documents the intended boundaries without claiming that the inactive path is
production-ready.
