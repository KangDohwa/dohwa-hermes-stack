# GitHub Pull-Request Reviewer

## Status

The reviewer currently operates in **comment mode**.

For an eligible pull request it may:

- collect authoritative pull-request metadata and diff content;
- run the configured analysis and bounded tests;
- classify findings;
- publish a GitHub review comment; and
- send a private operational summary.

It must not convert a pull request to draft or merge it. A passing review is
advisory; it is not merge authorization.

## Components

### Orchestrator

The orchestrator is the only reviewer component that needs authenticated GitHub
access. It:

- validates signed webhook deliveries;
- checks the repository allowlist and target branch policy;
- resolves the current head, base, merge base, and diff;
- writes durable job state;
- dispatches work to the analyzer and executor;
- verifies their bounded responses; and
- publishes the permitted review action.

### Analyzer

The analyzer treats repository content and pull-request text as untrusted data.
It produces a structured decision rather than executable instructions.

It does not receive the GitHub App private key, webhook verification secret, or
private reporting credential.

### Executor

The executor runs only policy-defined commands. It uses:

- no network;
- a temporary work directory;
- bounded CPU, memory, process, and output limits;
- an explicit writable-path policy; and
- archive validation before extraction.

Test output informs the review decision but cannot authorize a GitHub write.

## Eligibility and policy

Repository policy defines:

- accepted base branches;
- file and changed-line limits;
- test commands;
- required checks;
- writable test paths;
- high-risk paths; and
- labels that require the reviewer to stop or defer.

The public configuration should contain only repositories intended for this
deployment. Do not publish the names or policies of unrelated private
repositories. When adapting this project, prefer an operator-owned policy file
or a sanitized example committed to source control.

A pull request is not eligible for unattended handling when its repository,
base branch, fork status, size, mutable state, or high-risk paths fall outside
the approved policy. The safe result is human review.

Operational canaries should use a harmless documentation-only change. Changes
to reviewer code, workflows, security policy, or deployment configuration are
high risk and must exercise the human-review path instead.

## Review lifecycle

1. Verify and deduplicate the inbound event.
2. Fetch authoritative pull-request state from GitHub.
3. Apply eligibility and high-risk gates.
4. Record a review attempt bound to the current repository and commit context.
5. Analyze the bounded diff and metadata.
6. Run only allowlisted tests in the isolated executor.
7. Validate the structured result.
8. Publish a comment-mode review if the context is still current.
9. Reconcile later repository events with durable state.

Head, base, or diff changes invalidate the old review context. A previous pass
must not be carried forward to changed code.

## GitHub App and secrets

Create a dedicated GitHub App with only the permissions needed by the enabled
mode. Install it only on explicitly approved repositories.

Provide the following values outside Git:

- the App identifier and slug;
- the App private key;
- the webhook verification secret;
- the repository allowlist; and
- the private report destination.

Use secret files or an operator-managed secret store. Do not place real values
in Compose files, images, examples, fixtures, logs, model input, or review
comments.

## Failure behavior

The reviewer fails closed when it cannot verify identity, policy, current
commit context, archive integrity, test bounds, or a structured result.

An unavailable automatic-merge backend does not degrade into a legacy merge
API call. The current system records the limitation and leaves merge decisions
to a human.
