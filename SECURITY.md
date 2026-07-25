# Security Policy

## Reporting a vulnerability

Do not include credentials, private repository data, webhook payloads, runtime
databases, logs, or exploit details in a public issue.

Use GitHub's private vulnerability reporting or a private security advisory for
this repository when available. If no private reporting channel is available,
open a minimal issue asking the maintainer to establish private contact. Do not
include technical details in that issue.

Include the following in the private report:

- the affected component and revision;
- the required preconditions and trust boundary;
- a minimal reproduction with secrets removed;
- the expected and observed behavior;
- the potential impact; and
- any suggested mitigation.

## Scope

Security reports are welcome for the local integration code in this repository,
including:

- the Hermes image build and patch application;
- the GitHub reviewer, webhook validation, and GitHub App authentication;
- reviewer spool, archive, and state handling;
- the isolated test executor;
- candidate-CI manifest and sandbox enforcement; and
- accidental credential or private-data exposure.

Issues in unmodified Hermes Agent behavior should be reported to the
[upstream project](https://github.com/NousResearch/hermes-agent) under its
security policy.

## Current operating guarantees

The shipped reviewer configuration is limited to comment mode. It is not
authorized to merge pull requests.

The candidate sandbox is unprovisioned and must fail before candidate execution
or privileged host mutation. Automatic merge remains disabled because there is
no verified atomic merge backend. Any change to these guarantees requires a
separate security review, negative tests, and an explicit deployment decision.

## Credential handling

Credentials must be supplied at runtime from outside the repository. Keep
private keys, webhook verification secrets, reporting credentials, ingress
credentials, state databases, logs, and backups out of Git and container image
layers.

If a credential is exposed:

1. revoke or rotate it immediately;
2. stop affected automation when continued use could cause harm;
3. determine where it was exposed, including branches, tags, pull requests,
   logs, artifacts, and caches;
4. remove it from the current tree and rewrite history when necessary; and
5. verify the cleaned repository with an independent secret scanner.

History rewriting is not a substitute for rotation.

## Deployment responsibility

This repository is a personal integration stack, not a managed service.
Operators are responsible for repository allowlists, GitHub App permissions,
secret storage, ingress protection, runtime isolation, backups, updates, and
monitoring.
