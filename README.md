# Dohwa Hermes Stack

`dohwa-hermes-stack` is a personal deployment and integration stack built on
[Hermes Agent](https://github.com/NousResearch/hermes-agent).

This is **not an official Nous Research project**. It is not a fork or mirror of
the upstream source repository. The stack builds from a version- and
digest-pinned upstream container image, then applies a small set of local
patches, overlays, deployment settings, and review automation.

## What is included

- A pinned Hermes Agent gateway image with a Discord presence overlay.
- Build-time patches that fail when their expected upstream anchors change.
- An isolated GitHub pull-request reviewer composed of an orchestrator,
  analyzer, and network-disabled test executor.
- A candidate-CI security foundation for binding reviewed commits to a
  constrained test profile.
- Unit and security-contract tests for the local integrations.

The upstream agent source tree is not vendored here. Upstream behavior, CLI
usage, model support, and general Hermes documentation belong in the
[Hermes Agent repository](https://github.com/NousResearch/hermes-agent).

## Current safety status

The reviewer is intentionally configured for **comment mode**. It can analyze a
pull request and publish review feedback, but it must not convert the pull
request to draft or merge it.

Candidate CI and automatic merge are **not operational**:

- the candidate sandbox manifest is explicitly unprovisioned;
- runtime and image digests use fail-closed sentinel values;
- the workflow validates the manifest before any candidate code or privileged
  host setup is reached; and
- no verified atomic merge backend is enabled.

These conditions are deliberate safety gates, not setup bugs. Do not describe
this repository as providing unattended merge automation.

## Architecture

The gateway and reviewer are separate systems:

```text
Pinned upstream image
        |
        +-- local overlay and reviewed patches --> Hermes gateway

Signed GitHub event --> reviewer orchestrator --> analyzer
                                |
                                +---------------> isolated test executor
                                |
                                +---------------> review comment
```

Runtime data is stored in ignored directories such as `data/`, `workspace/`,
and `backups/`. Those directories may contain credentials, conversations,
state databases, logs, and recovery material. They are deployment data, not
repository content.

See:

- [Architecture](docs/architecture.md)
- [GitHub reviewer](docs/github-reviewer.md)
- [Candidate CI](docs/candidate-ci.md)
- [Upstream customizations](docs/upstream-customizations.md)
- [Security policy](SECURITY.md)

## Build the gateway

Review the pinned upstream version and local patches before every upgrade, then
build the gateway:

```bash
docker compose build gateway
```

Start it only after providing the runtime configuration and credentials through
operator-controlled secret storage:

```bash
docker compose up -d gateway
```

The reviewer stack is not a turnkey public service. Before deploying it, define
your own repository allowlist, GitHub App, webhook verification secret, report
destination, secret mounts, and ingress. Never copy credentials into Compose
files, images, test fixtures, or Git history.

## Verify

The repository's local tests can be run with:

```bash
python3 -m unittest discover -s tests -v
```

The candidate-CI tests verify the fail-closed foundation. Passing them does not
mean the sandbox is provisioned or automatic merge is enabled.

## Secrets

Required credentials depend on which services are enabled. Typical deployments
use a GitHub App private key, a webhook verification secret, and a private
reporting credential. Provide them through files or a secret manager outside
the repository.

Never commit:

- environment files containing real values;
- private keys, tokens, webhook URLs, or tunnel credentials;
- runtime databases, spools, logs, conversations, or backups; or
- screenshots and diagnostic bundles that may contain authenticated data.

If a credential is committed, revoke or rotate it before removing it from Git
history. See [SECURITY.md](SECURITY.md) for reporting guidance.

## Upstream relationship

The gateway build pins an upstream Hermes Agent release and checks that local
patches still apply exactly. An upstream upgrade is treated as a reviewed
integration change: update the image pin, rebase the patches, rebuild, and run
the full test suite.

Local patches contain context derived from upstream files. Preserve applicable
upstream copyright and license notices when redistributing this stack. This
repository does not imply endorsement by Nous Research.
