# Upstream Customizations

## Relationship to Hermes Agent

This repository is an image-based integration stack. It does not vendor, fork,
or mirror the Hermes Agent source tree.

The gateway build starts from a version- and digest-pinned
[Hermes Agent](https://github.com/NousResearch/hermes-agent) image. Local files
are then installed or applied to the image in a narrow, reviewable layer.

## Presence overlay

`overlays/discord_presence.py` is installed as a local Discord presence module.
It tracks gateway lifecycle state without turning presence failures into
gateway failures.

The corresponding unit tests cover the local state transitions and integration
contract.

## Dynamic-presence patch

`patches/discord-dynamic-presence.patch` adds the small gateway and Discord
adapter hooks needed by the local presence module.

The image build first runs `git apply --check`. If the upstream files no longer
match the reviewed anchors, the build stops. The patch is never applied with a
fuzzy or best-effort fallback.

After applying the patch, the build compiles the affected modules and performs
an import smoke test.

## Upgrade procedure

Treat every upstream version change as a code integration:

1. read the upstream release notes and compare the exact old and new revisions;
2. update the base image tag and immutable digest together;
3. inspect each patched upstream area for semantic changes;
4. rebase the patch instead of weakening its anchors;
5. rebuild the image from a clean context;
6. run the complete local unit and security-contract test suite;
7. verify gateway startup and presence behavior in a non-production
   environment; and
8. retain a tested rollback image and a consistent runtime-data backup.

Do not reuse a patch merely because it still applies syntactically. The
surrounding upstream lifecycle and security assumptions must also remain valid.

## Runtime data

Agent configuration, authentication material, sessions, memory, databases,
logs, workspaces, and backups are runtime state. They are intentionally outside
the source tree and must not be copied into public examples or diagnostic
artifacts.

Before an upgrade that may migrate state:

- stop writers or use an application-consistent backup method;
- capture all related database sidecar files;
- record the old image identity and schema state privately;
- test restore and rollback; and
- keep the backup outside Git.

## Attribution

The base image and patched files originate from the upstream Hermes Agent
project. Local patch files necessarily include upstream context. Preserve all
applicable upstream license and copyright notices when redistributing the
image or these patches.

This repository is independently maintained and is not endorsed by Nous
Research.
