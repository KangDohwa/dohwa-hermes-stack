# Third-Party Notices

## Hermes Agent

This project is an independently maintained deployment and integration stack
built on [Hermes Agent](https://github.com/NousResearch/hermes-agent) by Nous
Research.

The container build uses Hermes Agent
[`v2026.7.20`](https://github.com/NousResearch/hermes-agent/tree/v2026.7.20),
commit
[`3ef6bbd201263d354fd83ec55b3c306ded2eb72a`](https://github.com/NousResearch/hermes-agent/commit/3ef6bbd201263d354fd83ec55b3c306ded2eb72a),
under the MIT License.

Copyright (c) 2025 Nous Research

The complete upstream license is reproduced in
[`LICENSES/Hermes-Agent-MIT.txt`](LICENSES/Hermes-Agent-MIT.txt). The official
upstream copy is available at
<https://github.com/NousResearch/hermes-agent/blob/v2026.7.20/LICENSE>.

The upstream copyright and license notice applies to Hermes Agent source and
binaries inherited from the base container image, to upstream source context
included in `patches/discord-dynamic-presence.patch`, and to the patched
versions of `gateway/run.py` and `plugins/platforms/discord/adapter.py`
produced during the image build.

`overlays/discord_presence.py` is repository-authored integration code covered
by the root `LICENSE`. The image build installs it as
`plugins/platforms/discord/presence.py` within Hermes Agent and integrates it
with Hermes Agent internal APIs.

This project is not an official Nous Research project and is not affiliated
with, sponsored by, endorsed by, or maintained by Nous Research. Product names
and trademarks belong to their respective owners and are used only to identify
the upstream software and compatibility.
