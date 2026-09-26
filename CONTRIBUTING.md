# Contributing

PhantoWD EX4 is not ready for general device flashing. Start with the
[README](README.md) for the current source/build boundary and the
[implementation roadmap](ROADMAP.md) for scoped work packets and acceptance tests.

## Working agreement

- Use `develop` as the integration base; check open PRs before duplicating work.
- Select a roadmap task ID. Read the existing component contract and tests;
  identify authority, state transitions, failure behavior and explicit non-goals.
- Keep changes independently reviewable. Reuse existing typed stores, validators
  and privileged boundaries instead of creating parallel owners.
- Never upload proprietary WD firmware, device dumps, credentials, private
  network details, signing keys or user data.
- Hardware claims require exact model/revision, artifact identity and evidence.
  Host/QEMU success does not authorize NAS boots, data-disk tests or flash writes.
- Do not provide or execute unverified installation/recovery commands.

## Tests and handoff

Use the [validation ladder](ROADMAP.md#validation-ladder). Report the exact
commit, commands, environment, results and remaining limits. Include negative,
concurrency and interruption tests for the behavior being changed. Exercise
effective access and persistence where applicable, not only exit codes.

The [fast QEMU lane](support/QEMU-FAST-TESTS.md) is an iteration tool, not a
substitute for clean package/kernel builds or hardware qualification.
Do not hide failures with retries, relaxed guards, fabricated observations or
lazy unmounts.

## Documentation is part of the change

Before a behavior-changing PR is ready:

- Update the README capability table and concise roadmap when user-visible
  support changes. Describe what the checked-out source actually provides.
- Update the detailed roadmap task and the relevant component contract.
  Distinguish implementation, local tests, clean CI, hardware observation and
  product qualification.
- Keep build prerequisites and source versions consistent with scripts,
  module files and `versions.env`.
- Verify relative links/anchors and documented commands. Keep operator history,
  temporary addresses, transcripts and obsolete experiment narratives out of
  the README.
- Link validation to its exact commit. The live `develop` badge is integration
  status, not proof for another branch or permission to install an artifact.
- A release PR must update installation/upgrade/recovery guidance for its exact
  signed assets and supported compatibility matrix.

Documentation-only changes do not justify rebuilding all historical firmware
targets. Preserve workflow path filters and check documentation locally.

## Licensing

Original contributions are accepted under Apache-2.0 unless clearly derived
from an upstream work under another compatible license. Linux kernel and
device-tree derivatives remain GPL-2.0-only; other upstream components retain
their licenses. Preserve SPDX metadata and update `REUSE.toml` for paths not
already covered. See [LICENSE-POLICY.md](LICENSE-POLICY.md).
