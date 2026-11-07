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

Host toolkit CI selects the exact `GO_VERSION` compiler from `versions.env`
and checks the installed SDK before testing. A module's `go` directive is its
minimum language/toolchain requirement, not the CI compiler selector. Pin-only
changes trigger host CI as well as the applicable firmware qualification.

Use the [validation ladder](ROADMAP.md#validation-ladder). Report the exact
commit, commands, environment, results and remaining limits. Include negative,
concurrency and interruption tests for the behavior being changed. Exercise
effective access and persistence where applicable, not only exit codes.

For API/UI iterations on Windows, start with `support/test-api.ps1`; it does
not use Docker. If the pinned Buildroot image and workspace are already
available, `support/test-api-linux.ps1` additionally runs the full API vet/test
suite on Linux/amd64, including Linux-only tests; it reuses the workspace
read-only and never pulls/builds an image or creates a volume. This remains
host execution, not ARMv5/QEMU qualification. It bypasses the builder's ownership
repair entrypoint and runs UID/GID 1000 with no capabilities/no-new-privileges,
four CPUs, 2 GiB memory, 256 PIDs and 1 GiB disposable tmpfs. Its Linux suite
times out at 180 seconds with a 10-second termination grace; timeout/OOM/failure
does not trigger another run or resource cleanup. The full QEMU builder retains two
fixed named Docker volumes for incremental Buildroot output and compiler cache.
It requires 40 GiB free on the Docker data drive, but that is a start-time
guard, not a quota. Inspect
usage with `docker system df -v`; use
`support/clean-qemu-build-volumes.ps1 -WhatIf` before explicitly removing only
the unreferenced PhantoWD build volumes. Do not use broad Docker prune commands
to reclaim this project's space on a shared Docker installation.

Independent builds admit only a clean GitHub-hosted Ubuntu 24.04 x64 checkout
with at least 40 GiB free on both the checkout and Docker data filesystems.
If needed, that disposable job removes only unused host .NET, Android and
preinstalled tool-cache directories, then measures again before building.
The pinned container supplies subsequent build tools. Local/self-hosted callers
refuse before cleanup; no Docker prune is used. This is an initial headroom
policy, not a measured peak-space guarantee or a change to phase timeouts.
See the [runner environment contract](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).

The [fast QEMU lane](support/QEMU-FAST-TESTS.md) is an iteration tool, not a
substitute for clean package/kernel builds or hardware qualification.
Do not hide failures with retries, relaxed guards, fabricated observations or
lazy unmounts.

## Dashboard preview

For a synthetic dashboard preview, run `node support/dashboard-preview.mjs`
and open the printed loopback URL. This host helper never examines disks or
starts NAS services. `node support/test-dashboard-ui.mjs` also starts an
ephemeral loopback preview, checks every HTML asset's bytes and MIME type,
then closes it. These checks do not qualify browser rendering or accessibility.

## Qualified main promotions

Promotions use `chore/promote-...` branches and an exact qualified source tree.
Do not use `[skip ci]`: the lightweight **Promotion tree identity** check must
run. Include exactly one `Qualified-Commit: <40-hex SHA>` and one
`Qualified-QEMU-Run: <run ID>` trailer in the promotion commit. The run must be
the successful exact-head QEMU baseline with its small research-source receipt;
skipped jobs and receipt/checkout-tree mismatches refuse. The check compares the proposed
snapshot and prospective merge tree, then checks the actual main merge on push.
Require this named check on `main`; a skipped/missing required check must not
permit promotion. Firmware QEMU replay is skipped for these main snapshots;
manual qualification and development gates retain their existing budgets.

Independent reproducibility runs every Monday at 03:17 UTC on the default
branch once this workflow is promoted there, and on relevant `develop` input
pushes. The default-branch schedule cannot establish qualification for newer
unpromoted development commits. Manual dispatch remains available; see the
[schedule rules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
and [skip rules](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs).

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
