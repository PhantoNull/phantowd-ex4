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

The same host workflow covers API-source changes with native Linux API vet,
ordinary tests, race tests and QEMU-tagged vet plus the proc-diagnostic contract,
using that exact SDK. It also checks the memory-only browser policy backend.
This stays one bounded host job: no Docker build, kernel compilation or QEMU
boot. It does not replace ARM execution, positive privileged lifecycle tests or
firmware qualification. Native tests may explicitly skip unsupported/root-only
cases; inspect the actual logs rather than treating a green job as those proofs.
The workflow can be dispatched on a contributor branch before requesting heavy
integration checks; it does not automatically hold/cancel a separate ARM job.
Workflow contracts run immediately after checkout, before SDK setup or tests.
The SDK-selector fixtures preserve exact LF/CRLF bytes and invoke the resolved
Bash executable; GNU/mawk binary mode prevents Windows text normalization from
turning a rejected pin into an accepted one. Keep that negative corpus strict.
Feedback-driver fixtures also run before SDK setup. Their unchanged driver
requires executable tmpfs, so CI prepares one private 256 MiB RAM mount under
the runner's temporary directory and verifies unmount during cleanup. Only that
ephemeral runner mount uses sudo; tests keep the ordinary runner identity.
No shared mount is remounted, no physical device is supplied and no guest boots.
All remaining command/mock and syntax contracts also precede Go SDK work; a
portable fixture must supply synthetic paths rather than evaluate Windows-only
launcher defaults on a Linux runner. Keep every existing check and budget.
The native API step explicitly requires a non-root runner and prints the focused
normal-serving startup tests before the complete suite, so their root-only skip
cannot silently stand in for positive non-root execution.
The same focused invocation also prints the native read-only kernel thermal
observation's status/count. An empty or unavailable host roster is reported
explicitly; it is not nonempty-sensor, calibration or EX4 qualification.

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
