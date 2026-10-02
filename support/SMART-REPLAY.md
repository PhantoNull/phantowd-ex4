<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# CPU-only SMART producer oracle

`support/test-smart-replay.ps1` builds real upstream **smartctl 7.4 or 7.5** in a
disposable container with **only `os_generic.o`**, then uses its documented `-`
stdin pseudo-device with invented ATA debug responses. It does not install
smartmontools into the firmware, open a disk, use a Linux hardware backend,
update the drive database, run smartd or start a self-test.

## Inputs and invocation

First obtain the matching unmodified release archive from a trusted distribution.
Only these explicit version/hash pairs are accepted:

```text
smartmontools-7.4.tar.gz  e9a61f641ff96ca95319edfb17948cd297d0cd3342736b2c49c99d4716fb993d
smartmontools-7.5.tar.gz  690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e
```

These match the [pinned Buildroot recipe for 7.4](https://raw.githubusercontent.com/buildroot/buildroot/2025.02.18/package/smartmontools/smartmontools.hash)
and the [Buildroot 2026.08 recipe for 7.5](https://raw.githubusercontent.com/buildroot/buildroot/2026.08/package/smartmontools/smartmontools.hash).
The wrapper checks it on both sides of the container boundary; it never
downloads an archive, builds/pulls an image or creates a named volume.

With the existing pinned builder image and workspace available:

```powershell
.\support\test-smart-replay.ps1 -SourceArchive C:\path\smartmontools-7.4.tar.gz
.\support\test-smart-replay.ps1 -SmartctlVersion 7.5 -SourceArchive C:\path\smartmontools-7.5.tar.gz
```

The default version is 7.4; the archive name follows the explicitly selected
version under ignored `artifacts/smart-replay/`. The existing
workspace and repository are read-only; compilation and reports live only in
a 768 MiB tmpfs and are discarded on success or failure. The container runs as
UID/GID 1000, with no capabilities/network, no-new-privileges, two CPUs, a 1 GiB
memory limit and a PID limit. It does not expose physical devices. No output
binary, corpus, image, persistent build directory or daemon is installed.

## Assertions and limits

The fixture executes exactly `smartctl -j -i -H -`, without `-d`, against seven
synthetic inputs: reported pass/fail, partial collection with pass/fail,
unsupported SMART, disabled SMART and empty stdin. Unexpected exit/profile,
replay-order/coverage warnings or output fields fail the test. Independently
specified Go expectations consume the actual JSON through `smartreport.Parse`.
The Go test is opt-in via the `smartreplay` test build tag, never a product CLI.

Notably, upstream returns **exit 0 with no health assessment** when SMART is
reported disabled in this profile. A successful process exit must not become
`ReportedPass`. Empty input returns exit 2 without device evidence. The fixture
checks both, not merely that JSON parses.

For either known release, future/older versions, patch-version arrays and
pre-release metadata remain refused. Recognizing 7.5 is not accepting an
arbitrary version range or changing the profile's ATA info/health scope.

This is **native CPU-only actual-producer evidence using synthetic responses**.
It does not qualify an ARM producer, physical ATA transport, SMART ioctls,
standby/wake policy, device generations, executable authentication, real disk
health, counters/history, test jobs, scheduling, UI or notifications. Upstream's
replay implementation hardcodes the CHECK POWER MODE result; do not use it to
claim a standby-preserving collector. The independent pure-parser ARMv5 lane
remains in [the fast checks guide](QEMU-FAST-TESTS.md).

## ARM producer prerequisite

The current QEMU toolchain has C++ disabled and has no cross `g++`, `cc1plus`
or target `libstdc++`. smartmontools requires C++. The native oracle and ARM
parser are therefore distinct proofs, not an actual ARM producer test.

A real ARM producer fixture needs C++ enabled and a complete Buildroot rebuild,
not an unreviewed standalone replacement compiler. Keep the existing downloads
and bounded compiler cache, retire the obsolete generated output rather than
accumulating namespaces, and requalify all normal guest/service fixtures. Then
build only the generic stdin executable in disposable scratch, verify its
ARMv5 ABI/runtime closure, and run the fixed seven cases inside QEMU before
claiming an ARM producer pass. Do not install/start a real collector as a
side effect. Product collection has separate generation/privilege/wake gates.

Primary implementation references: [stdin pseudo-device](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/atacmds.cpp),
[generic backend](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/os_generic.cpp),
[ATA disabled-status handling](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/ataprint.cpp).
The [7.5 JSON initialization](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_5/smartmontools/smartctl.cpp)
and [ATA assessment flow](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_5/smartmontools/ataprint.cpp)
were reviewed separately before profile admission. See Buildroot's
[full-rebuild rules](https://buildroot.org/downloads/manual/manual.html#full-rebuild)
for toolchain changes.
