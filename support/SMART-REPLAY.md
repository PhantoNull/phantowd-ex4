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

## ARM producer lane

The QEMU defconfig now requests the Buildroot C++ toolchain. This changes the
configuration namespace and requires a **complete rebuild**, not reuse of an
older C-only output or an unreviewed standalone compiler. Keep downloads and
the bounded compiler cache; retire obsolete generated outputs after verifying
ownership and no active builder. Requalify normal guest/service fixtures.

`support/test-smart-replay-arm.ps1` requires that rebuilt workspace, the
manifest-verified QEMU base and the pinned 7.5 archive. Missing cross `g++`
refuses before compilation or QEMU. It creates no image/named volume and uses
the same read-only/non-root/no-network container boundary as the native lane.

```powershell
.\support\test-smart-replay-arm.ps1 -SourceArchive C:\path\smartmontools-7.5.tar.gz
```

The runner statically cross-compiles only the generic stdin executable, checks
ELF32/ARM/v5TE-or-v5TEJ/soft-float and absence of a dynamic interpreter, generates seven
invented traces, and executes the actual producer and tagged Go projection
tests in a disposable ARM926 QEMU guest. The base is unchanged; its copied
root is read-only with a snapshot, there are no data disks or networking, and
reports live in private guest tmpfs. Configure/build/test/guest execution have
finite deadlines; the fixture cleans scratch on success or failure.
Full integration runs this lane against its just-built base and toolchain.

The pinned ARM926 toolchain's static libraries can label the linked executable
`v5TEJ`, including when its own objects use `-march=armv5te`. The fixture admits
only the explicit `v5TE`/`v5TEJ` ARM926 guest profiles, not ARMv6/7 or hard-float.
Successful emulated execution does not qualify the EX4's physical CPU/board.

**Focused ARM execution now passes:** the rebuilt C++ toolchain's actual static
7.5 producer and all seven Go projections passed in the ARM926 guest using the
manifest-verified earlier base, whose hashes stayed unchanged. This is not
complete C++ image/service/SBOM integration, which still needs a terminal full
build. The native oracle and pure parser passes alone do not prove the producer.
The test-only executable is not
installed in the product image, SBOM or service startup. C++ runtime libraries
selected by the toolchain are ordinary Buildroot dependencies and must be
reflected by the rebuilt artifacts. Product collection has separate
generation/privilege/wake gates; no collector or SMART job is activated.

Primary implementation references: [stdin pseudo-device](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/atacmds.cpp),
[generic backend](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/os_generic.cpp),
[ATA disabled-status handling](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/ataprint.cpp).
The [7.5 JSON initialization](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_5/smartmontools/smartctl.cpp)
and [ATA assessment flow](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_5/smartmontools/ataprint.cpp)
were reviewed separately before profile admission. See Buildroot's
[full-rebuild rules](https://buildroot.org/downloads/manual/manual.html#full-rebuild)
for toolchain changes.
