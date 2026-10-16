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

### Separate temperature profile

The same disposable producer builds also run four independent invented ATA
attribute194 traces through `smartctl -j -i -H -A -`. This does not change the
original seven traces or their `-j -i -H -` command. Raw37/127 must produce
`temperature.current`; raw0/255 must omit it. Treating absence as zero or 255
as a reported temperature fails the oracle. The tagged Go temperature test
uses its own fixed expectations, requires exactly four temporary reports and
checks the actual release plus unchanged health semantics.

Native7.4/7.5 and ARM926 static7.5 pass this profile on2026-10-16; all original
health/capture proofs remain required. The ARM runner additionally requires
four temperature producer rows, its parser PASS and the separate temperature
readiness marker. Existing guest/process/output/resource limits are unchanged;
no additional guest, image, volume or physical device is added. Host input and
fake-reply refusal tests do not count as actual-producer qualification.

This qualifies attribute temperature JSON only. Signed device-statistics/SCT
emitters, source authenticity, freshness, operating limits, transport, standby,
history, thermal control and product collection remain unqualified. See the
[offline projection contract](../src/phantowd-api/internal/smartreport/README.md#separate-optional-ata-temperature-projection).

### Identity comparison extension: scoped native and ARM qualification

The invented IDENTIFY response now includes WWN-support bit8 in word87 and
fixed words108..111 (`5abc def1 2345 6789`), alongside `SYNTHETIC-ONLY`.
The Python producer guard requires the exact serial and structured NAA/OUI/ID;
the tagged Go corpus test additionally compares them to independent constants
using `ParseMatchingATAIdentity`. It preserves every existing assessment/exit,
refuses a changed expected serial/WWN, and refuses identity attribution for the
empty input. The original seven cases, fixed command, timeouts and generic-only
backend remain unchanged. This does not authenticate a report's physical source.

Six fast host tests verify the invented words, support-bit independence, runner
acceptance/refusal with explicitly fake subprocess replies, and workflow routing.
Fake replies never emit producer proof markers. The new Python-only test is
routed to host checks; actual corpus/API changes still require QEMU. Windows
preflight and pinned Go 1.26.8 Linux units/tagged vet, focused race3, Python/lint/
shell/path contracts pass. Formatting fixes preserve all seven ATA trace hashes.

On 2026-10-16 the real generic-only native 7.4 and 7.5 producers each pass seven
comparison/projection cases plus eight existing checksum/power boundary cases.
The actual static7.5 producer, full tagged parser test binary and existing
fake-source process-capture fixture also pass in ARM926 QEMU. Exact injection,
original strict markers and unchanged-base checks remain. All fifteen selected
source/archive/base witnesses match before/after these producer runs. Reused
read-only caches and temporary RAM scratch create no image/named volume.

This is not a complete rebuilt image/SBOM/legal audit, independent clean build,
own-head hosted qualification, source provenance or physical transport/standby
qualification. The collector still uses invented source observations; no NAS,
device permission, privileged SMART command or product startup is enabled.

The same native wrapper additionally runs eight actual-producer boundary tests
for each explicitly selected release. These use only invented stdin replies:

| Case | Fixed options beyond info/health/stdin | Expected result |
| --- | --- | --- |
| Corrupt SMART attribute checksum | `--json` | Exit 0/reported pass; no checksum warning in JSON |
| Same corrupt input with original text | `--json=o` | Exit 0/pass; checksum warning only in nested original output |
| Corrupt attributes, strict checksum | `--json -b exit` | Exit 4/no health; no later ATA requests expected |
| Valid strict control | `--json -b exit` | Exit 0/pass |
| Power query EIO | `--json -n standby,3,5` | Exit 3/no health; 7.5 reports -1/SLEEP, not independent sleep proof |
| Power query ENOSYS, explicit stop | `--json -n standby,3,5` | Exit 5/no health |
| ENOSYS with default continuation | `--json -n standby` | Exit 0/pass after subsequent synthetic health reads |
| Successful generic power query | `--json -n standby,3,5` | Exit 0/pass; generic backend hardcodes 255, not standby coverage |

7.4 is checked independently and must omit `power_mode`; only 7.5's two
applicable cases contain that object. All cases require matching embedded/
observed exits, exact release/schema, bounded output, no stderr and complete
replay order. Power-option sentinel exits are **not** sent to the ordinary
health-bitmask parser. Tests inspect warning text only to characterize upstream
output selection, never to authorize a product collection result. These tests
do not approve a checksum/wake CLI, privilege or disk-command policy.

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

The same boot also runs the `smartcapture` test-only coordinator adapter through
`processowner.NewCapture`: independent fixed code/stdin pins, fixed arguments,
UID/GID 1000, separate streaming output bounds, real ordinary exit status,
settled owned-group verification and seven redacted report projections. A fake
source-generation change after successful capture must discard the sample and
retain review even after restoration. The source observations are explicitly
synthetic, not disk identity/provenance. Both parser and capture success markers
are required; neither test is replaced by a cross-compilation assertion.

The same capture binary/boot also runs `TestFixedProducerCaptureCompared`:
independently invented expected serial/WWN fixed at collector construction,
six matched health projections, missing identity, foreign serial, foreign WWN
and changed fake generation. Missing identity returns no sample, not attributed
unavailability. Compared-report/source refusals retain review with no producer
retry. A closed host receipt catalogue requires the parent and all ten leaf
passes plus exactly one comparison marker; missing, duplicate, lookalike, extra,
failed and skipped receipts refuse. Existing capture30s and guest90s limits,
original tests and code/stdin ownership remain unchanged. This proves report
consistency in the synthetic composition, not expected-field origin, physical
report provenance, standby or SMART authority. Guard controls join the existing
host suite; no extra CI stage or boot is added.

The two Go guest test binaries omit debug symbols to fit the existing 80 MiB
temporary filesystem without enlarging the base or removing product files.
Every injected trace/binary/init is dumped back and compared byte-for-byte before
boot. This matters because debugfs can return zero after an allocation failure.
Exact-byte refusal and the final unchanged-base hash are independent checks.
The primitive's Linux lifecycle/negative tests run separately, not in this guest.

The pinned ARM926 toolchain's static libraries can label the linked executable
`v5TEJ`, including when its own objects use `-march=armv5te`. The fixture admits
only the explicit `v5TE`/`v5TEJ` ARM926 guest profiles, not ARMv6/7 or hard-float.
Successful emulated execution does not qualify the EX4's physical CPU/board.

**Focused ARM execution now passes:** the rebuilt C++ toolchain's actual static
7.5 producer and all seven Go projections passed in the ARM926 guest using the
manifest-verified earlier base, whose hashes stayed unchanged. The subsequent
complete local run on `dd55481` also passed rebuilt-image/package/legal-info/
SBOM integration, all existing guest/service fixtures and this actual producer
against the newly generated base; seven artifact hashes were independently
verified. It reused verified source/compiler caches, not independent clean
builds. Hosted feature qualification and license/distribution review remain
separate. The native oracle and pure parser passes alone do not prove the producer.
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
