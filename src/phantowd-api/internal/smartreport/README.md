<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Internal offline SMART report observation

M8.5 prerequisite only. `Parse` interprets supplied bytes and a separately
observed process exit value; it never executes `smartctl`, opens a device,
sends an ioctl or starts a self-test. No HTTP endpoint, scheduler, history,
notification, product installation or privilege expansion is added.

The explicit profiles are release smartctl **7.4 and 7.5**, JSON **1.0**, ATA
info+health fields. 7.4 matches the stock recipe in pinned Buildroot 2025.02.18;
7.5 is admitted after separate upstream/archive and actual native-producer
verification. Neither package is selected in the firmware. Version strings do not authenticate
an executable or prove provenance. Other versions/formats require separately
verified profiles rather than silently inheriting support.

The private observation retains only fixed states, assessment and exit flags;
JSON serialization is refused. Raw identity/path/model/serial/WWN, tool messages,
arguments, timestamps and vendor counters are not retained. A future public DTO
must be separate and describe collection scope, device generation and age.

## Meaning and refusals

- Exit bits 0–2 describe collection errors. Bit 1 alone cannot distinguish a
  failed open/IDENTIFY from a low-power skip. We do not call it "standby".
- Bit 3 is a reported failing SMART status; bit 4 denotes current prefail
  thresholds; bits 5–7 preserve historical threshold/error/self-test-log flags.
  Historical flags alone are not a present disk-failure verdict.
- A partial collection may still contain an explicit failing status. Preserve
  it with `Partial`; do not replace it with a reassuring blank report.
- `ReportedPass` means only the tool reported pass. It is not verified disk
  health, filesystem/RAID health, complete check coverage or data integrity.
- Process exit zero alone is not pass: upstream can return zero when SMART is
  disabled, with no health result. This remains `Disabled` / `NoAssessment`.
- Missing mandatory health fields, contradictory `passed`/bit 3, mismatched
  embedded/process exit, null/wrong-type known fields and contradictory
  support state refuse with no observation and a fixed, redacted error.
- Non-ATA protocols return `UnsupportedProtocol` without ATA flags or assessment.
  SMART-disabled and unavailable capability states remain separate. These are
  the tool's reported booleans, not independently verified hardware capability
  or enablement: ATA identify/cached-state uncertainty remains upstream. Neither
  path enables SMART nor suggests running a drive mutation.
- One UTF-8 object, at most 64 KiB / depth 12 / 8192 value+key tokens;
  strings at most 4096 bytes and keys 128 bytes. Entire ignored subtrees are
  validated and bounded. Duplicate/case-alias keys and replacement characters
  (including repaired unpaired-surrogate escapes) are refused. This deliberately
  narrow profile can reject otherwise valid large/vendor-rich JSON; no truncation
  or partial success is allowed. Unknown fields and their nulls are discarded.

## Separate optional ATA temperature projection

`ParseATATemperature` uses the same bounded decoder, release/schema checks and
health/exit semantics, but separately validates optional `temperature.current`.
The original info+health `Parse` and identity comparison are unchanged. Its
opaque result retains health plus an optional integer Celsius value; missing
is not zero, and JSON serialization/deserialization is refused. Malformed,
null, fractional/exponent, wrong-case, contradictory or out-of-profile values
refuse atomically. Non-ATA reports do not gain ATA temperature interpretation;
disabled/unsupported/unavailable reports do not publish a temperature sample.

The interval **-128..127 is a producer representation bound, not an operating
range**. In the hash-pinned 7.4/7.5 archives, `atacmds.cpp`'s attribute helper
emits only 1..127; zero and other raw bytes are omitted, not reported as zero.
`ataprint.cpp` also emits signed-byte device-statistics/SCT values. The global
JSON field does not identify which source supplied it. A supplied negative or
zero value is therefore retained as tool-reported, not reinterpreted as an
attribute value, an authenticated sensor, fresh sample or calibrated safe input.
The SCT path's sentinel handling is not a universal rule for all source paths.

The separate actual-producer fixture uses fixed `-j -i -H -A -` and invented
attribute194 values37,0,127,255. Native7.4/7.5 and static7.5 in ARM926 QEMU pass:
37/127 are reported;0/255 are absent. Original seven info+health cases and eight
native checksum/power controls remain. Negative/device-statistics/SCT cases
have parser/static-source coverage, not actual-producer replay qualification.
No collector, command approval, disk access, history, UI or fan policy is added.

## Remaining product gates

`ParseMatchingATAIdentity` is a separate **offline comparison prerequisite**:
it requires both an exact printable-ASCII serial (1..20 bytes, no surrounding
whitespace) and an NAA-5 WWN supplied by a separately trusted caller. It uses
the same bounded decoder and health semantics as `Parse`, then checks the
report's exact ATA protocol/serial and integer `wwn.naa`/`oui`/`id` fields.
WWN components are bounded to4/24/36 bits and combined as integer bits, never
floating point. There is no trimming, case folding, report-derived expected
identity or serial-only/path/bay fallback. Missing or unsupported identity
evidence refuses with no projection and a fixed error. Matching disabled or
unsupported-SMART reports retains their no-assessment state. `Parse` itself
continues to accept its original profile without requiring identity fields.

The field layout is inspected in the locally hash-verified upstream7.4/7.5
archives (`ataprint.cpp`, `print_drive_info`). The narrow comparison profile
is not a promise that all ATA identifiers fit it or that sysfs VPD and ATA
IDENTIFY strings have equivalent representations. Windows units/vet, all256
exit projections per release, negative/numeric/privacy controls and fuzz pass.
Pinned Go 1.26.8 Linux vet/race3 and real generic-only native 7.4/7.5 reports
now pass the comparison and mismatch controls. The actual static7.5 producer,
full tagged parser test binary and existing process-capture fixture also pass
in ARM926 QEMU with seven invented inputs and an unchanged base. This qualifies
these synthetic reports, not physical source/transport/standby or an installable
image. Root API cross-compilation alone would not prove these executions.

Matching identifiers in supplied JSON is **not report provenance**: copied or
forged JSON can match too. This function does not bind a process to a disk,
mint a census token/stable identity, inspect duplicates, authorize a command,
expose an endpoint or confer command authority. A private immutable
`ATAReportComparison` now fixes separately supplied expected fields for the
optional constructor-bound `smartcollect` comparison profile. It retains those
fields privately, rejects generic JSON and redacts ordinary formatting; the
returned observation still retains no raw identity. Its synthetic host/ARM
composition does not qualify expected-field origin or physical report attribution.
Provider/retained-device/transport/standby qualification remains required before
using the comparison as one check in an attributed collection pipeline.

Bind reports to a trusted retained device generation, exact executable/options,
bounded subprocess/output/time and explicit observed exit. Qualify ATA transport
and a standby-preserving collection policy (autodetection itself can wake a
drive); an offline parser proves none of these. Add truthful freshness/error
states, bounded history, vendor-aware counters, self-test authorization/progress,
deduplicated notifications and UI only after those boundaries are verified.
No NAS/disks, recovery or thermal gate is bypassed.

The opt-in [CPU-only producer fixture](../../../../support/SMART-REPLAY.md)
checks real upstream native 7.4/7.5 JSON from seven invented ATA stdin responses
per release, with explicitly pinned archives and identical refusal bounds.
It compiles only the generic backend, not a Linux device collector; no
physical transport/standby compatibility is established. The separate static
7.5 generic producer and Go projection fixture now passes in an ARM926 guest
against an unchanged manifest-verified base. Complete local rebuilt-image/
package/SBOM and guest/service integration subsequently passed on `dd55481`,
including this producer against the new base. Independent clean builds and
hosted feature qualification remain separate. Neither replay lane executes
physical ATA commands.

## Primary semantics

- [smartctl 7.4 exit status and no-check behavior](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/smartctl.8.in)
- [JSON initialization and emitted exit status](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/smartctl.cpp)
- [ATA support/assessment and partial-read fallback](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/ataprint.cpp)
- [Pinned Buildroot recipe](https://raw.githubusercontent.com/buildroot/buildroot/2025.02.18/package/smartmontools/smartmontools.mk)
- [7.5 JSON profile](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_5/smartmontools/smartctl.cpp)
- [7.5 ATA assessment/support](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_5/smartmontools/ataprint.cpp)
