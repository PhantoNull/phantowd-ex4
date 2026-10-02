<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Internal offline SMART report observation

M8.5 prerequisite only. `Parse` interprets supplied bytes and a separately
observed process exit value; it never executes `smartctl`, opens a device,
sends an ioctl or starts a self-test. No HTTP endpoint, scheduler, history,
notification, product installation or privilege expansion is added.

The initial profile is release smartctl **7.4**, JSON **1.0**, ATA info+health
fields. This matches the stock recipe in pinned Buildroot 2025.02.18; the
package is not selected in the firmware. Version strings do not authenticate
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

## Remaining product gates

Bind reports to a trusted retained device generation, exact executable/options,
bounded subprocess/output/time and explicit observed exit. Qualify ATA transport
and a standby-preserving collection policy (autodetection itself can wake a
drive); an offline parser proves none of these. Add truthful freshness/error
states, bounded history, vendor-aware counters, self-test authorization/progress,
deduplicated notifications and UI only after those boundaries are verified.
No NAS/disks, recovery or thermal gate is bypassed.

## Primary semantics

- [smartctl 7.4 exit status and no-check behavior](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/smartctl.8.in)
- [JSON initialization and emitted exit status](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/smartctl.cpp)
- [ATA support/assessment and partial-read fallback](https://raw.githubusercontent.com/smartmontools/smartmontools/RELEASE_7_4/smartmontools/ataprint.cpp)
- [Pinned Buildroot recipe](https://raw.githubusercontent.com/buildroot/buildroot/2025.02.18/package/smartmontools/smartmontools.mk)
