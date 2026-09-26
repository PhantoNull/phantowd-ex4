<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Development roadmap

PhantoWD aims to provide a maintainable WD My Cloud EX4 firmware distributed
through GitHub Releases, with a local web interface, modern file sharing,
recoverable updates and a conservative migration path for existing disks.
There is no installable release yet. This roadmap describes the work required
to get there; entries without linked verification remain planned.

## First-release product contract

The first release targets existing EX4 owners, with migration from the final
WD 2.13.108 firmware for explicitly qualified layouts and settings. Migration
must explain what can be preserved, what requires owner action and what is
unsupported before any mutation. Never imply that every legacy disk layout,
password representation or application can be imported safely.

Core features must be manageable from the authenticated local web panel:

| Capability | Required product behavior |
| --- | --- |
| SMB3 | File-service users, per-share access, permission previews and effective-access checks |
| NFS | Native exports, explicit client/network policy, UID/GID mapping and volume-safe lifecycle |
| iSCSI | Target/LUN creation, authentication, initiator/session visibility and guarded resize/removal |
| RAID | Qualified layouts, creation/import, member status, degraded/rebuild handling and guarded destructive operations |
| Disk health | Bounded periodic SMART observations/history, user-triggered extended tests, progress and error notifications |
| Front panel | Qualified status/color LEDs and LCD text, with hardware alarm priority over user preferences |
| Migration | Read-only assessment, supported data/configuration import, validation and a documented fallback path |

Legacy behavior is evidence to inspect, not code to preserve uncritically.
Review each capability against the extracted final firmware, its management
routes, persistent settings and hardware dependencies. Retain a traceable
replacement/retirement decision and fixture coverage. Manufacturing services,
unsupported cloud paths and insecure protocol defaults are not compatibility
requirements. Existing analysis does not mean all firmware behavior is known.

## Current evidence

| Area | Implemented and checked | Still required |
| --- | --- | --- |
| Software foundation | Pinned Buildroot/ARMv5 QEMU build, kernel source verification, package SBOM and license collection | Ongoing dependency/security maintenance and release license review |
| Reproducibility | Two clean builds matched the allowlisted artifacts for [one recorded commit](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36097108144) | Repeat on each release candidate and publish results |
| EX4 boot | Short diskless RAM boots reached readiness and halted | Stable board support and a tested recovery procedure |
| Management | QEMU administrator setup/login, sessions, optional TLS transport, responsive diagnostics dashboard | Durable configuration, account lifecycle, certificate lifecycle, service controls and recovery |
| Storage observation | Bounded sysfs block/VPD, Linux MD and existing-mount observations | Actual WD layout recognition, stable volume identities and qualified import |
| Storage research | Regular-file GPT, ext and MD inspectors, component comparisons, synthetic inventory assessment | Representative sanitized WD metadata corpus and empty-media integration tests |
| File services | Strict SMB/NFS policy and previews, atomic revision store, opt-in development save API, isolated QEMU access probes | Product accounts/state provisioning, storage qualification, activation/loss lifecycle and multi-client qualification |
| Updates | Host verification of signed release metadata, model/channel binding, payload hashes and version policy | Target installer, durable update state, rollback, key recovery and interruption testing |

The [API contract](src/phantowd-api/README.md) and
[research-tool contract](tools/phantowd-lab/README.md) define the current
boundaries. A successful parser, emulator boot or signed-payload check does
not establish disk compatibility, cooling safety or installability.

## Work that can advance on hosts and QEMU

### 1. Configuration and service domain

- Define a strict, versioned configuration for volume references, users,
  shares, network settings and service policy; reject unknown or ambiguous
  references. Keep identifiers independent of bay position and `/dev/sdX`.
- Separate desired configuration, observed state and operation results.
  Validate and preview a change before applying it.
- Implement durable configuration transactions and schema migrations on a
  temporary test filesystem: concurrent updates, interrupted writes, full
  storage, corrupt state and restart recovery must preserve a valid revision.
- Give long operations explicit states, cancellation rules and bounded logs.
  Define which steps can be retried and how incomplete work is recovered.
- Keep the HTTP service unprivileged. Any privileged helper must accept a
  small typed request set over a protected local interface, with independent
  validation and no arbitrary shell execution or caller-chosen executable.

Exit evidence: host failure tests and an ARMv5 QEMU restart test demonstrate
configuration recovery and refusal of invalid requests. Choosing the EX4's
persistent state location remains a separate hardware/layout decision.

### 2. Management interface and access

- Add password changes, logout-all/revocation, expiry and recovery policy;
  preserve bounded password-hashing work and generic authentication errors.
- Design first-owner enrollment and recovery without default passwords.
- Implement HTTPS certificate provisioning, renewal and replacement, with
  clear handling of device clock errors and changed names/addresses.
- Connect the UI to validated configuration previews and operation status;
  support keyboard navigation, narrow screens, partial failures and reconnects.
- Cache shared observations with explicit freshness and error state so
  additional browser clients do not multiply storage/controller probes.
- Review authorization, CSRF, request limits, error redaction and audit events
  for each operation; test service restarts and stale sessions.

Exit evidence: complete setup/login/configure/restart flows in QEMU, browser
verification and documented threat-model review before any LAN deployment.

### 3. Essential NAS services

- Integrate SMB3 users and share permissions, NFS exports with explicit client
  policy, and opt-in administrative SSH/SFTP.
- Add iSCSI target/LUN policy, authentication and active-session checks.
  Never mount a LUN's filesystem locally while an initiator owns it; capacity,
  deletion and backing-volume loss need explicit failure and recovery behavior.
- Render service configurations from validated objects; verify syntax before
  activation and retain the last working configuration on failure.
- Start shares only when their intended volume is present. A missing volume
  must never redirect writes into an empty directory on the system filesystem.
- Handle service crashes, unavailable volumes, read-only filesystems, full
  disks and shutdown ordering; report degraded service state in the UI.
- Add scheduled backup jobs, integrity-verification outcomes and restore
  workflows after basic sharing is qualified.

Exit evidence: isolated QEMU clients exercise permitted/denied access, restart,
volume-loss and capacity-failure cases against disposable virtual disks.

### 4. Storage identity, health and migration

- Collect a sanitized corpus for each supported WD single-volume/JBOD/RAID
  layout. Document the provenance and exact fields used for recognition.
- Correlate disk identity, partition identity, MD identity, filesystem identity
  and share references; refuse duplicate, missing, conflicting or unknown data.
- Parse SMART status with fixtures for unsupported devices, stale data,
  transport errors and failed health. A health warning must remain visible.
- Retain bounded health history, schedule lightweight checks without needless
  spin-ups, and provide separately authorized extended self-tests with progress,
  cancellation semantics and deduplicated error notifications.
- Model RAID creation/import/member replacement and rebuild as explicit jobs.
  Preview destructive effects and preserve identities; do not auto-assemble,
  repair or reshape an unknown array. Qualify supported RAID levels separately.
- Produce a read-only migration report covering recognized volumes, shares,
  owners/ACLs, free space, required backups and unsupported features.
- Map legacy users/groups, access rules, export paths and iSCSI backing objects
  to validated desired configuration. Flag incompatible credentials or ACLs
  for owner action rather than silently broadening access or dropping settings.
- Verify journal/recovery and MD assembly behavior before adding an importer;
  a read-only mount option alone is not a complete no-write guarantee.
- Qualify reorder, bay moves, missing members, degraded arrays and return to
  stock on dedicated empty media before admitting existing user disks.

Exit evidence: fixture corpus plus repeatable empty-media import, rollback and
data-integrity comparisons for every advertised layout. Unknown layouts stay
unsupported; no automatic formatting or implicit conversion.

### 5. Release tooling and efficient operation

- Maintain pinned source signatures/hashes and review dependency advisories;
  keep component selection compatible with ARMv5 and available resources.
- Measure image size, idle/peak RAM, CPU, boot time and request concurrency in
  QEMU, then establish hardware budgets from real measurements.
- Measure multi-client transfers and observation overhead, control log growth
  and avoid polling that unnecessarily prevents disk standby.
- Publish source, license material, SBOM, hashes, signed model-specific
  metadata, release notes, known limitations and validation evidence together.
- Run fast host checks for domain/tool changes, QEMU for runtime changes and
  the latest relevant EX4 probe for board changes. Keep clean release builds
  and reproducibility checks available independently of developer caches.

## Work requiring EX4 hardware evidence

| Gate | Required evidence before advancing |
| --- | --- |
| Network | Both physical ports, correct factory identities, simultaneous operation, reconnection and sustained link stability |
| Controller | Passive internal-UART captures establish framing, fields, checksums, ACK/retry behavior and asynchronous events; validate an open implementation against those captures |
| Cooling | Independently measured temperature, known safe fan/tach behavior, sensor/controller/daemon failure responses and bounded shutdown behavior |
| Board peripherals | SATA, USB, RTC, display, LEDs, buttons, watchdog and power behavior mapped and exercised with bounded tests |
| Recovery and flash | Exact model/revision, NAND geometry, ECC/OOB, bad blocks, boot validation, identity preservation, backup/restore and rescue entry independently reviewed and demonstrated |
| Storage | Empty expendable media, correct discovery and identity, safe removal/reinsertion, recovery behavior and verified data integrity |

The console UART and the internal controller UART are distinct interfaces.
No protocol command may be inferred safe merely from a selector name in a
vendor binary. QEMU cannot prove the EX4's electrical or thermal behavior.
Existing data disks are excluded from experimental firmware qualification.

## Installer and release qualification

The on-device installer follows the recovery and flash-layout evidence; an
A/B slot layout must not be assumed to fit or work with the existing bootloader.

1. Select and document a recoverable storage/boot layout and persistent state
   policy; preserve device identities and user data independently of OS slots.
2. Verify signatures, exact hardware compatibility, payload hashes, version
   policy, available space and power prerequisites before an update can start.
3. Implement durable installation progress, boot-pending state, health commit
   and rollback. Refuse ambiguous or partially verified states.
4. Exercise interrupted download, corrupt payload, failed verification, full
   state storage and restart boundaries in simulation.
5. On dedicated hardware, interrupt every durable installation/upgrade state
   and demonstrate recovery to a known system, including failed boot and
   interrupted state migration. Verify restored data, not just boot success.
6. Repeat install, upgrade, supported rollback and unbrick procedures from the
   published instructions on each advertised hardware revision.
7. Publish a limited opt-in beta with a compatibility matrix and recovery kit;
   resolve reproducible critical faults before declaring a stable release.

Production readiness requires sustained mixed-client I/O, thermal observation,
data-integrity checks, recovery drills, security review, upgrade testing and
reproducible release artifacts. Test duration, loads and numeric budgets must
be declared before qualification and published with the results.

## Later product features

Resource-qualified signed native applications, download clients, additional
backup targets, optional remote access and a mobile companion follow the core
NAS release. Each needs lifecycle, permission, resource and update contracts.
An application catalog must preserve the host's storage and recovery functions.
Additional NAS models require their own board definitions and qualification.

## Immediate development sequence

1. Confirm post-merge integration evidence for the read-only mount observer.
2. Integrate the implemented strict share-policy model and Linux revision store;
   validate the new ARMv5 QEMU probes before claiming guest execution evidence.
3. Extend restart/failure coverage to disposable persistent QEMU filesystems
   and define configuration recovery/migration before exposing writable APIs.
   Two independent ARMv5 boots now preserve the complete share policy on a
   generated ext2 disk, ignore a staged revision, reject corrupt state and
   refuse stale writers. This is clean-reboot evidence, not power-loss testing
   or qualification of the EX4 persistent-state location.
4. Extend the implemented standalone browser share-proposal form to full
   configuration management after persistence/recovery qualification.
   An authenticated, bounded stored-share-policy read endpoint now has an
   explicit Linux store adapter and post-reboot ARMv5 handler-dispatch tests.
   Its dashboard integration, HTTP save and product state provisioning remain
   incomplete; stored policy is never reported as active service state.
   Qualify effective POSIX permissions and runtime volume binding before service
   activation. Local ARMv5 QEMU has exercised HTTP/HTTPS previews, generated
   Samba grants with real Unix users (write/read/denial/ownership/symlink checks)
   and generated NFS exports on a disposable virtual disk; this does not
   qualify arbitrary product configurations or physical EX4 storage.
5. Connect trusted filesystem-identity qualification to the implemented Linux
   mount-descriptor guard, then integrate supervised SMB/NFS lifecycle using
   disposable QEMU disks. The guard's expected tuple is not yet produced by a
   qualified discovery/uniqueness/compatibility resolver. The guard now
   compares a mounted filesystem's kernel UUID with its expected policy UUID;
   an internal inventory can detect conflicts among supplied mounted ext
   devices, but cannot discover cloned identities on unmounted/omitted media.
   A separate libblkid descriptor helper now has host-native unmounted-image
   tests and static ARMv5 execution on two unmounted QEMU disks; clean package
   integration, block I/O-failure fixtures and trusted
   complete-device discovery must be qualified before connecting it.
   The native ext2/XFS collision fixture is refused without JSON; pinned
   libblkid collapses ambiguity into a generic error, never an empty result.
   The same collision is now refused in ARMv5 QEMU, with isolated signature
   controls, unchanged generated-image hashes and whole-set failure checks.
   A Linux single-slot helper supervisor now validates descriptors, bounded
   responses and cancellation; it is reused by the QEMU fixture. It does not
   establish eligible-device discovery, exclusivity or compatibility.
   Descriptor-set snapshots retain and recheck all provided objects, reject
   incomplete results and distinguish aliases from conflicting UUIDs before
   mounting. They report only the provided set, not global disk absence.
   Path-based service
   handoff and volume loss/recovery remain unimplemented.
6. Advance network/controller/recovery evidence on a separately reviewed
   hardware schedule; use those results to qualify the software on EX4.

Progress is tracked by demonstrated behavior and remaining release gates.
Neither a feature count nor a passing CI run substitutes for release qualification.
