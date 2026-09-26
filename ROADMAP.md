<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation roadmap

Reviewed: **2026-09-26**. This is the product specification and work breakdown,
not a release announcement. The [README](README.md) is the concise entry point;
component contracts remain authoritative for implemented behavior.

## Product contract

Build a maintained, efficient, local-first replacement for the **WD My Cloud
EX4**, distributed through GitHub Releases. The first supported product must
provide authenticated web administration, SMB3, NFS, iSCSI, qualified storage/RAID
workflows, disk health, functional front-panel status, recoverable updates and
a documented migration path from WD 2.13.108 for explicitly supported layouts.

The target is ARMv5/Feroceon with approximately 512 MiB RAM. Select components
for this hardware, not desktop convenience. Existing data, stable ownership,
cooling and recovery take priority over feature count or visual polish.

### Non-negotiable boundaries

- No installable firmware exists yet. Build outputs and successful QEMU runs
  are not authorization to flash or use existing data disks.
- Each release binds to one exact model and supported hardware revisions.
  Other My Cloud models require separate board support and qualification.
- Never use bay number, `/dev/sdX`, a label, or a mount pathname as the sole
  persistent volume identity. UUIDs can collide and require whole-inventory checks.
- Missing/ambiguous/corrupt state is not an empty configuration. Refuse mutation
  and preserve evidence; never silently re-enroll, adopt, format or reuse IDs.
- Keep desired policy, observed state, operation outcome and validation freshness
  separate in storage, APIs and UI. Saving a policy must not claim activation.
- HTTP stays unprivileged. Privileged work uses bounded typed operations,
  independently validated authorization and fixed executable/configuration paths.
- No passwords, hashes, tokens or private keys in argv, journals, API errors,
  diagnostics, repository artifacts or public logs.
- No experimental NAND/flash writes before reviewed format, ECC/OOB, bad-block,
  boot-validation and demonstrated recovery gates.
- Hardware tests require a separately reviewed plan. Important data disks are
  excluded; a SMART-failed spare is useful only for explicitly destructive fault
  experiments, never as healthy-media qualification evidence.
- Do not weaken a failing check, introduce automatic mutation retries, or use
  lazy unmount to obtain a green pipeline.

### Compatibility and retirement policy

Retain useful outcomes: SMB/NFS, managed file-service identities, qualified
arrays, iSCSI objects, backups, health visibility and front-panel controls.
Do not preserve insecure defaults or obsolete WD cloud/manufacturing services.
SMB1, unauthenticated administration and vendor manufacturing endpoints are
not required compatibility features.

Maintain a public compatibility matrix before claiming support. For each
candidate disk layout, filesystem, array mode, ACL representation and credential
format record: recognized / importable / requires owner action / unsupported.
Single-volume, multi-volume, JBOD and RAID layouts must be evaluated individually;
no RAID level or legacy layout is promised merely because Linux can parse it.
Unknown formats require an explicit backup-and-restore route, not conversion.

## Current baseline

Status vocabulary:

- **Implemented / host-tested**: code and deterministic local checks exist.
- **QEMU-tested**: actual ARMv5 guest behavior passed within the documented fixture.
- **Hardware-observed**: a bounded EX4 experiment, not complete support.
- **Product-qualified**: all acceptance, security, recovery and hardware criteria
  for an advertised capability have passed. No milestone has this status yet.
- **Planned**: specification only. A library is not a deployed product service.

| Area | Evidence and limits |
| --- | --- |
| Build/tooling | Pinned Buildroot 2025.02.18 / Linux 6.18.53; source verification, package metadata, SBOM and clean CI. Independent reproducibility was demonstrated for one earlier commit, not every revision. |
| Admin management | Host/DOM and ARMv5 authentication, password-change, revocation and clean-reboot tests. Product enrollment, state placement, recovery and certificates remain open. |
| Desired SMB/NFS policy | Strict models, revision stores and opt-in development editing. Stored policy does not activate services. |
| Native identities | Reservation ledger, protected local reader, creation journal, typed executor, cooperative owner/listener and multi-account router. Not a deployed account manager. |
| Samba credentials | Actual guest authentication/rotation/disable and persistence fixtures. Ordinary password reset can re-enable a disabled account; the safe product primitive is not implemented. |
| Storage | GPT/ext/MD image research, sysfs/mount observations, restricted libblkid helper, supplied-descriptor collision checks and mount guard. No complete discovery, compatibility resolver or importer. |
| Hardware | Short diskless serial/RAM and Ethernet/temperature observations. Networking stability, controller/cooling, storage and recovery remain unqualified. |
| Updates | Host-side signed metadata/payload/version assessment. No on-device installer, update transaction, recovery or installation release. |

Clean run [36234101935](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36234101935)
validated `2c09f81`. Router/race correction `fbaeb4a` and Samba boundary
characterization `6f3d65f` subsequently passed local host/Linux/ARMv5 tests;
they require their own clean integration result. This is dated evidence, not
a moving claim that the current branch is green. Consult exact-commit CI.

Known unresolved qualification issue: intermittent state-volume unmount
`EBUSY` in the two-boot QEMU fixture. Subsequent passes do not establish its
cause or resolution. See [fast-lane limitations](support/QEMU-FAST-TESTS.md).

## Execution rules for contributors and agents

### Task contract

Take one bounded task ID below, inspect the linked implementation and tests,
and write down before coding:

1. **Input and authority:** trusted/untrusted fields, caller privileges, owned
   resources, supported platforms, and whether the action can mutate state.
2. **State transition:** before/intent/after states, revision checks, success
   evidence, cancellation boundary and interrupted-operation handling.
3. **Failure contract:** malformed data, missing/conflicting identity, concurrent
   actors, lost replies, process exit, storage refusal/fullness and partial results.
4. **Change boundary:** existing packages to extend, explicit non-goals and any
   proposed new package. Avoid a second policy owner or duplicate parser.
5. **Acceptance evidence:** named tests, expected assertions and environment.
   Use generated fixtures, not operator data. State which hardware gates remain.

Deliver code, regression tests, updated component contract and this task's
status/evidence in one coherent change. Report exact commit, commands, environment,
results, limitations and next dependency. A test that checks only exit zero is
insufficient where actual authentication, ownership, persistence or recovery
can be observed.

A contributor may implement pure models and disposable host/QEMU tests without
hardware authority. Do not invent undocumented WD formats, GPIO values, controller
commands, disk layouts, recovery steps or cryptographic schemes. If evidence is
missing, build the read-only interface/fixture and record the unresolved decision.

### Validation ladder

| Change | Required checks |
| --- | --- |
| API/domain/UI | Host wrappers, focused negative/concurrency tests, DOM tests for changed flows; pinned Linux vet/unit/race and relevant bounded fuzz lanes |
| Linux filesystem/privilege behavior | Real Linux tests for permissions, descriptor provenance, symlinks/replacements, contention, cancellation and process interruption |
| Guest services/native helper | Actual ARMv5 QEMU, permitted and denied operations, observed postconditions, owned-resource cleanup and relevant two-boot fixtures |
| Kernel/package/build recipe | Clean pinned Buildroot build; the userspace overlay lane is insufficient |
| Board behavior | Static configuration audit first, then a separately approved bounded EX4 test with explicit stop conditions |
| Installer/release | Independent reproducibility, license/SBOM review, device compatibility, security and recovery qualification |

Use [host wrappers](README.md#fast-host-checks), the pinned Linux test scripts in
`support/container/`, and [QEMU fast-lane instructions](support/QEMU-FAST-TESTS.md).
Do not launch all historical Stage A/B/B2/B3 targets for an unrelated API edit.
Use the latest relevant board probe; historical targets remain reference tools.
Batch related userspace changes into a reviewed increment, then run clean CI.
Do not repeatedly cancel a running qualification build to publish small follow-ups.

### Sequencing and release gates

Software work can proceed without hardware, but product claims cannot:

```text
M0 test reliability
  + M1 state + M2 identities ----+
  + M3 volume lifecycle --------+--> M4 sharing --> M5 product UI
  + M6 networking --------------+
  + M7 board/cooling/recovery --> hardware qualification of M1/M3/M4/M6
M3 + M7 --> M8 migration/RAID + M9 iSCSI
M1 + M7 + M8 + signed verification --> M10 installer
M0–M10 + security/performance/recovery evidence --> M11 public release
```

UI mockups and pure domain models may proceed earlier. Do not connect a write
button to an unqualified backend simply because the screen exists.

## M0: Engineering baseline and test reliability

**State:** in progress. **Entry:** no NAS required.

- **M0.1 — Integrate verified work.** Extend the existing integration PR rather
  than opening separate PRs for every intermediate branch. Require clean checks
  for its exact final head; retain the fixed identity response-publication
  regression. Never substitute an older green commit. Delete superseded branches
  only with squash-aware provenance checks, preserving unmerged work.
- **M0.2 — Resolve shutdown fixture ownership.** Reproduce the intermittent
  state-volume unmount refusal; capture only bounded, redacted process/FD/mount
  ownership evidence. Test the concrete owner/lifecycle defect before changing
  cleanup. Do not assume parent process exit proves descendant exit. A fix needs
  a deterministic regression and a declared repeated two-boot campaign.
- **M0.3 — Keep CI proportional.** Host/domain changes use fast checks; runtime
  changes use QEMU; board changes use the relevant current probe. Preserve
  isolation, exact-source hashes and clean-build/reproducibility lanes. Cache
  hits are an optimization, never qualification evidence.
- **M0.4 — Maintain release inputs.** Dependency update changes include source
  signatures/hashes, ARMv5 compatibility, package configuration, vulnerability
  review, license material and regenerated SBOM. Test the selected package set.

**Start in:** `support/`, `.github/workflows/`, `versions.env`,
`package/`, `configs/`.

**Done when:** exact-head integration passes, known fixture failures have a
demonstrated resolution or explicit non-release limitation, and each build
records commit/configuration/toolchain/artifact identity.

## M1: Durable state and operation recovery

**State:** transaction libraries and QEMU persistence exist; product provisioning
and recovery do not. **Depends on:** M0 for tests; M7 for physical placement.

- **M1.1 — Specify state ownership.** Define the schema/version, permissions and
  single writer for admin credentials, desired services, account ledger, operation
  journals, Samba private state and system settings. Distinguish persistent
  state from cache/log/session data. Select actual EX4 placement only after layout,
  capacity, wear and recovery review; do not assume a legacy mount is suitable.
- **M1.2 — Explicit bootstrap and migration.** Define pristine, initialized,
  corrupt, incompatible and unavailable states. Enrollment is allowed only from
  proven pristine state. Version upgrades need checked preconditions, retained
  recovery evidence and no implicit empty-state fallback.
- **M1.3 — Recover interrupted operations.** Extend current journal semantics
  to an explicit review/reconciliation workflow. An intent plus missing reply
  does not imply failure or success. Preserve orphaned publications; compare
  fresh observed state before any authorized recovery. No blind replay/deletion.
- **M1.4 — Qualify filesystem durability.** Exercise write, rename, file/directory
  sync, ENOSPC, read-only storage, corrupt/truncated files, replacement/symlink
  attacks, concurrent writers and process exits at each durable boundary.
  Clean reboot and process exit are not power-loss guarantees.

**Start in:** [admincredentials](src/phantowd-api/admincredentials/README.md),
[fileservicestore](src/phantowd-api/fileservicestore/README.md),
[identityprovision](src/phantowd-api/identityprovision/README.md),
[identityowner](src/phantowd-api/identityowner/README.md).

**Done when:** restart never invents ownership or loses the last confirmed
revision; ambiguous work is visible and cannot auto-run. Demonstrate recovery
on disposable QEMU media, then on the selected physical state medium.

## M2: Native identities and Samba credentials

**State:** coordination libraries tested; credential executor/product daemon
not implemented. **Depends on:** M1; M3/M8 supply storage/import exclusions.

- **M2.1 — Complete allocation inventory.** Reconcile local Unix accounts,
  reserved/tombstoned IDs, imported ownership and offline-volume reservations.
  Missing inventory must block allocation. An empty QEMU fixture is not proof
  that a real NAS has no external ownership. Keep immutable identity IDs
  independent of display names; define rename and group-membership semantics.
- **M2.2 — Deploy one authority.** Provision protected paths/socket through an
  explicit startup contract; enforce one writer for Unix/Samba identity state.
  Existing advisory leases do not exclude arbitrary root tools. Define startup,
  crash, restart, readiness and drain order. HTTP never opens root stores directly.
- **M2.3 — Implement disabled-preserving credentials.** Follow the
  [credential integration specification](src/phantowd-api/SMB-CREDENTIAL-LIFECYCLE.md).
  Investigate a narrow Samba-native adapter that sets a password and retains
  disabled state in one SAM update. The current CLI cannot express the required
  combination; resetting then disabling exposes an enabled interval. Verify
  tdbsam behavior, source/ABI/license implications, SID/RID binding and writer
  serialization before choosing a maintained patch/helper.
- **M2.4 — Journal credential operations.** Enrollment, password replacement,
  enable, disable and retirement have separate authorized intent/result states.
  Transport bounded secrets through protected memory/stdin only. Refuse adoption
  of unrelated passdb entries and do not persist secrets for retry. Retain
  tombstones; retirement must not silently reassign existing file ownership.
- **M2.5 — Distinguish connection and session revocation.** Current disabled-user
  fixtures prove denial of new connections only. Specify and test active SMB
  sessions, open handles and durable reconnects. Show incomplete revocation as
  pending/degraded; a panel logout does not revoke file-service credentials.
- **M2.6 — Add account API/UI only after the backend.** Authorize typed account
  IDs and revisions; reject caller-selected UIDs, paths, shells and executables.
  Read status after uncertain replies rather than resubmitting mutations.

**Start in:** [serviceaccounts](src/phantowd-api/serviceaccounts/README.md),
[unixidentity](src/phantowd-api/unixidentity/README.md),
[identityexec](src/phantowd-api/identityexec/README.md),
[identityrpc](src/phantowd-api/identityrpc/README.md), and the M1 packages.

**Acceptance:** real guest clients cannot authenticate during disabled enrollment
or replacement; after explicit enable only the intended new credential works.
Other accounts/SIDs/files remain unchanged. Test stale revisions, unknown IDs,
concurrent requests, owner restart, lost replies, command failure and orphaned
intent. Hardware durability and imported identities remain separate gates.

## M3: Complete storage discovery and volume lifecycle

**State:** readers/probes/guards exist; complete resolver and mount lifecycle
are missing. **Depends on:** M1; M7 for hardware.

- **M3.1 — Define complete discovery.** Enumerate eligible devices from trusted
  kernel observations; bind open descriptors to the observed generation and
  inventory. Distinguish excluded, absent, unreadable and ambiguous devices.
  An unreadable candidate makes the relevant assessment incomplete, not unique.
- **M3.2 — Resolve stable identity.** Correlate device, partition, MD and filesystem
  identifiers; distinguish two descriptors for one object from two cloned
  filesystems. Never prove uniqueness from only the devices supplied by a caller.
  Report bay location separately from logical volume identity.
- **M3.3 — Gate compatibility and mounting.** Define a per-layout/filesystem
  allowlist with evidence. Inspect before assembly/mounting; journal replay and
  automatic MD actions can write even during a supposedly read-only assessment.
  Unknown signatures, mixed generations and degraded cases require refusal or a
  separately qualified policy, not best-effort mounting.
- **M3.4 — Own mount lifecycle.** Model absent, discovered, rejected, qualified,
  mounting, mounted, unavailable, draining and review-required outcomes.
  Derive the transient mount tuple from trusted observations, not HTTP or an
  arbitrary directory. Revalidate descriptors/generation before handoff.
- **M3.5 — Handle loss and return.** Stop new dependent access when a volume is
  lost, changed, read-only or unqualified. Never fall back to rootfs directories.
  Reappearance requires fresh identity/compatibility checks; a matching pathname
  or UUID alone is insufficient.

**Start in:** [volume probe](src/phantowd-volume-probe/README.md),
[supervisor](src/phantowd-api/volumeprobe/README.md),
[mountguard](src/phantowd-api/mountguard/README.md),
`tools/phantowd-lab/diskimage/` and `storageinventory/`.

**Acceptance:** generated disks cover duplicate UUIDs, aliases, omitted/unreadable
devices, signature collisions, mid-probe replacement, reordered discovery,
stale generation, filesystem refusal and volume loss. Assert no unexpected mounts,
writes or fallback directories. Physical bay moves require dedicated media tests.

## M4: Supervised SMB and NFS

**State:** policy/rendering and isolated service fixtures tested; no product
activation. **Depends on:** M1, M2, M3; M6/M7 before LAN qualification.

- **M4.1 — Typed activation plan.** Resolve validated policy against qualified
  volumes and actual identities; compile a bounded plan with expected revisions
  and observations. Refuse stale plans. Validate generated daemon configuration
  before replacing active configuration.
- **M4.2 — Single service owner.** Define start/reload/stop and child-process
  ownership; bound diagnostics and verify readiness. Preserve the last known
  working configuration on syntax/start failure without claiming an unapplied
  requested revision is active.
- **M4.3 — Access semantics.** Specify SMB3 grants and denied cases; keep SMB1
  disabled. Support explicit NFS client/network rules, export paths and numeric
  identity/squash policy. NFSv3 compatibility has guest evidence; NFSv4 is a
  separate protocol/identity/recovery qualification, not an assumed feature.
- **M4.4 — Storage-safe handoff.** Document how pathname-consuming daemons remain
  bound to the qualified volume after descriptor checks. Close replacement,
  symlink and unmount windows; a held descriptor alone does not secure every
  future daemon pathname lookup.
- **M4.5 — Failure and shutdown.** Cover startup with absent disks, service crash,
  read-only/full volume, client reconnect, stale NFS handles, shutdown with open
  files and restart ordering. Distinguish safely unavailable from healthy.
- **M4.6 — Product persistence.** Reboot with saved policies, identities and data;
  verify activation of the intended revision and no recreation of credentials,
  permissions or missing directory trees as a recovery shortcut.

**Start in:** [fileservice](src/phantowd-api/fileservice/README.md),
[smbconfig](src/phantowd-api/smbconfig/README.md),
[nfsconfig](src/phantowd-api/nfsconfig/README.md), M1/M3 stores and guest fixtures.

**Acceptance:** actual permitted/denied clients, ownership/ACL checks, multiple
connections, volume substitution/loss and restart cases pass. Observe effective
access, not just rendered text or daemon exit status.

## M5: Product web management and security

**State:** development UI/authentication exists. **Depends on:** each backend
milestone before enabling its controls; M1/M6 for deployment.

- **M5.1 — Secure first use.** Define owner-presence/enrollment and reset recovery
  without default passwords or unauthenticated remote enrollment takeover.
  Preserve admin/file-service identity separation. No reset may silently erase
  data or ownership.
- **M5.2 — HTTPS lifecycle.** Specify initial certificate trust, device naming,
  replacement/renewal, key permissions, time errors and restart behavior.
  Transport support is not a certificate provisioning strategy.
- **M5.3 — Typed operation API.** Map privileges and state transitions to endpoints.
  Preserve strict decoding, origin/Host validation, CSRF, bounded requests,
  generic errors and per-operation concurrency limits. Long jobs return durable
  identity/status; cancellation must distinguish requested from actually stopped.
- **M5.4 — Complete workflows.** Setup, system health, disks/arrays, shares,
  identities, iSCSI, network, updates and recovery screens must show freshness,
  partial failure, confirmation/preview and observed results. Do not display
  configuration-only saves as successful service changes.
- **M5.5 — Accessible efficient UI.** Keyboard operation, labels/focus, narrow
  viewports, screen-reader status and high contrast; bounded static assets and
  shared observations. Avoid per-client hardware polling, stale-response
  overwrites, duplicate submissions and unbounded retained logs.
- **M5.6 — Audit and diagnostics.** Record actor, operation ID, revisions and
  redacted outcome; bound retention. Export a sanitized support bundle that
  excludes credentials, private keys, passdb hashes and user file contents.

**Start in:** `src/phantowd-api/http.go`, authentication handlers, `ui/`,
component API contracts, `support/test-dashboard-ui.mjs`.

**Acceptance:** real-browser responsive/accessibility checks plus DOM/HTTP tests;
expired/revoked sessions, concurrent tabs, disconnects and uncertain writes cannot
publish stale success or widen privileges. Complete a threat-model review before
exposing management on a LAN.

## M6: Network and system services

**State:** product implementation planned; board network observations limited.
**Depends on:** M1/M5; M7 for physical networking.

- **M6.1 — Network domain.** Specify DHCP/static addressing, subnet masks, routes,
  DNS, hostname and both physical interfaces. Validate conflicts and interface
  identity; do not hardcode an operator network or assume all LANs use /24.
- **M6.2 — Recoverable changes.** Apply changes as a trial with explicit confirmation
  and a safe timeout/recovery route. Loss of the management connection must not
  strand the owner permanently. Qualify reboot mid-trial and address conflicts.
- **M6.3 — Port modes.** Validate independent interfaces before choosing failover
  or bonding modes. Document loop risks and switch requirements. Two sockets on
  the rear do not imply bridged, bonded or simultaneously qualified operation.
- **M6.4 — Time/discovery/administration.** Define RTC/NTP failure handling,
  local service discovery, firewall defaults and optional key-based SSH/SFTP.
  Debug access is opt-in; management is not internet-exposed by default.
- **M6.5 — System jobs.** Time schedules, notifications and shutdown/reboot are
  typed, authorized and coordinated with services, active storage operations and
  cooling. Bound retention and notification repetition.

**Acceptance:** host network-policy tests, isolated QEMU namespaces/clients where
appropriate, then both EX4 ports under sustained traffic, reconnect, reboot and
recoverable-configuration trials. Report exact factory MAC identity handling;
do not fabricate or clone addresses.

## M7: EX4 board, controller and thermal qualification

**State:** hardware research only. **Entry:** a separately approved plan with
stop conditions and suitable equipment/media; not ordinary software work.

- **M7.1 — Evidence inventory.** Map supported board revisions, SoC/RAM, UARTs,
  GPIO/pinmux, interrupts, controllers and boot handoff. Keep model-specific
  evidence and source attribution next to board definitions.
- **M7.2 — Controller protocol.** Passive internal-UART captures first; qualify
  framing/checksum, selectors, timing, replies, asynchronous alarms and failure
  behavior. Console UART is not the management-controller UART. Validate parser
  fixtures before considering any transmitted control command.
- **M7.3 — Cooling safety.** Independently measure temperature and fan/tach
  behavior. Define startup-safe fan state, unavailable/stale sensor handling,
  controller/daemon failure, overtemperature and safe shutdown. Do not disable
  watchdogs or alarms to prolong an unstable experiment.
- **M7.4 — Peripheral support.** Qualify SATA bays, USB, RTC, LEDs, LCD, buttons,
  watchdog and power control. Hardware alarms override cosmetic display choices.
  Record LED/button semantics and shutdown completion, not just driver presence.
- **M7.5 — Non-persistent boot.** Keep research targets and product configuration
  separate. Audit enabled write-capable subsystems, readiness/stop markers and
  state effects before a RAM trial. Never turn a narrow B3 success into a blanket
  authorization for longer boots or attached data disks.
- **M7.6 — Recovery foundation.** Determine exact NAND geometry, ECC/OOB,
  bad-block policy, vendor headers/checksums, boot validation, environment and
  device identity dependencies. Verify backups and an independent rescue path.
  A raw image copy or recognizable SquashFS magic is insufficient.

**Start in:** [EX4 board research](board/wd/ex4/README.md),
`board/wd/ex4/`, `configs/`, `tools/phantowd-lab/mcuproto/`,
`vendorupdate/` and `uimage/`.

**Acceptance:** independently reviewed evidence for each advertised peripheral,
bounded failure tests and demonstrated recovery. No destructive qualification on
the only important-data system. Lack of suitable hardware blocks these gates,
not host/QEMU progress.

## M8: RAID, health and legacy migration

**State:** research inspectors exist; management/importer planned.
**Depends on:** M1/M2/M3/M7.

- **M8.1 — Sanitized layout corpus.** For every candidate WD layout, record provenance,
  metadata dependencies, array/filesystem versions and recognition conditions.
  Keep proprietary firmware and private user metadata out of the repository.
  Project synthetic JSON is not a verified WD XML parser.
- **M8.2 — Read-only assessment.** Report data/configuration that can be retained,
  uncertainties, required owner actions, free-space needs and exact unsupported
  features. Explicitly assess ownership/ACLs, shares and iSCSI backing objects.
  A recognizable filesystem does not establish safe assembly or migration.
- **M8.3 — Import identity and settings.** Preserve qualified volume/array identity,
  ownership and access policy across bay moves. Refuse collisions. Incompatible
  credentials need explicit reset/re-enrollment, never silent permissive access.
  Define how stock export paths/names map to stable product references.
- **M8.4 — RAID jobs.** For each supported mode specify create/import, degraded
  operation, replace/rebuild, resync, scrub and removal. Plan destructive extents
  before confirmation; reject wrong members and conflicting generations.
  Do not auto-assemble, reshape or repair unknown arrays.
- **M8.5 — SMART and health.** Bounded collection/history, stale/unsupported/error
  states, scheduled checks that respect standby, authorized extended tests,
  progress and deduplicated alerts. A SMART pass is not an integrity guarantee.
- **M8.6 — Backup/restore and stock return.** Define verifiable data/configuration
  backup and restore paths, and constraints on returning to stock after metadata
  changes. Removing disks protects them during diskless tests; it is not a
  replacement for migration backups or proven future readability.

**Acceptance:** disposable healthy media cover supported layouts, reorder/bay
moves, missing members, full storage, interrupted import/rebuild and restore.
Compare file contents, ownership, modes/ACLs and metadata before/after. Publish
support per tested combination; refuse untested combinations without mutation.

## M9: iSCSI targets and LUN lifecycle

**State:** planned. **Depends on:** M1/M2/M3/M5/M7/M8.

- **M9.1 — Backend decision.** Evaluate the kernel/userspace target implementation
  for this kernel, ARMv5 and resource budget. Record package/license choices.
  Do not assume legacy WD target configuration is directly portable.
- **M9.2 — Target model.** Stable target/LUN identity, backing volume/object,
  capacity/allocation policy, initiator access and protected authentication
  secrets. Secrets are not returned by read APIs or exposed in diagnostics.
- **M9.3 — Guard mutations.** Create/enable/disable/grow/remove operations check
  real initiator/session ownership and backing-volume state. Prevent local
  filesystem mounting while an initiator owns the LUN; prohibit unsafe shrink.
  Session presence and disconnect races need observed pre/postconditions.
- **M9.4 — Import and failure.** Recognize supported old backing objects without
  modifying them during discovery. Full backing storage, loss/reappearance,
  abrupt initiator disconnect, target restart and interrupted mutations preserve
  data and report uncertainty instead of recreating a LUN.

**Acceptance:** disposable QEMU initiators verify authentication, isolation,
stable identity/data across restart, active-session refusal and backing failure.
Then qualify the selected backend and migration objects on expendable EX4 media.

## M10: Signed installer, upgrades and recovery

**State:** host verifier exists; target installer absent.
**Depends on:** M1/M7/M8 and explicit boot/storage design approval.

- **M10.1 — Installation layout decision.** Document space, wear, bootloader and
  rescue constraints, state/data separation and device identity preservation.
  A/B slots are a candidate, not an assumed fit or implementation.
- **M10.2 — Trust and release discovery.** Retrieve immutable GitHub Release
  metadata/assets; verify signatures against pinned trust roots, exact model/
  revision/channel, hashes and version policy before writes. HTTPS alone is
  insufficient. Define signing-key rotation, compromise/recovery, offline use,
  rate-limit/network failure and owner-authorized rollback policy.
- **M10.3 — Target transaction.** Explicit preflight, staged, verified, installing,
  boot-pending, health-confirmed and recovery states. Journal durable boundaries;
  check space/power prerequisites. An ambiguous state must not restart installation
  or claim success automatically.
- **M10.4 — Health and rollback.** Define boot health using required storage,
  identity, controller/cooling and management readiness. Retain the ability to
  diagnose/recover a failed trial. Schema migration must not make the fallback OS
  unable to read state without a documented recovery route.
- **M10.5 — Interruption campaign.** Inject corrupt/truncated/wrong-model payloads,
  bad signatures, stale versions, unavailable state, full media and process exits
  in simulation. Physical power interruption at durable boundaries is a separate
  dedicated-hardware campaign after reviewed recovery.
- **M10.6 — User instructions.** Exact compatibility, backup, installation,
  verification, upgrade, rollback and unbrick steps; explicit unsupported cases.
  Do not publish plausible-looking flash commands before they are demonstrated.

**Start in:** `tools/phantowd-lab/githubrelease/`, `releaseverify/`,
vendor format research and board definitions. Reuse tested verification rules;
do not design a new signing scheme.

**Acceptance:** independent reproduction of installation and recovery from the
published instructions on every advertised revision, preserved identities/data,
and failed-update recovery demonstrated beyond merely reaching a boot prompt.

## M11: Performance, security and public release

**State:** planned; prerequisite for an installable beta.
**Depends on:** all first-release capability gates M0–M10.

- **M11.1 — Declare budgets before qualification.** Image/state size, idle/peak RSS,
  CPU, startup/readiness time, management latency, transfer concurrency, open-file
  limits, probe frequency and log retention. Establish physical measurements and
  justified headroom within the EX4 resource envelope; do not invent targets from
  QEMU timing or advertise unmeasured savings over WD.
- **M11.2 — Mixed-load campaign.** Declare client count, protocols, dataset, duration,
  disk/network setup and pass criteria. Measure sustained SMB/NFS/iSCSI I/O with
  management/health activity, thermal safety, error handling and post-run data
  integrity. Test full storage and realistic memory pressure.
- **M11.3 — Security review.** Inventory exposed listeners, privileged boundaries,
  enrollment/recovery, updates, sessions, secrets, application execution and data
  access. Review dependency advisories and document mitigation/response ownership.
  No known unresolved critical data-loss, authentication or cooling issue ships.
- **M11.4 — Reproducible release.** Two independent clean builds compare a declared
  allowlist. Publish exact source commit/configuration, payload hashes, signed
  metadata, SBOM, license/legal material, support matrix, release notes, limitations
  and qualification evidence. Fast-overlay artifacts are never releases.
- **M11.5 — Staged publication.** Contributor builds → qualified limited beta →
  stable release after issue triage and recovery drills. Drafting a GitHub Release
  or passing CI does not advance a gate. Installation documentation must match
  the exact published assets.

**Done when:** an independent owner can determine compatibility, install, manage,
upgrade and recover using the published instructions without private operator
knowledge. Existing disk support is limited to the qualified matrix.

## After the first core release

These features are separate scope, not shortcuts around core acceptance:

- **Signed lightweight applications:** curated native packages with declared
  model/ABI, resource budgets, filesystem/network privileges, service identity,
  install/upgrade/rollback/uninstall and state retention. Transmission-like
  download clients or database services are candidates, not bundled promises.
  No arbitrary vendor APKG compatibility or unreviewed install scripts.
- **Additional backup integrations:** scheduled jobs, credential isolation,
  retention and independently verified restore; do not describe RAID as backup.
- **Remote access:** explicit threat model and owner-controlled exposure; no
  mandatory cloud account or default internet management port.
- **Mobile:** qualify the responsive web UI/PWA first; a native companion must
  reuse authenticated APIs without creating a second privilege boundary.
- **Additional NAS models:** separate evidence, configs, signed compatibility
  metadata and recovery qualification. No universal autodetected flash image.

## Decisions that must not be guessed

| Decision | Required evidence / milestone owner |
| --- | --- |
| Product state medium and filesystem | Capacity/wear/durability/recovery review, M1 + M7 |
| Complete ownership inventory and legacy ID policy | Read-only corpus and offline-volume policy, M2 + M8 |
| Samba credential adapter and active-session revocation | Native source/runtime/failure tests, M2 |
| Supported new/legacy filesystems and RAID modes | Corpus plus empty-media validation, M3 + M8 |
| First-enrollment/reset presence and certificate trust | Threat model and recovery UX, M5 |
| Dual-port modes and safe network rollback | Isolated policy tests + exact-device evidence, M6 + M7 |
| Fan/watchdog/power-control commands | Verified controller protocol and thermal instrumentation, M7 |
| Target backend and LUN migration | ARMv5/runtime ownership tests, M9 |
| Flash layout, A/B feasibility, trust-key recovery | NAND/boot/rescue evidence and review, M10 |
| Performance targets and qualification duration | Baseline hardware measurements and declared protocol, M11 |

## Next bounded work packets

1. **M0.1:** finish exact-head integration of router/race correction and Samba
   characterization; keep the existing PR consolidated.
2. **M2.3:** compile and test the disabled-preserving Samba primitive in disposable
   QEMU. Deliver source/license review, actual denied-authentication assertions,
   identity preservation and failure behavior; no HTTP password endpoint yet.
3. **M1.3 / M2.4:** implement explicit credential intent/reconciliation around the
   qualified primitive. Preserve uncertainty; do not persist/replay secrets.
4. **M3.1–M3.2:** implement a complete trusted discovery snapshot and collision
   assessment using existing descriptor tools; no automatic mounts/import.
5. **M4.1:** define and test the activation plan against qualified fixture volumes;
   add the daemon owner only after preconditions and lifecycle are demonstrable.
6. **M5:** expose completed backend outcomes incrementally, with disabled controls
   and honest unavailable/review states for capabilities not yet implemented.

M0.2 reliability work and passive M7 evidence preparation can advance alongside
these software packets. Any step requiring real disk writes, controller commands
or firmware boot must stop at its hardware authorization gate.

## Keeping this plan current

Every behavior-changing PR updates the affected task status, component contract
and README capability summary, with exact-commit validation evidence. Keep
experiments and command transcripts out of the README. Mark superseded decisions
explicitly; never turn one passing sample into a universal qualification claim.

If a task becomes too broad for one coherent review, split it under its existing
ID (for example M3.2a/M3.2b), retaining dependencies and acceptance checks.
Do not mark an entire milestone complete because a parser, mock, screen or library
exists. A public release is gated by demonstrated product behavior, not estimated
percentage, lines of code or number of merged branches.
