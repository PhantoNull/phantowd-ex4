<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation roadmap

Reviewed: **2026-10-03**. This is the product specification and work breakdown,
not a release announcement. The [README](README.md) is the concise entry point;
component contracts remain authoritative for implemented behavior.

The dated [code-to-roadmap comparison](IMPLEMENTATION-STATUS.md) records
implemented evidence, missing product integration, planning estimate bands and
the immediate execution sequence. Estimates are not release qualification.

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
The initial evidence-backed status is tracked in
[`STORAGE-COMPATIBILITY.md`](STORAGE-COMPATIBILITY.md); no legacy layout is
currently product-qualified for migration.

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
| Build/tooling | Pinned Buildroot 2025.02.18 LTS / Linux 6.18.54 LTS; source verification, package metadata, SBOM and clean CI. Independent reproducibility was demonstrated for one earlier commit, not every revision. |
| Admin management | Host/DOM and ARMv5 authentication, password-change, revocation and clean-reboot tests. Product enrollment, state placement, recovery and certificates remain open. |
| Desired SMB/NFS policy | Strict models, revision stores and opt-in development editing. Stored policy does not activate services. |
| Native identities | Reservation ledger, protected local reader, creation journal, typed executor, cooperative owner/listener and multi-account router; Owner now supports a revisioned internal desired-state toggle that does not change Unix/Samba authentication or activate services. Not a deployed account manager. |
| Samba credentials | M2.3 root-only disabled-password patch passed exact-head hosted ARMv5 QEMU and Stage B3 checks, merging as `33df1ed`. M2.4 journals disabled-first enrollment and separate explicit enable through `identityowner`; its fixed executor and internal binary Unix-socket v2 fixture prove authentication denial before enable and success only after same-SID confirmation. A QEMU-selftest-only root Owner boot service now passes init start, protected socket, authorized/denied peers, process restart and drain checks; it is not product startup. Product config/state binding, HTTP authorization, review workflow and remaining lifecycle operations are open. |
| Storage | GPT/ext/MD image research, sysfs/mount observations, restricted libblkid helper, duplicate SCSI VPD identity reporting, generation-bound descriptor probing, complete-set matching, partition-parent correlation, holder/slave topology and trusted read-only broker. PR #42 passed exact-head host and ARMv5 QEMU checks on `7254555` and merged as `059fa24`; PR #44 added read-only mounted filesystem UUID / MD identity correlation and passed host, Stage B3 and QEMU checks before merging as `db9fd33`. Local M3.2a privately reconciles GPT disk GUID/PARTUUID and partition number/start/size against the full generation-bound sysfs set. Local M3.2b marks duplicate disk GUIDs/PARTUUIDs ambiguous only within the observed GPT-candidate subset; MBR stays unsupported and incomplete GPT coverage is explicit. M3.2c retains GPT type GUIDs privately; M3.2d derives only generic hints for a small known set, not content or WD compatibility. Raw IDs, type GUIDs and hints stay out of JSON; no mount/import authority is added. The dashboard exposes a separate authenticated explicit observation action; page load and ordinary refresh do not scan disk partition metadata, and the result contains aggregate counts only. Host tests/vet, smoke-only ARMv5 overlay and full local Buildroot/package integration passed on `1358202`; QEMU smoke and the state-reboot fixture passed and generated artifact hashes verified. The run reused existing fixed Buildroot/cache volumes, so clean independent reproducibility is not established. Hosted CI and EX4 qualification remain pending. Persistent volume identity, EX4 device-rule qualification, global-use accounting, WD compatibility resolution, import/mount authority and product RAID management remain unqualified or unimplemented. |
| Hardware | Short diskless serial/RAM and Ethernet/temperature observations. Networking stability, controller/cooling, storage and recovery remain unqualified. |
| Updates | Host-side signed metadata/payload/version assessment. No on-device installer, update transaction, recovery or installation release. |

The storage-discovery implementation at code commit
`2059a93afdbb3178c6112677013087a249622a49` passed [host CI
`36302718909`](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36302718909)
and the [ARMv5 QEMU build/smoke plus EX4 research DTB
`36302718920`](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36302718920).
The QEMU run also removed its isolated build volume successfully. These are
feature-branch results, not integration into `develop` or EX4 hardware
qualification; consult exact-commit CI for later revisions.

Known unresolved qualification issue: intermittent state-volume unmount
`EBUSY` in the two-boot QEMU fixture. Subsequent passes do not establish its
cause or resolution. See [fast-lane limitations](support/QEMU-FAST-TESTS.md).
The 2026-10-03 lifecycle correction separately prevents parent-only Samba
shutdown success with surviving same-group children. Native regression/race
and actual ARMv5 smoke/two-boot checks pass. Complete cached local integration
also passes on `28b16f4`; hosted topic qualification and original `EBUSY`
causality remain open. A passing run does not establish a release gate.

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
  a deterministic regression and a declared repeated two-boot campaign. Ten
  more local repetitions on 2026-09-30, using the current harness and existing
  manifest-verified rootfs artifact, passed without reproducing EBUSY; this does
  not establish a fix. A QEMU-only failure hook emits a 4-KiB-capped, redacted
  process/FD/mount snapshot if ordinary unmount fails. Its `/proc` reader now
  consumes at most 160 directory names plus one truncation sentinel and retains
  at most 128 numeric PIDs; normal process-exit races do not make the whole
  snapshot incomplete, while other collection errors remain explicit. Host
  fake-proc and bounded-enumeration tests, an actual Linux `/proc` redaction test,
  the no-Docker host suite, Linux-native tests and ARMv5 cross-compilation pass.
  A current-source overlay on `aedd22e` subsequently passed the ordinary ARMv5
  QEMU smoke and the complete two-phase state-reboot fixture after this
  refinement. Both unmounts succeeded; the diagnostic did not fire and EBUSY
  did not recur. This closes the post-refinement regression run, not the
  historical root-cause investigation or repeated qualification. Cleanup is
  unchanged: no retry or lazy/forced unmount. See the test-lane evidence.
  On 2026-10-03 the complete cached witness build `12f54d2` reproduced EBUSY
  at ordinary state-volume unmount. Preserved diagnostics list only the owner,
  no matching FD/path and one visible state mount; they inspect current
  descendants, not reparented/orphan processes or mappings. Ten-pair state-only
  campaigns pass on the older exported census image and separately on the actual
  newly built cached image. This is non-reproduction, not a fix. Do not confuse
  exported artifacts with the failed build's image: export is after successful
  state reboot. Next distinguish full process-group settlement, mapped/thread
  references and kernel deferred release with a deterministic lifecycle seam.
- **M0.3 — Keep CI proportional.** Host/domain changes use fast checks; runtime
  changes use QEMU; board changes use the relevant current probe. Windows host
  iteration has a no-Docker preflight and an optional Linux/amd64 test runner
  that reuses only an already-present read-only Buildroot cache; it must not
  pull/build an image or create a volume. Preserve isolation, exact-source
  hashes and clean-build/reproducibility lanes. Cache hits are an optimization,
  never qualification evidence.
  The full builder now runs the same workflow/fixed-fuzz-roster contract as
  hosted host CI before compilation. A locally reproduced stale 17-versus-21
  count after adding four network campaigns is corrected without weakening
  the exact roster/count guard. The regression also requires each new campaign
  exactly once and the early local invocation; real non-root fixed-repository
  Git mode checks and the feedback tests pass. Firmware runtime is unchanged.
  The pinned container now supplies Debian-snapshot CMake; a fresh disposable
  QEMU configuration exercises Buildroot's real minimum-version check and
  dependency graph before host-Go bootstrap. Missing/unsuitable tools refuse;
  no dependency override, prebuilt workspace or weaker test lane is used.
  A local cold build actually constructs host-ccache and its dependencies
  using system CMake without building host-cmake. Compare exact-head hosted
  timings before claiming overall CI savings; cached full validation is not
  independent clean-build or release qualification.
  The build feedback refinement runs pinned native Go vet/unit/race/fuzz tests
  before the full kernel/Samba compilation. Failed guest logs are preserved and
  their final 120 lines printed; failure-only artifacts are uploaded separately
  from successful image artifacts. A fresh completed-compile checkpoint permits
  only trusted, non-cancelled `develop` pushes to seed the bounded compiler cache
  even if later tests fail. This does not establish a fix for historical fixture
  failures or independent clean-build reproducibility. Cancel obsolete merged-PR
  runs only after confirming that the integration run covers them.
  A differential ARMv5 regression found the MD fixture PID-1 script recorded
  non-executable in Git, masked by Docker Desktop source permissions. Mode
  `0644` produces kernel `EACCES`/panic; changing only the inode to `0755`
  passes the MD/Owner fixture with the base image unchanged. Correct the Git
  mode and check direct guest entrypoint modes before compilation. Hosted
  exact-head confirmation remains necessary; historical state-unmount EBUSY
  is a separate unresolved issue.
  The later hosted standard smoke hit its 120-second readiness budget after
  compilation; local CPU-limited testing reproduced that timeout and completed
  the full smoke at 162 seconds with a bounded 240-second budget. Preserve all
  assertions, one-shot startup, prompt error/death handling and retained logs.
  Explicit override is limited to 1..300 whole seconds; report bounded progress
  every 30 polls. Exact-head hosted confirmation remains required, including
  the MD/state fixtures not reached by the timed-out run. Compiler-cache
  restore may try older QEMU/Linux entries after exact inputs; never restore
  prebuilt workspaces/images, weaken ccache input checks or change the trusted
  develop-only write/checkpoint/1 GiB policy. Measure actual hosted savings;
  a broader lookup is not reproducibility or a release qualification.
- **M0.4 — Maintain release inputs.** Dependency update changes include source
  signatures/hashes, ARMv5 compatibility, package configuration, vulnerability
  review, license material and regenerated SBOM. Test the selected package set.

The local full wrapper also provides an opt-in `-CachedOnly` mode: it checks
existing version-derived image/volumes and initialized current output before
one non-root, zero-capability, CPU/memory/PID/time-bounded invocation. Host test
caches and scratch use bounded disposable tmpfs; cold API race testing established
the current 2048 MiB temporary allocation. Command-boundary refusal tests and
actual Linux shell preflight tests pass. This neither reduces the full test set
nor qualifies independent reproduction, hosted results or device safety. Do not
run concurrent builds against the same workspace or silently seed missing caches.

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
  **M1.4a — abrupt combined-policy writer (native-tested; not complete):**
  a test-only child holds the actual revision-store lock while its parent
  confirms exclusion, then sends SIGKILL at seven write/sync/close/publication
  boundaries. Reopening returns the exact old/new nonempty SMB/NFS policy,
  never staged or mixed components; pending evidence survives observation,
  stale commits refuse and explicit subsequent commits succeed. Three native
  Linux race-enabled repetitions and whole tagged API vet/race tests pass.
  The campaign uses temporary tmpfs regular files without mounts/devices;
  production code and firmware inputs are unchanged. This is not ARMv5/EX4
  execution, real ENOSPC/read-only-media qualification, power interruption,
  selected state-medium durability or an implemented reconciliation workflow.

**Start in:** [admincredentials](src/phantowd-api/admincredentials/README.md),
[fileservicestore](src/phantowd-api/fileservicestore/README.md),
[identityprovision](src/phantowd-api/identityprovision/README.md),
[identityowner](src/phantowd-api/identityowner/README.md).

**Done when:** restart never invents ownership or loses the last confirmed
revision; ambiguous work is visible and cannot auto-run. Demonstrate recovery
on disposable QEMU media, then on the selected physical state medium.

## M2: Native identities and Samba credentials

**State:** native identity libraries are tested; the M2.3 Samba CLI patch is
merged and passed exact-head hosted ARMv5 QEMU and Stage B3 checks. M2.4
implements disabled-first enrollment, disabled password assignment, and
separate revision-checked enable/disable/re-enable under `identityowner`, with
durable intent/result phases and review on ambiguous outcomes. The fixed Linux
executor and internal binary Unix-socket v2 fixture are tested against
disposable Samba state: valid authentication fails before enable, succeeds
after same-SID confirmation, fails for new connections after disable, and
succeeds after a separate re-enable. M2.5 now extends the same journaled
`Disable` operation to revoke the target account's existing sessions and
verify absence in disposable QEMU; uncertain execution becomes review-required
without replay. This can interrupt active transfers. Open-handle/durable-
reconnect semantics and product integration remain unqualified.
A new M2.2
integration starts one root Owner from the QEMU-only init hook and verifies
protected-socket peer checks, process restart and listener drain before Owner
close. Its authority and Samba state are fixture-only; it does not provide
product startup or persistence. The fixture validates the pinned Samba
configuration before initializing Owner state and proves a missing config and
a `testparm`-rejected config are rejected without side effects. The
current-source QEMU smoke also exercises a revisioned registry desired-state
round-trip `disabled -> enabled -> disabled` (revisions 2 -> 3 -> 4) after the
listener drains.
The native identity journal remains unchanged; no Samba child journal,
authentication mutation, or service activation occurs. The process-restart
fixture deliberately resumes after `group-confirmed` and before Unix-user
creation. These are internal library/QEMU contracts, not account APIs.
The credential-free JSON v1 protocol remains
unchanged. No HTTP authorization binding or product startup/configuration exists;
retirement, operator recovery, revocation integration/recovery and hardware
qualification remain open. The revocation primitive is currently QEMU-only.
**Depends on:** M1; M3/M8 supply storage/import exclusions.

- **M2.1 — Complete allocation inventory.** Reconcile local Unix accounts,
  reserved/tombstoned IDs, imported ownership and offline-volume reservations.
  Missing inventory must block allocation. An empty QEMU fixture is not proof
  that a real NAS has no external ownership. Keep immutable identity IDs
  independent of display names; define rename and group-membership semantics.
- **M2.2 — Deploy one authority.** Provision protected paths/socket through an
  explicit startup contract; enforce one writer for Unix/Samba identity state.
  Existing advisory leases do not exclude arbitrary root tools. A QEMU-selftest-
  only prototype now starts a root service at boot, creates fixed `/run` fixture
  paths, binds one `identityowner.Owner` and its trusted SMB backend at open,
  and serves only the protected AF_UNIX router (no HTTP). ARMv5 QEMU verifies
  non-root API UID admission, rejection of a different UID even when DAC permits
  socket access, operation state across process restart, and listener drain
  before Owner close. Current-source smoke additionally round-trips the
  registry's internal desired service-account state disabled→enabled→disabled
  at revisions 2→3→4 after listener drain; the native creation journal stays
  immutable, no SMB child journal/passdb mutation occurs, and no service is
  activated. The fixture also restarts at `group-confirmed` before the Unix-user
  step. These are library/QEMU-test contracts, not socket, HTTP, or product
  account APIs. This is not production startup: durable state/config
  placement, product boot ordering, readiness/failure policy, crash/recovery,
  installed-service authorization binding and real-device qualification remain
  open. Arbitrary root tools remain outside cooperative single-writer exclusion;
  HTTP must never open root stores directly.
- **M2.3 — Implement disabled-preserving credentials.** Follow the
  [credential integration specification](src/phantowd-api/SMB-CREDENTIAL-LIFECYCLE.md).
  The selected prototype adds root-only
  `smbpasswd --set-password-disabled`, requires `-s`/stdin and an existing
  disabled account, then applies password and disabled state in one SAM update.
  Its Samba 4.22.11 patch applies cleanly, builds, and passes the local ARMv5
  QEMU authentication fixture: replacement remains disabled until explicit
  enable, the old credential is denied, and Unix account files remain unchanged.
  Exact-head hosted ARMv5 QEMU and Stage B3 checks passed; PR #46 merged to
  `develop` as `33df1ed`. Failure/restart behavior, persistent operation
  recovery, tdbsam/password-history, SID/RID binding and single-writer
  serialization remain gates. This is not a product credential service.
- **M2.4 — Journal credential operations.** Enrollment, password replacement,
  enable, disable and retirement have separate authorized intent/result states.
  **Implemented slice:** disabled-first enrollment, password assignment while
  disabled, and separate explicit enable/disable/re-enable actions, through internal
  `identityowner.SMB(id)` methods under the same global lock as Unix identity
  creation. It revalidates the live Unix identity, refuses a pre-existing
  passdb entry, journals create/password/enable/disable intent, confirms the SID
  and disabled state before enable and enabled/disabled state afterward, sends a bounded
  password via backend stdin, and never persists the secret. One fixed backend
  is bound once to the Owner and
  journal at open; the validated config inode stays pinned for the Owner
  lifetime and is closed after active operations drain. Operation calls cannot
  substitute the backend. Reopened intent becomes
  review-required without command replay. The internal credential-bearing
  version-2 Unix-socket methods, including explicit `enable` and `disable`, are bound to the
  Owner resolver and used only by the disposable QEMU fixture; no HTTP endpoint
  exists; enable and disable are never implicit. M2.5 extends journaled
  `Disable` to account-scoped session revocation and confirms target-session
  absence in QEMU while preserving an unrelated same-IP peer. Uncertain results
  enter review-required without replay; active transfers may be interrupted.
  The executor is exercised in local QEMU using only disposable
  passdb/config state; it is not yet wired to product startup or persistent
  Samba state. The local Owner now permits an in-process read-only `Review`
  only for `review-required` operations. It verifies the current Unix identity
  under the Owner lock, reads a validated redacted Samba observation through
  the bound backend, never invokes recovery or a mutator, and leaves quarantine
  unchanged. Linux-host tests cover the phase gate, identity gate, lock,
  redaction and unchanged journal; ARMv5 QEMU-tagged tests cross-compile but
  this new method has not yet run in guest QEMU. No RPC/HTTP path exposes it.
  **Still required:** production listener/startup wiring and HTTP-session-to-owner
  authorization binding; a human operator workflow to reconcile or resolve
  review-required state; and production integration/recovery for session
  revocation. Retain tombstones;
  retirement must not silently reassign existing file ownership.
- **M2.5 — Initial pre-JSON boundary (superseded by local QEMU follow-up below).** A disposable exact-
  build QEMU fixture now confirms that disabling an account blocks a fresh login
  but an already-authenticated writer can still complete a write. It holds two
  target sessions and one unrelated same-IP peer, then verifies QEMU-only
  PID-targeted shutdown removes the target sessions while the peer remains
  usable. This is characterization, not a product revocation primitive: this
  Buildroot Samba build has `--without-json`, `smbstatus -j` reports that JSON
  support is unavailable, and the human table exposes only PIDs without process
  generations. PID-only targeting is unsafe for production. Next provide and
  validate a supported generation-bearing inventory/target path; then test
  open handles, reconnect/durable handles, stale observations and uncertain
  command outcomes. Until qualified, disable means only blocking new
  authentication; incomplete revocation must remain pending/degraded. A panel
  logout does not revoke file-service credentials.

  **Intermediate local validation (2026-09-29; superseded by the account-scoped operation below):** At that intermediate stage, the
  tree enabled Samba JSON with Jansson while keeping AD-DC disabled.
  The QEMU fixture validates complete session server IDs and sends only
  PID/unique_id to smbcontrol; two target writer sessions are removed while an
  unrelated same-IP reader remains usable. Disable still allows an existing
  writer to finish a write before targeted shutdown, and denies fresh login.
  This qualifies generation-bearing targeting only in the disposable QEMU
  fixture. This PID/unique-ID targeting experiment was replaced by the
  account-scoped logoff operation below; its intermediate new-login-only
  behavior is not the current contract.

  **Current account-scoped operation (local QEMU passed 2026-09-29):** the
  trusted backend disables the passdb entry, reads a complete JSON session
  inventory, sends one `smbcontrol smbd logoff-user <unix-name>` if any target
  sessions remain, then requires two complete inventories without that user
  within five seconds. Malformed status, command failure, cancellation or
  timeout returns uncertainty; the already-journaled `Disable` enters
  `review-required` and is never replayed. Only read-only status verification
  may poll. QEMU verified two target sessions disappear, a new login is denied
  and a same-IP peer remains usable; the pre-disable active write was confirmed.
  Disabling can interrupt in-flight transfers. Product startup/configuration,
  review UX, EX4 state placement, open-handle and durable-reconnect semantics
  remain unqualified; no HTTP route exists.
- **M2.6 — Add account API/UI only after the backend.** Authorize typed account
  IDs and revisions; reject caller-selected UIDs, paths, shells and executables.
  Read status after uncertain replies rather than resubmitting mutations.

**Start in:** [serviceaccounts](src/phantowd-api/serviceaccounts/README.md),
[unixidentity](src/phantowd-api/unixidentity/README.md),
[identityexec](src/phantowd-api/identityexec/README.md),
[identityrpc](src/phantowd-api/identityrpc/README.md), and the M1 packages.

**Acceptance:** real guest clients cannot authenticate during disabled enrollment
or replacement; after explicit enable only the intended new credential works.
An explicit disable must also revoke that account's existing sessions and verify
absence while preserving unrelated accounts, including a peer from the same IP.
Ambiguous control/verification results must enter review without replay; document
that in-flight transfers can be interrupted. Test stale revisions, unknown IDs,
concurrent requests, owner restart, lost replies, command failure and orphaned
intent. Open-file/durable-reconnect semantics, hardware durability and imported
identities remain separate gates.

## M3: Complete storage discovery and volume lifecycle

**State:** readers/probes/guards exist; complete resolver and mount lifecycle
are missing. **Depends on:** M1; M7 for hardware.

- **M3.1 — Define complete discovery.** Enumerate eligible devices from trusted
  kernel observations; bind open descriptors to the observed generation and
  inventory. Distinguish excluded, absent, unreadable and ambiguous devices.
  An unreadable candidate makes the relevant assessment incomplete, not unique.
  The read-only API marks every enumerated whole-disk node sharing a valid
  SCSI VPD serial or NAA WWN as `ambiguous`, without returning raw values.
  It rechecks fixed metadata and disk generations before publishing an
  all-or-error schema-v2 snapshot. Partition entries expose `parent_name`,
  `parent_major`, and `parent_minor` as current topology only; parent diskseq
  remains internal, and these values are not stable identity or authorization.
  `OpenObservedBlockSources` is a separate fixed-path opener that accepts only
  kernel names plus major/minor/diskseq from its caller, opens fixed `/dev`
  paths read-only/no-follow, validates major/minor and `BLKGETDISKSEQ`, and
  cleans up every partially opened descriptor on failure. The complete-set
  matcher rejects omitted, extra, duplicate, or reused sources and orders the
  validated set. The storage collector internally resolves each partition to
  exactly one observed whole-disk sysfs target and rechecks that link; the
  relation is exposed only as the schema-v2 partition-parent tuple. The QEMU
  fixture now detects mounts on a selected virtual disk or its directly
  observed partitions. This is fixture coverage only. The implementation
  also validates bounded, reciprocal sysfs `holders`/`slaves` links against
  the complete inventory and
  follows transient slave/partition-parent links when correlating mountinfo to
  a selected disk. A generated host test covers a synthetic
  disk-to-partition-to-MD-to-device-mapper chain and a multi-member MD mount.
  The new QEMU-only fixture creates a real RAID1 from two generated virtual
  disks, formats it with a synthetic ext2 UUID, mounts it read-only, verifies
  both backing disks are attributed (and an unrelated disk is not), then
  ordinarily unmounts and stops the array. It is isolated to the QEMU profile;
  it does not instantiate a guest device-mapper chain, prove global unmounted
  state/exclusive access, or qualify production discovery. The prior code
  commit `2059a93` passed exact-head host and ARMv5 QEMU CI
  (`36302718909`, `36302718920`). PR #41 points at `ac016b9`; exact-head host,
  QEMU and compile-only CI passed (`36340076242`, `36340076246`,
  `36340076277`). Those runs do not validate the local follow-on branch
  described below.
  The local follow-on branch adds an internal `completeObservedBlockDeviceSet`
  bridge: only a collector-produced, in-memory inventory with private
  completion evidence is accepted, all whole-disk generations are emitted in
  inventory order, and no caller-selected name list is accepted. Its internal
  discovery coordinator excludes visible mounts, virtual nodes, active
  MD/device-mapper stacks and removable devices. It refuses active or
  unreadable swap state and mounted Btrfs/Bcachefs/ZFS, opens the full
  read-only candidate set, and then rechecks sysfs, the current process mount
  namespace and swap observations; every partial descriptor is closed on
  error. VPD ambiguity is preserved and missing identity evidence is
  explicitly not considered uniqueness. Host fixtures cover eligibility,
  unsupported multi-device filesystems, complete-set ordering, active swap,
  mutation/replacement, topology cycles and descriptor cleanup. The disposable
  QEMU storage fixture now includes this coordinator and fixed `/dev` opener.
  Exact-head ARMv5 QEMU execution passed in PR #42 run `36364383677` on commit
  `7254555`; the smoke asserts broker/API group separation, `no_new_privs`, zero
  broker capabilities, whole-disk mode `0440`, hotplug recheck, duplicate
  serial/WWN redaction and read-only fixture scope. This qualifies the
  disposable fixture, not production storage authority or EX4 hardware.
  `support/test-api.ps1` passes, including `go vet`, the full Go suite and
  ARMv5 QEMU-tagged cross-compilation.
  **M3.1 is implemented and QEMU-tested, but not product-qualified:** the
  merged code has a dedicated non-root broker,
  read-only whole-disk device rules, a protected peer-credential-checked local
  socket, and an API that receives only bounded/redacted snapshots. The broker
  requires no-new-privileges, zero effective/permitted/inheritable capabilities,
  and no supplementary group beyond the read-only device group; it opens and
  closes the complete eligible candidate set without reading disk contents.
  SysV/mdev startup and the QEMU coldplug/hotplug assertions are implemented.
  Exact-head host run `36364383665` and QEMU run `36364383677` passed on
  `7254555`; the latter completed ARMv5 boot, broker smoke assertions, EX4
  research-DTB compilation, artifact upload and isolated-volume cleanup. PR #42
  was squash-merged to `develop` as `059fa24`. The previous pre-boot marker
  mismatch was corrected before this passing run.
  This point-in-time discovery does not
  establish global userspace or mount-namespace exclusivity and grants no
  content-read, mount, import or mutation authority. Those require separate
  evidence and hard gates, as do stable identity and compatibility.
  Cross-snapshot consistency comparisons also bind valid VPD status to a
  private, domain-separated SHA-256 equality digest, so a serial/WWN change
  cannot pass merely because both observations say `present`. Raw values stay
  in collector-local metadata; neither values nor digests enter API JSON or
  become stable identity. Host red/green coverage and the exact-head QEMU guest
  fixture pass; real EX4 enumeration and product policy remain unqualified.
- **M3.2 — Resolve stable identity.** Correlate device, partition, MD and filesystem
  identifiers; distinguish two descriptors for one object from two cloned
  filesystems. Never prove uniqueness from only the devices supplied by a caller.
  Report bay location separately from logical volume identity.
  The local M3.2a slice observes GPT only: its disk GUID and PARTUUIDs are joined
  to the complete generation-bound kernel partition set by partition number and
  exact start/size. DOS/MBR is unsupported and yields no disk/partition IDs.
  M3.2b classifies repeated disk GUIDs and PARTUUIDs independently as ambiguous
  within the observed GPT-candidate subset; singleton means only "seen once in
  this GPT subset," never globally unique. M3.2c retains the parser's GPT
  partition type GUID privately. M3.2d maps only a small allowlist of common
  GUIDs to generic declaration hints (`efi-system`, `linux-data`,
  `linux-raid-member`, `linux-swap`, and `linux-lvm`); unknown/vendor values
  remain `unknown`. A type GUID/hint is not evidence of contents, a WD role,
  or compatibility. Non-GPT candidates remain explicit
  coverage gaps, so unsupported MBR and no-table candidates cannot be mistaken
  for GPT uniqueness. A host integration fixture verifies duplicate IDs across
  two correlated candidates in a complete discovery snapshot. The QEMU smoke
  exercises the separate protected manual summary endpoint through the real
  broker against two distinct read-only cloned synthetic GPT guest disks and
  verifies duplicate GUID/PARTUUID classification end to end.
  The classifier revalidates canonical, nonzero lowercase disk/PARTUUID/type
  GUIDs and checks generic-hint consistency; malformed private bindings fail
  closed rather than weakening duplicate classification. Desired SMB/NFS
  policy now represents its logical `VolumeID` reference separately from the
  expected `FilesystemUUID` with distinct Go types; this does not imply a
  persistent resolver or physical identity proof. SMB/NFS previews derive
  proposed anchors from that logical ID; the filesystem UUID remains the
  expected lower-layer identity for a future resolver, not a check performed
  by the renderer. No anchor is provisioned and no mount/export authority is
  added.
  These observations are private and excluded from JSON; they confer no
  persistent identity, mount, import, compatibility or write authority. A
  separate authenticated, CSRF-protected manual `POST
  /api/v1/storage/gpt-observation` now invokes the trusted broker's fixed
  `observe-gpt` operation. It does not run during page load or ordinary storage
  refresh; those remain sysfs-only. The helper reads first-sector partition
  metadata and valid GPT headers/entry arrays only, never filesystem
  signatures, partition contents or file data. Exact generation-bound
  candidates are correlated to the complete current kernel partition set by
  partition number/start/size. The API receives only candidate/GPT/partition
  counts, coverage and duplicate counts; disk GUIDs, PARTUUIDs, geometry,
  kernel names and paths stay in the broker. MBR/DOS, other partition schemes
  and candidates without a valid GPT table remain explicit coverage gaps.
  The HTTP and broker each admit at most one GPT observation, and the broker
  retains one additional worker so ordinary inventory can remain available.
  Bounded request deadlines and redacted error handling return no partial
  result, but kernel uninterruptible I/O can outlive the timeout. Host/API
  tests, generated regular-image C tests, ARMv5 API-test cross-compilation and
  an ARMv5 helper link against the cached Buildroot sysroot/libblkid pass
  locally. A smoke-only local ARMv5 QEMU overlay also passed: it rebuilt the
  API and helper into a disposable rootfs copy, issued the authenticated
  explicit POST through the guest broker, observed two distinct cloned GPT
  disks/partitions, and verified duplicate counts plus summary-only redaction.
  The subsequent local integration run on `1358202` passed the Buildroot
  image/package integration, ARMv5 QEMU smoke and state-reboot fixture; artifact
  SHA-256 checks passed. It reused the existing fixed Buildroot and compiler-cache
  volumes, so independent clean-room reproducibility is still open. A later
  current-source API overlay on `0f2e44e` also passed QEMU smoke and the separate
  two-boot state-reboot fixture over cached kernel/packages; this is not a clean
  Buildroot rebuild. Hosted CI and EX4/product qualification remain pending.
  Keep raw IDs out of
  HTTP, MBR unsupported, and mount/import/repair/write authority absent.
  PR #44 merged the first read-only slice: correlate mounted filesystem UUID
  anchors with MD topology and verify the path against a disposable RAID1 guest
  fixture; it also fixes broker per-thread `no_new_privs` initialization. Exact
  host, Stage B3 and ARMv5 QEMU checks passed on head `f7bdc68`, merged as
  `db9fd33`. This does not provide persistent volume IDs, a bay map, a product
  resolver, import/mount authority or EX4 qualification; those remain M3 work.
  **M3.2e — mounted-root census (partial; locally tested):** a private Linux
  collector derives all eligible ext2/3/4 filesystem-root anchors from the
  complete current-process mount table, not a caller-selected subset. Explicit
  exclusions cover process root, subtrees, unsupported filesystems and
  zero-major devices; zero-major is not proof of non-block backing. Unknown
  nonzero devices, stacked mountpoint ambiguity or more than64 scoped roots
  refuse the entire observation. Fixed descriptor-based root observations are
  repeated and bracketed by complete sysfs/MD and mount-table observations.
  Private mountinfo ID/root retention detects same-path/device remount or
  subtree changes without confusing those IDs with statx unique mount IDs.
  Whole native vet/race, Windows preflight and actual ARMv5 existing MD/two-boot
  fixtures pass; seven base artifacts remain unchanged. No block node or file
  data is read, state written or product/API operation added. Next: join complete
  observations to an explicitly specified persistent VolumeID/compatibility
  authority and production roster. Do not convert this point-in-time census
  into qualification, global-use proof, an automatic import/mount or a lease.
  **M3.2f — scoped desired-volume review (partial; locally tested):** privately
  join validated desired VolumeID/expected UUID claims to the complete mounted
  census, never infer a persistent ID or select a pathname. Same-device root
  aliases count as one object; distinct devices with cloned UUIDs remain
  ambiguous. Missing/unclaimed objects and unresolved scoped physical-disk
  evidence remain explicit. Validate the full topology and independent original
  root observations before any desired subset, including empty policy. Native
  RED/GREEN checks cover changed derived UUID/unique mount IDs, and aliases,
  clones, incomplete input, ordering and16/64 bounds pass. Whole native race,
  Windows and actual ARMv5 existing MD/two-boot overlay pass; original base
  artifacts unchanged. No I/O, HTTP, persistent registry, qualifying token,
  Owner construction, mount/import or activation. Next authority still needs
  an explicit durable identity/compatibility contract, not a singleton UUID.
  **M3.2h — explicit full-census freshness (partial; locally tested):**
  validate the entire previous mounted-ext census before root observations,
  recollect through the fixed complete reader and compare scoped coverage,
  complete mount/storage snapshots, MD bindings and independent root metadata.
  Reject missing metadata, cancellation and changes even in unclaimed/excluded
  scope; ignore collection timestamps, not identity. Native cases cover empty
  and64-root scopes, corrupt prior records and drift. Whole pinned Linux race,
  Windows preflight and actual ARMv5 existing MD/two-boot overlay pass on
  `616579f`; the guest rejects coherent stale mount-ID and MD-UUID observations
  while accepting unchanged metadata. Base artifacts remain unchanged; this is not a
  retained lease, sticky Owner, persistent registry, global-use proof or service
  authority. M3.2g is the separate protected-registry contract below.
  Follow-up`fe1e855` extends the existing disposable MD fixture with actual
  ordinary unmount/read-only remount; ARMv5 standard smoke confirms absent/stale
  refusal, changed unique mount ID and fresh-census acceptance. Windows/native
  checks pass. Development-engine shutdown interrupts the original full overlay;
  after approved restart, unchanged API/runtime inputs rebase as`e22199b` on
  integrated PR80, and the remaining contracts plus actual standard ARMv5/
  two-boot overlay pass. Independent source/base hashes agree. This is local
  cumulative acceptance only; no production/physical authority is granted.
  **M3.2g — protected registry observation (partial; locally tested):**
  internal versioned explicit-ID/expected-UUID model with strict bounded JSON,
  canonical shareconfig validation and no writer/adoption. The Linux reader
  retains a trusted directory descriptor/shared flock, binds its effective
  owner once and accepts only fixed single-link0600 `volumes.json` beneath a
  private0700 directory, without symlink/cross-mount fallback or atime updates.
  Bracket file/directory metadata, refuse uncertainty and return immutable
  nonserializable provenance. Private pure reconciliation reuses full census
  validation and explicit scoped alias/clone/missing results, never a chosen
  mountpath or lease. Acceptance: strict model, actual Linux permissions/race/
  lock/lifecycle and complete resolver tests; existing ARMv5 disposable MD plus
  fresh tmpfs registry fixture, then whole standard/two-boot overlay all pass
  locally with the pinned image and existing two volumes; base artifacts remain
  unchanged. This is not clean/hosted/physical qualification. No product
  state placement, registration, root service, HTTP, mount/import or activation.
  Next: specify stronger backing identity/global-use/compatibility and recoverable
  registration separately; a UUID expectation is not durable physical identity.
  A private scoped backing review now distinguishes physical disk/partition,
  MD device/partition/stack and other block stacks after whole-census validation.
  Aliases count once, cloned/missing claims select no backing and unresolved
  physical evidence remains explicit. Whole local native race and actual ARMv5
  standard/two-boot fixtures pass, including the actual two-leaf MD array.
  Schema1 and authority stay unchanged; observed topology is not an expected
  durable backing selector, RAID health or WD compatibility qualification.
  The private policy-binding follow-up now compares validated atomic SMB/NFS
  policy with protected registry claims and the complete scoped census, requires
  exact ID+UUID agreement and retains separate revisions/reference counts.
  Unknown ID, conflicting backing, missing/cloned/unresolved scope and invalid
  split policy cannot become usable/planner evidence. Whole Windows/Linux race
  and actual ARMv5 standard/two-boot overlay pass locally; no registry writer,
  product state, HTTP, mount/import or service activation is added.
  **Reader-bound recheck (partial; locally tested):** a private origin and full
  file/directory stamps bind snapshots to one Reader. Retained nonblocking
  inotify mutation history closes a reproduced rapid same-byte/permission/
  directory ABA gap where full metadata remains identical. Recheck serializes
  with Read/Close and refuses zero/foreign/reopened/stale snapshots. Watch loss,
  overflow or64KiB drain exhaustion invalidates the Reader without retry;
  metadata-only fallback is forbidden. Whole Windows and pinned Linux tagged
  vet/race pass; actual ARMv5 standard/two-boot overlay verifies restoration
  refusal with unchanged base artifacts. Native synthetic overflow/drain tests
  do not claim actual kernel overflow reproduction. No schema/writer/HTTP,
  retained storage lease, global-use qualification, mount/import or activation.
  **Registry/census composition (partial; locally tested):** an internal
  collector takes one protected Reader and validated desired policy, observes
  registry plus the complete mounted-ext census and computes existing policy/
  backing reviews from that same pair. Recheck the entire census and original
  registry before returning; cancellation, restored registry mutations, root,
  excluded/unclaimed scope drift or reader closure return no partial result.
  Whole Windows/pinned native tagged race and actual ARMv5 standard/two-boot
  overlay pass, using the existing MD/tmpfs fixture and unchanged base. This
  sequential bracket is not an atomic/global snapshot, continued freshness,
  retained lease, compatibility qualifier or activation/planner authority.
  No writer, product startup, HTTP, mount/import or new privilege is added.
- **M3.3 — Gate compatibility and mounting.** Define a per-layout/filesystem
  allowlist with evidence. Inspect before assembly/mounting; journal replay and
  automatic MD actions can write even during a supposedly read-only assessment.
  Unknown signatures, mixed generations and degraded cases require refusal or a
  separately qualified policy, not best-effort mounting.
  Static review of WD 2.13.108 also found a RAID1 monitor path that may remove
  fault-marked members and attempt to add expected-but-unlisted partitions using
  SATA-connector mapping to current `/dev/sdX` devices. The extracted runtime
  mapping values and invocation schedule are unavailable, so no bay-move
  outcome is claimed. Migration discovery must not run this implicit repair
  policy; member removal/re-add/resync needs its own explicit, qualified workflow.
  The host-only `phantowd-lab inspect-storage-image-set` now correlates bounded
  GPT, ext, MD v1.2, MD v1.0 and MD 0.90 metadata across up to four supplied
  regular-file images, detects duplicate disk/partition/filesystem identity fingerprints,
  and withholds cross-image conclusions when any GPT input is invalid. It
  reports mixed filesystem/array signatures and inconsistent or incomplete
  metadata for review (including ext state not marked clean or requesting
  journal recovery); even a clean `metadata-observed` result remains
  `wd_compatibility=unqualified` and cannot authorize migration, assembly or
  mount. Static review of the extracted stock installer found data-array
  creation paths using MD metadata 1.0 (root-array paths use 0.90); the generic
  host inspector now reads and compares 1.0 components from offline images. This
  advances format observation only, not WD layout qualification. A dedicated
  local ARMv5 QEMU fixture now creates GPT on two 32 MiB disk images in tmpfs,
  then uses mdadm to create MD v1.0 RAID1 on partition 1 of each. The host reads
  both GPT images, validates each selected partition and reconciles the
  checksummed metadata as a set, requiring complete active-role coverage and
  unchanged parser inputs. The bounded firmware parser and complete trusted
  coordinator now run behind fixed storage-broker operation `observe-md-v1.0`.
  The broker performs full candidate discovery, GPT-to-sysfs correlation,
  generation-bound O_RDONLY opens, parser reads only on GPT-declared Linux RAID
  partitions, and storage/mount/swap rechecks before and after reading. Its
  client sends no path, device name or selection; the response contains only
  validated counts, redacted coverage/status and fixed limitations. Protocol
  v3 strictly validates this payload; no MD HTTP endpoint or automatic scan was
  added. The block-reading provider is compiled only in the Linux QEMU test
  build; normal firmware builds contain a fail-closed unavailable stub, so a
  local broker request cannot trigger MD reads on an EX4. The focused ARMv5
  QEMU fixture starts the non-root broker after mdev
  coldplug, writes MD metadata only with mdadm to two tmpfs-backed synthetic
  members, stops the array, then runs a separate API-UID client. It requires two
  GPT candidates, two RAID partitions, one metadata-consistent array and
  complete active-role coverage. The broker operation itself reads no
  filesystem content and does not assemble or mount. Host tests cover incomplete, conflicting, divergent and ambiguous
  sets. The host parser then reads the same two regular files read-only,
  extracts each exact GPT partition range to another temporary regular file,
  and also runs the standalone `inspect-md-v1.0-component-set` comparison;
  source and extracted-component hashes must remain unchanged. This validates
  broker isolation and generic parser agreement against a mdadm-authored
  synthetic sample, not an EX4 disk or WD layout. The same focused local
  wrapper now also runs a separate M3.4 stage: it formats only the disposable
  MD array as ext2, stops it, reassembles it read-only, mounts ext2 read-only,
  and passes the live Owner observation into a planner snapshot. This passed on
  the 2026-10-01 working tree based on `74ca3f9`; it is not exact-head or
  hosted-CI evidence. The host whole-image check reports the expected shared
  ext UUID as review while MD metadata remains consistent. A
  sanitized corpus of exact EX4 data-disk layouts and an evidence-backed
  allowlist remain required. Linux host regressions now inject storage-
  generation, mount-inventory and active-swap changes after GPT observation
  and during MD reads: pre-read changes prevent the MD parser from running;
  changes during a set read discard the entire result and close every source
  descriptor. An incomplete GPT result set is likewise rejected before MD
  parsing. These test-only observers do not change the fixed production probe.
- **M3.4 — Own mount lifecycle.** Model absent, discovered, rejected, qualified,
  mounting, mounted, unavailable, draining and review-required outcomes.
  Derive the transient mount tuple from trusted observations, not HTTP or an
  arbitrary directory. Revalidate descriptors/generation before handoff. The
  internal `mountowner` prototype now binds one fixed driver and observer,
  consumes one-use qualification, issues directory leases only after mounted
  identity verification, blocks new access during drain, revokes Owner-tracked
  handles after identity change, and sends uncertain mount/unmount outcomes to
  `review-required` without retry or implicit cleanup. Its QEMU-only driver
  pins the source and destination directory descriptors, rechecks that the
  fixed target pathname still names the pinned destination, and attaches the
  cloned mount with Linux `open_tree(AT_EMPTY_PATH)` / `move_mount(EMPTY_PATH)`;
  it has no path-based mount fallback. Deterministic QEMU races replace the
  target after owner preflight, again in the narrow interval after the driver's
  final pathname check but before `move_mount`, and the source after its
  descriptor is opened. The replacement target is never used: in the late
  race the mount attaches only to the renamed, pinned original object, then
  enters `review-required` before any lease is issued. The source test likewise
  uses only the pinned qualified filesystem before quarantine. Linux host tests
  and the current-source local ARMv5 QEMU overlay pass for normal lifecycle,
  overmount/revocation, ambiguous mount/unmount results, filesystem mismatch,
  and all three path-replacement cases. The Owner now also exposes
  `ObserveMountedVolume()`: under the lifecycle lock it revalidates and returns
  a non-serializable tuple for its one active volume. The QEMU service-planner
  fixture consumes this method instead of reading private Owner fields. A
  fixed-roster `MountedVolumeSet` now locks every member Owner in canonical
  target order, revalidates all members, rejects duplicate device/UUID/mount
  identity, and emits an all-or-error aggregate fingerprint/generation. The
  current QEMU roster is one synthetic volume; completeness applies only to the
  roster supplied by trusted construction and does not establish physical
  inventory completeness. No production roster source or adapter exists. A
  `MountedVolumeSet.Acquire` operation now retains leases for every member
  under the same canonical lock set and returns no partial authority: failed
  member revalidation rolls earlier leases back, and uncertain cleanup moves
  the affected Owner to `review-required`. Grouped directory opens are routed
  by logical volume ID; closing the set lease revokes all Owner-tracked handles.
  Linux tests cover multi-member drain blocking and rollback; the one-volume
  current-source ARMv5 QEMU overlay exercises acquire/open/release on synthetic
  ext2. A
  QEMU-only composed fixture feeds the synthetic MD v1.2 identity from the
  separate MD-stack fixture through a fixed M3.4 Owner roster and planner
  snapshot. A separate focused fixture now also composes the MD v1.0 broker
  observation with read-only reassembly/mount and the same Owner/planner path.
  Both prove only fixture bridges, not production discovery. The MD v1.0
  composition passed locally on the 2026-10-01 dirty working tree based on
  `74ca3f9`, not on exact-head hosted CI.
  These tests do not make unmount descriptor-based or establish production
  mount-point ownership. The prototype is not wired to product startup, the
  storage broker, a production qualifier or service handoff; no real NAS/disk
  test is in scope. It does not establish EX4 media compatibility or a
  deployable mount service. M3.4 remains incomplete until trusted production
  qualification, fixed mount-point ownership, service handoff, and operator
  review/recovery are specified and qualified.
- **M3.5 — Handle loss and return.** Stop new dependent access when a volume is
  lost, changed, read-only or unqualified. Never fall back to rootfs directories.
  Reappearance requires fresh identity/compatibility checks; a matching pathname
  or UUID alone is insufficient.
  The local `mountguard.Root` primitive now closes its own retained descriptor
  permanently after a failed identity/state check, so the same guard cannot be
  reused after the anchor reappears; opening a replacement requires a new
  trusted tuple. Host regression and ARMv5 QEMU mount-change coverage passed.
  A separate two-volume ARMv5 QEMU fixture now composes the M3.4 roster lease
  with distinct synthetic ext2 and read-only MD-backed filesystems. When the
  MD mount identity changes, that Owner enters `review-required`, its tracked
  handles are revoked, and the healthy volume's existing group-lease access
  survives. Returning the old MD anchor does not revive it; complete-roster
  reacquisition still fails all-or-error, while the independent healthy Owner
  can issue a fresh direct lease. This is disposable fixture evidence only.
  The group lease is not a production volume monitor or a per-service routing
  mechanism: dependent services are not yet owned, selectively withdrawn, or
  recovered by volume identity. M3.5 remains incomplete until production
  monitoring, per-volume service access revocation, fresh qualification on
  return, and operator review/recovery are integrated and qualified.

**Start in:** [volume probe](src/phantowd-volume-probe/README.md),
[supervisor](src/phantowd-api/volumeprobe/README.md),
[mountguard](src/phantowd-api/mountguard/README.md),
`tools/phantowd-lab/diskimage/` and `storageinventory/`.

**Acceptance:** generated disks cover duplicate UUIDs, aliases, omitted/unreadable
devices, signature collisions, mid-probe replacement, reordered discovery,
stale generation, filesystem refusal and volume loss. Assert no unexpected mounts,
writes or fallback directories. Physical bay moves require dedicated media tests.
Before any candidate descriptor is opened, a mountinfo device with nonzero major
must map to exactly one object in complete sysfs inventory; an unmapped nonzero
device fails closed. Major-zero pseudo-filesystems do not imply a block source.

## M4: Supervised SMB and NFS

Runtime prerequisite evidence now includes a disposable actual libatomic
ARM926 dispatch fixture: versioned exported calls, four widths, sequential
semantics/upper-64-bit CAS/overflow and bounded two-thread increments, with
zero-capability execution and exact target/image library checks. GNU readelf
resolver offsets are distinguished from selected function offsets. This
does not identify or qualify every implementation, instruction or memory
model, and cannot replace signed runtime manifests, process-set ownership,
physical EX4 testing or product activation. See the
[fast fixture contract](support/QEMU-FAST-TESTS.md#actual-libatomic-dispatch-on-arm926).

**State:** policy/rendering and isolated service fixtures tested. The internal
candidate planner has target parser evidence. A Linux adapter now obtains
identity evidence directly from `identityowner.Owner`; host tests and a local
ARMv5 QEMU Owner→adapter→planner fixture verify fingerprint freshness using an
empty policy and synthetic empty storage. A Linux adapter now converts a
lock-coherent, all-or-error snapshot from a fixed set of M3.4 mount Owners into
planner storage evidence. A local ARMv5 QEMU fixture uses a one-volume
synthetic roster to build non-empty candidates and validates the SMB candidate
with target `testparm`; the Owner-backed NFS candidate also binds the local
UID/GID census. Target `exportfs` separately accepts and withdraws this
Owner-backed NFS candidate in the disposable guest, requiring the prior export
table to be restored. The synthetic combined-plan `exportfs` fixture remains
separate. These tests reject stale identity/storage fingerprints and do not
enroll Samba identities or activate a product service. Roster completeness
means only that all Owners in that trusted roster were observed while their
locks were held; the QEMU fixture does not prove completeness over appliance
storage. No production roster provider or activation path exists.
**Depends on:** M1, M2, M3; M6/M7 before LAN qualification.

- **M4.1 — Typed activation plan.** Resolve validated policy against qualified
  volumes and actual identities; compile a bounded plan with expected revisions
  and observations. Refuse stale plans. Validate generated daemon configuration
  before replacing active configuration. The current internal
  `fileserviceplan` prototype checks complete synthetic identity/storage
  snapshots, qualified volume/UUID/anchor bindings, SMB account/passdb identity,
  NFS numeric identities, readonly constraints and exact revision/generation
  freshness. Its candidate is non-serializable and has no apply operation. A
  local ARMv5 QEMU fixture now checks the combined SMB candidate with target
  `testparm` and the NFS candidate with target `exportfs`; the temporary NFS
  export is applied only to the disposable guest fixture and then withdrawn.
  `identityowner.SetDesiredState` now supplies a separately revisioned,
  in-process registry desired-state toggle under the Owner lock and live Unix
  identity check; this does not mutate authentication, Samba state, share
  grants, or services. `identityowner.FileServiceSnapshot` now provides
  all-or-error registry/native/Samba evidence and local Unix UID/GID/name
  reservations under that lock; it uses one redacted batch passdb observation
  for Owner-ledger accounts (not a global Samba/foreign-identity inventory),
  rejects unjournaled existing entries and fails closed on interrupted or
  review-required SMB state before querying passdb, without rewriting journal
  evidence; it is non-serializable. Linux host tests cover this slice, and the
  Linux `fileserviceplan.IdentityFromOwner` adapter now turns that
  fresh observation into a planner input. ARMv5 QEMU exercises the real
  disposable Owner/passdb observation path, builds an empty-policy candidate,
  then changes desired identity state and verifies the old candidate is stale
  while a rebuilt candidate is fresh. Planner freshness now binds the registry
  revision and full SHA-256 identity fingerprint plus storage generation and a
  canonical SHA-256 fingerprint over the sorted complete mounted-volume tuple
  (logical VolumeID, expected filesystem UUID, fixed anchor, compatibility,
  mount ID, device major/minor and read-only state). Host regressions show that
  a changed mount ID or device tuple with a reused generation invalidates the
  old candidate, while volume enumeration order does not affect the fingerprint.
  Freshness, identity/storage evidence and plans reject JSON serialization.
  Current-source ARMv5 QEMU passes the planner and Owner-staleness markers; the
  isolated Owner freshness control still uses synthetic empty storage. A
  separate candidate now combines the disposable Owner's identity snapshot
  with the M3.4 fixed-roster snapshot, which acquires all Owner locks in
  canonical order and revalidates every member before yielding any evidence.
  A `fileserviceplan.StorageFromMountedOwnerSet` adapter converts that opaque,
  non-serializable set evidence into a snapshot carrying its owner fingerprint
  and generation. The QEMU roster contains one synthetic ext2 volume; its
  read-only NFS candidate uses the account's local UID/GID census. Host tests
  cover incomplete/ambiguous rosters, all-or-error behavior and lock ordering;
  the fixture rejects altered identity/storage fingerprints and performs no
  Samba enrollment or service activation. `fileserviceplan.BuildFromOwners`
  obtains the complete mounted-set evidence first and the identity snapshot
  second, holding both locks through evidence adaptation and deterministic
  candidate construction. External parsers and filesystem/process/service
  work remain outside those nested callbacks. Its ARMv5 NFS-only fixture also
  requires the Samba candidate to contain no share section. Roster completeness is only as sound
  as trusted roster construction. The combined SMB target-`testparm` and
  synthetic NFS target-`exportfs` checks remain separate fixtures. In addition,
  the Owner-backed NFS-only candidate is briefly loaded into a fixed temporary
  export file in the disposable guest; target `exportfs` accepts it, then
  withdrawal must restore the exact pre-test table. This validates parser
  compatibility for the combined Owner/mount tuple, not product activation.
  The production storage inventory-to-roster provider, legacy identity import,
  product service owner, HTTP route and transactional activation are absent.
  M4.1 remains incomplete until fresh storage and identity evidence are
  collected together through production owners and native validation plus
  configuration replacement are owned transactionally before product service
  changes.
- **M4.2 — Single service owner.** Define start/reload/stop and child-process
  ownership; bound diagnostics and verify readiness. Preserve the last known
  working configuration on syntax/start failure without claiming an unapplied
  requested revision is active. A Linux-only internal `processowner` primitive
  now pins and launches one foreground executable in an owned process group,
  bounds readiness, stop and diagnostics, and supports explicit lifecycle
  observation. If a process that passed readiness exits unexpectedly, the
  owner enters `review-required` and will not restart it implicitly. Linux API
  tests cover review/quarantine after unexpected exit; a local one-boot ARMv5
  QEMU smoke also starts disposable foreground `smbd`, waits for a real SMB
  readiness request, verifies generated access policy, and stops only the owned
  process group. Controlled BusyBox children then cover both recovery hazards:
  an unexpected nonzero exit moves `Observe` to `review-required`, preserves
  the generation and blocks restart; a second child ignores `SIGTERM`, forcing
  bounded `SIGKILL` escalation, review state, blocked restart and process-group
  cleanup. A third child times out before readiness while ignoring `SIGTERM`;
  after forced cleanup, a later `Stop` only verifies that its process group is
  gone and preserves `review-required` with restart blocked. The standard
  smoke passed locally on the current source tree; `qemu-smoke.sh` requires
  markers for normal start/ready/stop, unexpected exit, forced stop and
  failed-start quarantine. A Linux-only `processowner.Set` now owns a fixed,
  ordered set of child specs: all members must pass readiness before the set
  advances generation; a later startup failure rolls prior members back in
  reverse order, and uncertain cleanup quarantines the set. If a member exits
  unexpectedly, observation quarantines restart but leaves healthy peers
  running until an explicit stop; stop cleans all peers without clearing
  review. Host tests cover rollback order, immutable args, serialization
  refusal, member-level review and peer cleanup. The local ARMv5 QEMU smoke
  runs the same lifecycle with disposable BusyBox children. These synthetic
  children do not simulate an unexpected crash or forced stop of `smbd` itself.
  This is still not an SMB/NFS service manager, persistent service state,
  configuration reload, last-known-good transaction, or product startup.
- **M4.3 — Access semantics.** Specify SMB3 grants and denied cases; keep SMB1
  disabled. Support explicit NFS client/network rules, export paths and numeric
  identity/squash policy. NFSv3 compatibility has guest evidence; NFSv4 is a
  separate protocol/identity/recovery qualification, not an assumed feature.
  The combined desired-policy preview flags equal or ancestor/descendant
  SMB/NFS relative paths on the same logical volume for focused review. This is
  consultative only and does not block, mount or activate services. It is
  lexical policy evidence only: aliases, effective permissions and service
  behavior still require runtime qualification.
- **M4.4 — Storage-safe handoff (prototype; not complete).** The internal Linux
  `mountowner.ServiceHandoff` accepts fixed `ServiceShare` roots, retains a
  lease over the complete fixed volume roster, and clones only declared
  subdirectories from pinned `O_PATH` descriptors with `open_tree`/`move_mount`.
  It rejects whole-volume `.`, malformed paths, duplicate IDs and overlapping
  paths on one volume. Detached clones receive `nosuid,nodev,noexec`; a
  read-only request is applied with `mount_setattr` and verified through the
  attached mount. The private volatile handoff root remains
  `root:<service-gid>` mode `0710`. QEMU proves a 1000:1000 consumer can read
  inside the declared subtree, a sibling marker is absent from that clone, a
  read-only binding rejects writes with `EROFS`, UID 65534 cannot traverse the
  handoff root, and a mismatched process group is rejected. Source-anchor loss
  quarantines the Owner/handoff; the pathname does not follow a replacement.
  `ServiceRuntime` verifies bindings before startup, verifies storage after
  readiness, and stops its fixed process set before teardown. An uncertain
  stop retains the lease without retry. Callers must poll `Observe`; there is
  no automatic monitor, restart or production daemon wiring.

  Security limit: this is a share-scoped pathname view, not a complete service
  authorization boundary. Consumers still run in the host mount namespace and
  may reach the original volume path if its Unix metadata permits; that path
  could also bypass a read-only clone. Every process in the one fixed handoff
  group can traverse every share root in that handoff. No per-service grants,
  ACL enforcement/recovery, private process mount namespace, product identity
  provisioning or production storage constructor exists. Do not expose user
  data to this prototype and do not change source ownership/modes. Windows API
  tests, Linux API/vet, ARMv5 cross-compilation and the local one-boot ARMv5
  standard smoke pass with existing read-only Buildroot inputs and transient
  overlay/container space. The two-boot fixture, clean build, exact-head hosted
  CI and physical EX4 behavior are not qualified. No NAS or production media
  was used.

  Local follow-up: a separate native static-ELF launcher prototype passes a
  disposable ARMv5 QEMU fixture with a pinned restricted root, private mount
  namespace/propagation, zero capabilities, exact non-root credentials, FD and
  inherited-signal cleanup, preserved PID/PGID, and a read-only share. Eleven
  invalid launch cases are refused, including named filesystem FIFOs and
  read-only pipe ends on either diagnostic descriptor. The positive probe also
  checks closure of an inherited original-root FD 511. Complete cached local
  integration on `febc799` passes every existing guest lane; its seven exported
  artifact hashes are independently verified. The helper remains fixture-
  injected, not product-installed. The source is
  [phantowd-service-launcher](src/phantowd-service-launcher/README.md); run
  `support/test-service-launcher.ps1` using existing read-only cache/base
  inputs. It now runs through a fixed-input `processowner.IsolatedOwner` and
  proves readiness, descriptor/spec independence, normal stop/reap, refused
  close while running and pre-launch/live input-loss quarantine without retry.
  A separate `mountowner.IsolatedServiceRuntime` now composes exactly one
  static non-root child with a dedicated grant-only handoff root. A bounded
  root census refuses undeclared entries; an explicit pin blocks direct close
  while live. ARMv5 QEMU proves the original storage anchors are unreachable,
  writes through the grant fail with `EROFS`, and normal/source-loss cleanup
  reaps the group before releasing descriptors/clones/roster leases. Review
  never permits restart. This does not isolate the ordinary process Set,
  prepare daemon runtime manifests, implement per-client Samba privileges or
  control kernel NFS. Existing ordinary handoff behavior remains unchanged;
  no product service is enabled.

  Next: implement a trusted per-service root-manifest constructor and connect
  isolated owners to the multi-process Set/service-specific lifecycle,
  giving each service an isolated private mount namespace whose only
  storage roots are its explicit grants; prove the original volume anchors and
  ungranted shares are unreachable and that read-only access cannot be bypassed.
  The [Samba Owner packet](support/SAMBA-RUNTIME-PROFILE.md#next-owner-integration-packet-proposed-not-qualified)
  details the separate retained resources, code-only versus composed roots,
  process-group/`setsid` conflict, bootstrap/final privilege distinction and
  lifecycle acceptance campaign. It is proposed, not qualified or permission
  to run a new privileged composition.
  Keep daemon privilege profiles distinct: the real multi-user Samba QEMU
  fixture currently runs with root credentials and the pinned implementation
  performs Unix identity/group switches. The generic fixed-UID zero-capability
  child is not an implementation of those semantics. Define and validate a
  bounded Samba-specific runtime/privilege contract, preserving per-client
  Unix identities/ACLs; never substitute `force user` or shared credentials to
  make isolation tests pass. Kernel NFS remains a separate typed authority.
  The internal [runtime-bundle inspector](src/phantowd-api/internal/runtimebundle/README.md)
  now supplies a read-only prerequisite: a privately copied bounded code-only
  roster, complete descriptor-relative census, kernel-enforced read-only mount,
  exact hashes/modes/aliases and no cross-mount/symlink traversal. The disposable
  code-only permission regression additionally requires access/default ACL
  refusal on the root/directories and access-ACL refusal on regular files,
  even when mode bits and hashes match. Keep this distinct from supported
  data-grant ACLs; never strip users' permissions to satisfy code validation.
  The ARMv5 Samba-root fixture verifies this before adding configuration/state/
  grants and refuses altered plans. Its observation is not a lease, signed
  manifest, root constructor or execution token. The future constructor must
  obtain expected bytes from the trusted release boundary, serialize other
  writable views, retain pins and revalidate through start/stop/source loss;
  compose configuration, state, devices and Owner-held grants explicitly.
  Do not promote fixture text or the offline ELF candidate into authority.
  A separate `qemu && linux` prototype now stages fresh regular files from a
  pinned local read-only source into an exclusively owned empty 0700 tmpfs
  root. It uses descriptor-relative no-traversal/no-cross-mount operations,
  `O_EXCL`, hashes during bounded copies and exact final modes, then generates
  declared direct aliases. It rejects occupied trees, symlink source files,
  writable sources and canceled operations. Interrupted copies are disposable
  incomplete trees, never resumed or published. This replaces shell copying in
  the test fixture only; authenticated expected inputs, production root
  ownership/serialization, sealing and activation/recovery remain open.

  The internal retained-code Owner now privately holds the verified root and
  all regular files, plus independently pinned executables from a fixed process
  set. Its first adapter accepts only static ELF/non-root children: it does not
  authorize dynamic Samba or kernel NFS. Before/after launch and on explicit
  observation it checks the complete roster, hashes and original inode/mount/
  metadata identities. Drift or uncertainty requires permanent review and a
  bounded stop; restoring inputs never restarts. Explicit teardown stops/reaps
  every owned group before releasing pins, including accepted canceled cleanup.
  Unknown process ownership blocks release; later explicit verification cannot
  resend signals or clear review. Host/race and a separate finite ARMv5 fixture
  cover caller close, immutable inputs, duplicate Start, canceled teardown,
  same-byte replacement and live root drift. A subsequent ARMv5 fixture also
  proves aggregate Owner forced-stop retention through kernel `EBUSY`, followed
  by explicit reap verification/release without clearing review. This operates
  only on a private disposable code bind, not user data. Full cached local
  integration on
  `c93d936` passes; clean/hosted and EX4 qualification remain separate. Next
  compose the separately reviewed dynamic Samba root/privilege adapter with
  fixed configuration/state and Owner-held storage grants, then qualify durable
  review/recovery and source-loss supervision. Do not weaken the static adapter
  or treat a fixture-derived roster as a signed product manifest.
  The static supervisor and its focused-wrapper feedback contract also pass
  complete cached integration on `8e3ce63`, including actual ARMv5 fault cases
  and all existing image/guest lanes. Independent exported hashes match the
  preceding image: this remains a separately compiled probe, not product
  startup or hosted/physical qualification.
  The existing `NewIsolated` root pin now uses `SyscallConn.Control`, refusing
  caller Close-in-progress even when its kernel FD remains alive. A real
  deterministic constructor RED/GREEN, repeated host race checks and the
  actual ARMv5 launcher fixture cover this lifetime defect without starting
  any child with the invalid input or widening the static-child profile.
  This follow-up also passes complete cached local integration on unchanged
  `6cb8d46`, including all existing host/image/guest lanes and independent
  seven-artifact verification. Hosted and clean-build qualification remain
  separate; it does not grant service activation or EX4/product authority.
  Then define product-owned service identities and safe ACL provisioning and
  recovery without silently changing legacy ownership. Add the bounded
  source-loss supervisor and a fail-closed production storage constructor only
  after these denied cases pass. Keep real disks and services disabled until
  permission, recovery and compatibility matrices pass.

  An internal `runtimebundle.Owner.Supervise` now accepts only an already-ready
  static/non-root Owner. It serializes complete code/process observations,
  waiting a fixed bounded idle interval after each completed scan, without
  catch-up work or automatic restart. Accepted cancellation stops before return;
  code pins remain until explicit close, and uncertainty preserves review.
  The finite ARMv5 Owner fixture covers invalid/stopped/pre-canceled admission,
  exclusive lifecycle, clean cancellation, code drift, unexpected exit and forced
  stop, kernel group absence, pin retention and blocked restart. This is not
  production source-loss wiring or a dynamic Samba/NFS supervisor. Kernel stalls
  are not proven interruptible and physical polling budgets remain unqualified.
  A measurement around the existing Samba code scan produces redacted file/byte/
  monotonic-time evidence, without adding work. Treat QEMU time as emulation
  evidence only, never an EX4 throughput or resource-saving claim.

  Host-only prerequisite: `phantowd-lab inspect-runtime-closure` now derives a
  bounded ARM32 ELF candidate from the existing extracted-tree inventory.
  The host inventory now also observes processor-specific header flags; every
  selected object must declare EABI5 without hard-float procedure calls or BE-8
  code. Missing flags are refused, while implied base procedure calls are valid.
  This does not qualify ARM instruction/build attributes or symbol compatibility
  and adds no process or device authority.
  A further host-only observer now records explicit aeabi file-scope attributes
  with bounded lengths/counts, exact NTBS hex and absent/unobserved/refused
  states; private vendor payloads remain opaque and default/inherited values
  are not invented. The optional GNU target-readelf comparison covers 1,444
  CPU/ISA values across 361 objects, not every tag or hardware instruction.
  The current libatomic contains IFUNC variants and declares v7/Thumb-2 despite
  its EABI5 soft-float header. Qualify dispatch/kernel-helper behavior separately;
  neither blanket header acceptance nor a new CPU-tag-only allowlist is an
  approved runtime manifest. The dependency candidate's authority is unchanged.
  Pinned Linux unit/vet/race and 50,000 fuzz executions pass; the current cached
  target's `smbd` graph contains 105 distinct objects (27,110,832 bytes). It
  grants no execution authority and does not qualify loader caches, dynamic
  modules/NSS, runtime state, ABI or privilege semantics. The fixed disposable
  QEMU loader differential now passes with the default and 1000:1000 builders:
  all selected hashes/aliases match, 104 dependencies equal the candidate roster
  excluding smbd itself, and no daemon is started. The original rootfs stays
  unchanged. Fast parser/refusal contracts and full-build comparison hooks are
  implemented; exact-head full/hosted integration remains separate. Next inventory
  the remaining
  Samba runtime and implement a separately trusted root constructor. Do not
  treat this candidate as the product manifest or mark M4.4 complete.

  A separate [Samba restricted-root QEMU profile](support/SAMBA-RUNTIME-PROFILE.md)
  now verifies distinct-user SMB3, Unix file ownership/mode denial, kernel
  read-only grants, denied original paths, one Unicode filename and group stop
  under six bounded root capabilities. A fixture-only follow-up deliberately
  inherits original-root/ungranted-file
  descriptors and altered signal state, then checks actual closure, complete
  mask clearing and default dispositions before exec. Eight native negative/
  restoration cases exercise the actual checker before heavy builds. The live
  daemon additionally has zero inheritable/ambient capabilities; all prior
  distinct-user/ACL/streams/kernel-RO and verified group-stop tests still pass
  in the same actual ARMv5 boot. This is not the proposed separate Samba Owner,
  additional bootstrap authority or product startup qualification. One explicitly
  selected, hash-verified
  `streams_xattr` module also passes an SMB alternate-stream roundtrip, exact
  native xattr-byte checks and denied reader/kernel-read-only overwrites without
  modifying ordinary file data. It is a fixed disposable experiment,
  not a production constructor, per-client privilege certification, Owner-backed
  activation or full module/ACL/encoding qualification. Preserve that separation
  when constructing the trusted runtime and service-specific lifecycle.
  Before claiming ACL support, qualify the actual storage filesystem's POSIX
  ACL configuration and Windows ACL persistence/denials under the same bounded
  privilege profile. A disposable ext4 fixture now checks exact POSIX ACL bytes,
  named-reader access, denied writes/outsider reads and mask-based revocation.
  The missing ext4 kernel option was reproduced and corrected; kernel-input
  fingerprinting prevents cached fragments being silently ignored. This is
  not Windows ACL or migration qualification. Do not silently choose permissive masks,
  ignore system ACLs, change xattr namespaces or add mount-admin privileges.
  The separate CP850 gap is now reproduced by a dynamic ARMv5 conversion probe
  inside the same restricted root. QEMU selects only IBM850 through Buildroot;
  the fixed graph/canonical catalog validator and disposable overlay pass exact
  bidirectional bytes/aliases and reject unsupported or malformed UTF-8 without
  replacement. Full local new-config and combined integration now pass with
  the actual installed converter; exact-head feature CI remains separate.
  This does not enable SMB1 or establish complete legacy name,
  case-folding or Unicode-normalization compatibility.
  A separate ext4 inheritance fixture now creates a directory and file through
  real SMB and verifies exact access/default ACL bytes, setgid group ownership,
  `2750`/`0640` modes and reader/outsider denials without metadata/data mutation.
  Disable DOS-to-Unix execute-bit mappings in the explicit runtime profile while
  storing DOS metadata; the synthetic archive flag remains visible via SMB.
  Do not infer all policies, legacy import, reboot persistence or trusted
  product construction from these disposable tests, even after full local
  integration passes. Global policy is still
  separate from the share-section renderer and requires complete validation.
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
  **M5.4a — desired-policy change review (partial; locally tested):** after the
  existing whole-policy preview, compare explicitly loaded baseline/candidate
  by stable definition/user IDs and exact NFS CIDRs. Semantic before/after
  rows cover volume/user references, SMB definitions/grants and NFS definitions/
  client access, squash, anonymous IDs and security. Reordering/revisions alone
  are not access changes. At most 512 changed entries; larger/ambiguous reviews
  refuse without partial output or Save. Text-only semantic table and candidate
  lifecycle clearing add no endpoint, request, automatic save, activation or
  browser persistence. Complete DOM/Windows/native tests and actual ARMv5
  embedded-asset standard/two-boot overlay pass. Real-browser/accessibility,
  hosted feature and production management remain separate gates; no current
  service or filesystem permission is inferred from this desired comparison.
  **Cross-protocol pair advisory (locally tested extension):** loaded baseline
  and candidate identify equal/nested SMB/NFS folders by stable share/export
  IDs on the same policy VolumeID, including pairs removed from the candidate.
  Counts cover the complete bounded pair census; retain only64 sorted details
  with an explicit remainder. Missing lexical overlap is not alias/effective-
  access proof; SMB and NFS revocations remain independent. The advisory limit
  does not block Save. Complete DOM/Windows checks, pinned Linux tagged
  API vet/race, fixed fuzz/contracts and actual ARMv5 standard/two-boot overlay
  pass on the combined increment. Counts/retention limits are fixture-tested,
  not measured browser/device performance. Hosted acceptance, browser and
  product activation remain open.
- **M5.5 — Accessible efficient UI.** Keyboard operation, labels/focus, narrow
  viewports, screen-reader status and high contrast; bounded static assets and
  shared observations. Avoid per-client hardware polling, stale-response
  overwrites, duplicate submissions and unbounded retained logs.
  **M5.5a — diagnostic request ownership (partial; locally tested):** one browser
  snapshot generation owns the existing four read-only requests and a 10-second
  deadline, including body decoding and a snapshot-originated auth reread.
  Sign-out/password-change or unavailable/unauthenticated status invalidates
  that generation, aborts its reads and clears observations immediately. Late
  successes, errors, auth bodies and finalizers cannot repopulate a retired
  session, overwrite a new session or unlock its current refresh. Duplicate
  refreshes do not issue another set; no read is automatically retried. Domain
  failures still clear only failed values and report partial freshness.
  Actual-source DOM regression first reproduces retired-session data after
  logout, then passes eleven deterministic cases in five groups. Windows/API,
  pinned native tagged vet/race and actual ARMv5 asset integration plus clean
  two-boot overlay pass on code `fab3b7e`. No server endpoint/authorization,
  privilege, job, hardware polling or service activation changes. Browser abort
  does not prove server/kernel work stopped; real-browser/accessibility and
  product authentication/recovery remain separate gates.
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

**State:** internal desired-policy model tested; product application planned;
board network observations limited.
**Depends on:** M1/M5; M7 for physical networking.

- **M6.1 — Network domain.** Specify DHCP/static addressing, subnet masks, routes,
  DNS, hostname and both physical interfaces. Validate conflicts and interface
  identity; do not hardcode an operator network or assume all LANs use /24.
  **M6.1a — desired syntax (partial):** the internal
  [networkpolicy contract](src/phantowd-api/internal/networkpolicy/README.md)
  validates schema-1 IPv4/IPv6 modes, static aliases, default priorities,
  non-default routes, hostname and manual/automatic DNS for two logical slots.
  Bounded strict JSON, duplicates, cross-slot static subnet conflicts,
  gateways and route ties are checked. Windows preflight, pinned Linux
  vet/race, fixed-count mutation/fuzz tests and same-boot ARMv5 QEMU plus
  the clean two-boot overlay pass. No network syscall, persistence or HTTP.
  Slots are NOT qualified kernel/factory identities. Next M6.1 work must
  admit actual interfaces and observe current/leased address conflicts; the
  model cannot establish connectivity or authorize application. Cached overlay
  is not a new full Buildroot image, EX4 test or product qualification.
  **M6.1b — private kernel observation (partial):**
  [networkinventory](src/phantowd-api/internal/networkinventory/README.md)
  uses fixed bounded link/address netlink dumps, namespace pin/checks and two
  matching samples. Interrupted/filtered/truncated/incomplete dumps, malformed
  records, namespace/set drift and cancellation refuse without retry/partial
  output. Raw names/MACs/addresses/state stay private; summary is redacted.
  Native unprivileged collection/race/mutation/fuzz and actual ARMv5 same-boot
  kernel observation plus clean two-boot overlay pass. Recheck is not an event
  subscription, generation lease, factory identity or atomic snapshot. Remaining
  M6.1 work: board-qualified slot bindings, route/use/conflict and DAD admission,
  fresh authority and production integration. No policy application or HTTP.
  **M6.1c — configured FIB observation (partial):** the same private collector
  now includes bounded IPv4/IPv6 configured routes across all returned tables,
  terminal/local routes, source/destination prefixes, effective table, metric,
  gateway/via, preferred source and correlated interface/ECMP references.
  Attribute ordering is normalized; ECMP member order is preserved (M6.1e
  corrects the earlier sorting assumption). Unknown attributes, nested metrics
  and referenced nexthop IDs remain private and explicitly unresolved. Semantic
  changes refuse matching samples; volatile cache usage/expiry is excluded,
  reported cache error retained. Fixed strict requests exclude cached exceptions;
  only the declared route scope accepts Linux's FILTERED response flag.
  Link/address filters and interrupted/truncated dumps remain refused.
  Windows preflight, pinned Linux whole-API vet/race, generated wire tests,
  bounded fuzz and actual ARMv5 route assertion plus two-boot overlay pass locally.
  No route lookup/evaluation, rule/object dump, event lease, reachability,
  persistence, application, HTTP or physical qualification follows.
  **M6.1d — private IP routing rules (partial; locally tested):**
  two fixed strict IP-family dumps, checked response family, prefix/scalar/range
  framing and bounded private semantic equality. Preserve within-family order,
  same-priority ordering and duplicate multiplicity; normalize only family dump
  order. Detached interface, goto/complex/unknown semantics remain unresolved.
  Native actual unprivileged capture/race/fuzz and Windows preflight pass.
  QEMU multiple-table support is requested/audited in the existing network
  fragment; refresh Linux within the same cache, not a new output namespace.
  Complete cached new-kernel integration passes on unchanged `e0986fc`, including
  actual same-boot positive rule assertion, clean two-boot and all other guest
  lanes. Seven exported hashes and image/export/target API equality are checked
  independently; resolved kernel options are audited. This is local cached
  evidence, not hosted topic or independent clean-build qualification. Production
  EX4 profile/configuration remains a separate gate. No rule evaluation or apply.
  **M6.1e — private nexthop objects (partial; locally tested):**
  one fixed strict AF_UNSPEC dump observes all returned objects, not just route
  references; completed empty and missing rosters are distinct. Bound 128
  objects/32 ordered members, correlate local OIF and route/group IDs, reject
  missing/duplicate targets and group nesting, retain effective 16-bit weights.
  FDB/encapsulation/unknown semantics and resilient groups without bucket
  observations remain unresolved; joined route IDs still grant no routing
  authority. Object dump/attribute order is normalized, member order preserved.
  Two complete sets/recheck must match, with private IDs/count-only summary.
  Inline ECMP sorting reproduced a real hidden-drift regression; corrected
  parser preserves order and non-adjacent duplicate refusal. Pinned no-flag LWT
  encapsulation framing has a separate RED/GREEN test. Native whole API
  vet/race, actual UID1000/zero-capability collection/FD counts, 25,000-execution
  object/route fuzz and Windows preflight pass. Actual ARMv5 kernel collection
  plus nonempty generated weighted-group assertions and clean two-boot overlay
  pass on code `319a331`; those overlay checks alone are not a full image/SBOM
  build or independent clean/hosted/physical qualification. The subsequent
  complete cached integration passes on `cec1527`; PR #74 then passes its own
  exact `02bdb0c` host/QEMU checks and integrates as `f19e6eb` with whole-tree
  equality. No physical networking or release qualification follows.
  Live nonempty kernel-group behavior remains a separate acceptance gap.
  **M6.1f — local address preflight (partial; locally tested):** privately join
  a validated policy and complete immutable inventory through exactly two
  transient slot-to-ifindex bindings. Return overlapping diagnostic counts,
  never admission: exact/missing prefixes, same-address/peer use and subnet
  overlap anywhere locally, conservative link/address flag blockers, scoped
  local gateways, unresolved dynamic families and disabled unbound slots.
  Validate every bound link, including disabled slots; reject invalid/copied/
  canceled inputs with zero output. Observe interfaces outside the bindings;
  handle /16,/31,/32 and IPv6, alias flags and link-local gateway scope explicitly.
  Windows preflight, complete native tagged vet/race, fixed 2,000-case mutations,
  existing bounded fuzz/feedback contracts and actual ARMv5 standard/two-boot
  overlay pass on code `68fae6b`, tree-identically rebased as `8bf993d`.
  The generated fixture is mandatory in the existing boot, with actual kernel
  collection checked separately. No new stage, parser, syscall, privilege,
  endpoint or network change. Counts do not prove external address availability,
  policy ownership, address lifetimes/DAD or routing/DNS reachability. Factory
  binding, fresh authority and M6.2 recovery/application remain open.
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
  Static WD 2.13.108 analysis distinguishes connector-based MD member mapping
  (connector/partition pairs resolved to the current `/dev/sdX`) from the
  logical `/DataVolume` mount. The live `DVC_MDS` mapping and bay-move behavior
  remain unverified; the legacy RAID1 auto-reinsert path is mutating and must
  not be reused for discovery. See the [storage compatibility matrix](STORAGE-COMPATIBILITY.md).
- **M8.4 — RAID jobs.** For each supported mode specify create/import, degraded
  operation, replace/rebuild, resync, scrub and removal. Plan destructive extents
  before confirmation; reject wrong members and conflicting generations.
  Do not auto-assemble, reshape or repair unknown arrays.
- **M8.5 — SMART and health.** Bounded collection/history, stale/unsupported/error
  states, scheduled checks that respect standby, authorized extended tests,
  progress and deduplicated alerts. A SMART pass is not an integrity guarantee.
  - **M8.5a — Report semantics (partial implementation).** The internal
    [offline parser](src/phantowd-api/internal/smartreport/README.md) projects
    bounded smartctl 7.4/7.5 / JSON 1.0 ATA reports into fixed states. Match the
    embedded status to the separate process exit; preserve collection errors,
    reported status and current/historical flags independently. Reject
    ambiguous/inconsistent input atomically. Host/fuzz and synthetic ARMv5 tests
    are not device, transport or executable qualification. A separate
    [native producer oracle](support/SMART-REPLAY.md) runs actual upstream 7.4/7.5
    with the generic backend and seven synthetic ATA stdin transcripts per release, including
    exit-zero disabled and partial failing status. This is not an ARM producer
    or physical collector test. No device commands,
    public endpoint or installed collector exist yet. Newer tool/schema profiles
    need upstream review and attributed generated reports before selection.
    The earlier C-only output was retired and the new C++ toolchain rebuilt.
    Actual static7.5 producer/projection tests pass on the ARM926 guest against
    the unchanged manifest-verified earlier base; v5TE/v5TEJ soft-float are the
    explicit guest profiles. Complete local C++ image/package/legal-info/SBOM
    integration and existing guest/service requalification passed on `dd55481`,
    including seven final artifact hash checks. This cached run is not clean
    independent reproducibility, hosted feature or physical qualification.
    Reuse downloads/bounded ccache and a single generated output; do not add a daemon or physical
    collector authority as a side effect of that prerequisite.
  - **M8.5b — Trusted collection.** Bind each report to the retained disk's
    generation and recheck it before publication; refuse replacement, disappearance,
    duplicate identity and stale observations. Review a separate least-privilege
    SMART command boundary: the raw read-only metadata broker does not already
    authorize ATA/SMART ioctls. Pin executable/runtime/options, bound stdout/stderr,
    concurrency, duration and memory; distinguish process signals/timeouts from
    8-bit exits. Unsupported transport and command/checksum errors must not become
    healthy states. First test fakes/QEMU only; physical qualification is separate.
    The internal [coordinator](src/phantowd-api/internal/smartcollect/README.md)
    now fixes a backend/target/budget at construction, checks complete-census
    token and major/minor/diskseq before and after one capture, and quarantines
    changed sources or uncertain process cleanup. Constructor-issued handles
    cannot be copied to fork lifecycle state. Host/race/fuzz and the existing
    diskless ARMv5 parser boot test these semantics with fake backends only;
    this supplies no executable/device provenance, streaming output bound,
    physical SMART authority or product startup. Implement the separately
    reviewed fixed command boundary and trusted provider next. A separate
    Linux single-use capture primitive now retains fixed code/regular-stdin
    descriptors, copies options, observes bounded before/after drift digests,
    stream-bounds stdout/stderr and distinguishes real ordinary exits/signals.
    Host lifecycle tests and a test-only adapter in the existing ARM926 producer
    boot pass seven genuine generic-producer projections and fake-source-change
    refusal. This closes neither authenticated/isolated runtime nor device
    provenance, ioctl, standby or physical qualification; no product startup
    uses the primitive. Debug-free guest tests fit the existing copied image;
    injected bytes are verified before boot even if debugfs reports success.
    An additional private sysfs census reuses the complete schema-v2 collector
    and topology validator, not import/mount eligibility. Its non-virtual whole
    leaf view retains mounted disks, active MD members, removable/read-only
    flags and missing/invalid/ambiguous VPD states. Whole-inventory comparison
    includes private VPD evidence, unrelated nodes and topology; invalid or
    forged partial views are refused. Native race tests and the existing ARMv5
    smoke pass, including the mounted root and two active disposable MD members.
    This point-in-time observation is not `SourceAdmitted`, a census token,
    retained device binding, SMART-capable transport or command authority.
    Product startup, broker operations and HTTP remain unchanged.
    A separate Linux-only [descriptor witness](src/phantowd-api/internal/smartdevice/README.md)
    retains a supplied read-only block FD with CLOEXEC duplication protected
    against caller-close/reuse. It rechecks type/access, major/minor and the
    kernel's BLKGETDISKSEQ, refusing value copies/concurrent operations and
    retaining permanent review after failed observation. Native race/refusal/
    no-leak tests and actual generation checks on the existing temporary QEMU
    MD members pass. Closing the caller FD leaves the independent pin usable;
    an intentionally changed expected tuple tests sticky review, not hotplug.
    It opens no path, reads no disk content, exposes no FD and admits no SMART
    command. This is neither report attribution nor a provider/capture lease;
    complete census reconciliation, fixed opener, transport/runtime authority
    and physical qualification remain separate. No product/broker wiring changes.
    The private Linux complete-census witness set now requires one borrowed
    O_RDONLY source for every whole leaf and retains independent descriptors
    all-or-error. It observes the entire inventory before/after all witness
    checks; failures keep review and pins until explicit Close, with no command
    or child ownership. Native race/refusal tests and the existing actual ARMv5
    MD fixture pass for all seven virtual leaves, reordered sources, partial
    rollback, caller-close independence and injected reader failure; the
    standard smoke and two-boot overlay pass. The complete native ReadLinkFS
    regression catches a missing Lstat method without weakening the collector.
    The observation remains point-in-time, not report attribution, source
    admission, stable identity, transport/wake qualification or product wiring.
    Complete cached local package/image/legal/SBOM integration and all existing
    guest lanes subsequently pass on35ae558, with seven exported hashes and
    image/export/target API equality verified. Independent clean reproduction,
    hosted qualification, command authority and product wiring remain open.
    Do not add
    history/UI by treating this transient tuple as a stable media identity.
  - **M8.5c — Wake policy.** Specify exact no-check/device-detection behavior per
    tool and transport. Low-power skip must have explicit evidence; exit bit 1
    alone is ambiguous. Do not parse tool prose to claim standby. Verify that
    scheduled checks/autodetection do not wake supported drives on sacrificial
    hardware, with cooling and recovery gates satisfied. Unknown power state
    cannot authorize a heavy check or force SMART enablement.
  - **M8.5d — Bounded history.** Store versioned observations by trusted stable
    identity plus generation, with collection age/scope and explicit unknown,
    partial, stale and unavailable states. Cap records/retention/writes; do not
    join unrelated disks after a bay move or identity collision. Treat vendor
    raw counters and units as model-dependent; no universal Seagate counter or
    power-on-time interpretation. Test boot-clock changes and disk replacement.
  - **M8.5e — Self-test jobs.** Separate observation from authorized short/extended
    test mutations. Plan exact disk/generation, thermal/load limits and interaction
    with active arrays/clients before consent. Record intent/progress and terminal
    observations; interruption or uncertain effect requires review, not automatic
    retry/restart. Cancellation must have supported observed semantics. Never use
    production media to qualify the first mutation path.
  - **M8.5f — Alerts and panel.** Show reported status, collection reliability,
    current vs historical flags, observation age, scope and next safe action.
    Keep SMART, filesystem, RAID and backup assessments separate. Deduplicate
    alerts by stable event identity with bounded history; redact raw tool output,
    serials/WWNs, paths and secrets. LED/display alerts depend on M7 qualification.
  - **M8.5g — Acceptance.** Cover pass with historical warnings, explicit fail
    during partial collection, unsupported/disabled/low-power ambiguity,
    missing/truncated/oversized/duplicate fields, status contradictions, signals,
    timeouts, races, vendor units and stale observations. Qualify actual tool
    reports and standby/self-test behavior independently of synthetic parser
    fixtures. Measure CPU/RAM, idle writes/wakeups and mixed-load thermal behavior.
- **M8.6 — Backup/restore and stock return.** Define verifiable data/configuration
  backup and restore paths, and constraints on returning to stock after metadata
  changes. Removing disks protects them during diskless tests; it is not a
  replacement for migration backups or proven future readability.

**Acceptance:** disposable healthy media cover supported layouts, reorder/bay
moves, missing members, full storage, interrupted import/rebuild and restore.
Compare file contents, ownership, modes/ACLs and metadata before/after. Publish
support per tested combination; refuse untested combinations without mutation.

## M9: iSCSI targets and LUN lifecycle

**State:** desired-model prototype; target backend/lifecycle planned.
**Depends on:** M1/M2/M3/M5/M7/M8.

- **M9.1 — Backend decision.** Evaluate the kernel/userspace target implementation
  for this kernel, ARMv5 and resource budget. Record package/license choices.
  Do not assume legacy WD target configuration is directly portable.
  **M9.1a — isolated LIO prerequisite and target fixture (local research):** a pinned-archive,
  fresh-tmpfs ARMv5 kernel helper enables built-in LIO/FILEIO for a separate
  research profile, not the standard QEMU or EX4 defconfig. Six Windows/Linux
  profile test groups and ShellCheck pass; the actual kernel compile succeeds.
  A separate actual ARM926 guest with pinned libiscsi now verifies good CHAP,
  exact wrong/missing/foreign login refusals, capacity/512-byte blocks, effective
  RO/RW, retained backing through replace/unlink and closed/missing descriptor
  refusal without recreation. Session observation, forced TPG disable, revoked
  I/O/new-login refusal, re-enable data and complete teardown pass locally.
  Initialized virtual entropy is required; no fixed seed/auth bypass is used.
  This does not implement a product mutation-refusal or authority owner. FILEIO's
  O_CREAT/RW and control delimiters prohibit blindly using a desired pathname;
  credential configfs attributes require a separate privileged/redacted owner.
  One bounded local wrapper supports fresh tmpfs compile and a small verified
  candidate for fast feedback, without new Docker images/volumes. Pure host CI
  must not be confused with actual target qualification.
  **Expanded M9.1a local evidence:** actual reciprocal CHAP accepts distinct
  synthetic credentials and refuses exact wrong inbound/target response/name;
  inactive-session credential rotation rejects old login and preserves data.
  Two explicit ACL peers are concurrently observed with independent credentials,
  primary RW and secondary RO; cross-peer credentials fail and one logout leaves
  the other session/data usable. Missing/duplicate/unknown/contradictory consumer
  markers refuse (native RED/GREEN). This remains one LUN/pinned-client QEMU,
  not product credential/session ownership, Windows or interrupted rotation.
  **Required-mutual gate:** unmodified pinned LIO permits one-way login even with mutual
  credentials configured; source and actual guest agree. Do not label that
  setting enforced mutual authentication. A product policy requiring both
  directions must refuse admission until a separately reviewed enforcement
  solution is qualified; an explicitly approved weaker policy would be distinct.
  **Research subset now verified:** an opt-in default-off kernel option rejects
  missing initiator challenges only when outbound credentials are configured.
  Separate fresh strict/default actual ARM926 guests pass exact refusal versus
  upstream acceptance, reciprocal exchange, rotation, two-peer RO/RW, retained
  data and teardown. Seven profile/seven result groups, wrapper strict-cached
  refusal and host-only workflow selection pass. This patch applies only in
  disposable research tmpfs, not product/standard QEMU/EX4 kernels. Independent
  security review, product backend selection/integration and credential admission
  remain open; a target cannot prove an untrusted client checked its response.
  **Multi-LUN/block-size research subset:** fresh strict/default actual ARM926
  guests now verify 32 MiB/512-byte and 8 MiB/4096-byte retained FILEIO objects,
  exact ACL LUN sets primary0/1 RW/RO versus peer0/3 RO/RW, capacity, distinct
  seeds, readback/peer-write visibility, denied writes and exact ungranted-LUN
  SCSI refusal, then full teardown. Clients are sequential; the existing
  single-LUN concurrent-session test remains. A RED/GREEN native C matcher
  regression fixes an invalid sorted-REPORT-LUNS assumption without weakening
  exact cardinality/uniqueness/membership. Host-only gates now include7 profile/
  8 result groups and512 finite matcher vectors; they are not target execution.
  Multiple-target/other-client and production allocation/use/session admission
  remain open; this is not a product 4096-byte backing qualifier.
  **Next M9.1b:** typed internal backend admission/observation contract: retained
  backing identity and writable authority; bounded credentials with reserved
  configfs-value refusal; redacted session observations; no automatic creation
  or recovery. Qualify required-mutual enforcement, durable/live-session
  credential rotation and exact active-session mutation refusal before any
  product owner; extend multiple-LUN/client compatibility separately.
  Add crash, full/backing-loss and uncertain teardown campaigns separately.
  See the [research contract and source boundaries](support/ISCSI-LIO-RESEARCH.md).
  **M9.1b metadata prerequisite (internal prototype):** `internal/backingpin`
  borrows an actual qualified Root and retains existing single-link regular
  parent/file O_PATH references, with exact expected size and no data access.
  Unique mount identity/flags, inode/size/mode/UID/GID/link drift or unresolved
  names quarantine permanently; restoration cannot revive the pin. Explicit
  serialized close releases its references, not the borrowed Root. No raw
  descriptor or JSON observation is exported. This is neither writable authority
  nor a tracked mount-owner lease, allocation/global-use admission or target
  adapter. Metadata I/O is not guaranteed nonblocking. Native lifecycle tests
  require unique mount IDs; the mandatory actual ARMv5 ext-root fixture covers
  missing/unsafe objects, replace/unlink/truncate/mode/hardlink/parent restoration,
  O_PATH read/write refusal, concurrent/uncertain close, nested/leaf binds,
  private read-only transitions and Root loss. Finish the remaining writable
  lifetime, coherent desired/registry qualification, allocation/access/use/session
  and credential gates above; do not mark M9.1b complete for this prerequisite.
  **Writable-reference lifecycle prototype:** private constructor binds an
  already-open exact RW descriptor to the metadata Pin and an immutable trusted
  backend. Successful construction exclusively owns all three; failure does
  not consume caller references. Start/observation bracket readiness with
  identity checks; drift/exit/uncertainty stops once before release. Active or
  uncertain resources block direct Pin close; stop uncertainty preserves RW
  and metadata references in review, never automatic retry/restart. Native
  lifecycle seams are not descriptor admission. Require actual ARMv5 real-Root
  descriptor/unsafe-flag refusal, inherited FD writes by a UID1000 child,
  verified stop/reap before release, unchanged replacement, unexpected exit,
  concurrent stop and uncertain retention. Test-only disposal after independent
  reap is not product recovery. No exported owner constructor, product opener,
  LIO backend, tracked mount-owner/use/session/allocation admission or activation
  follows; qualify those remaining capabilities rather than widening this fixture.
  **Writable prototype local acceptance:** native state-machine race/count3
  and actual ARMv5 real-Root descriptor/duplicate-claim/stop-lifetime cases pass,
  with the existing full two-boot lane. A fixed static UID/GID1000 consumer
  replaces the reproduced BusyBox setuid second-exec readiness race; all32
  post-write credential observations remain required. No guard is relaxed.
  This adds neither a qualified writable opener nor a LIO adapter. Next compose
  protected coherent policy/use admission with the retained mount lifetime below;
  do not promote the existing advisory overlap review into that authority.
  **Retained mounted-roster prototype:** metadata-only `OpenFromMountedLease`
  privately pins one member of an existing complete roster. Whole-roster rechecks
  retain canonical locking; returned directory references are independently
  owned, not double-closed Owner-tracked handles. Direct group close stays busy
  through live/uncertain consumers; metadata/RW closure precedes root-pin release.
  Uncertain closure retains the claim without retry or implicit unmount. Native
  race/count3 covers unselected-member drift, drain/generation/identity failure,
  concurrent release and uncertain-close retention. Actual ARMv5 proves fixed
  mounted-owner composition, failed-admission cleanup, constant FD count across32
  checks and normal/replace/exit/uncertain writer lifetime. Separate actual
  same-filesystem overmount proves metadata-only root loss retains independent
  FD/group claims until release. Additional actual same-filesystem overmount
  cases now prove a live inherited-RW UID1000 consumer quarantines: confirmed
  stop/reap precedes release, deliberately uncertain stop retains the live
  child and RW/metadata/mount claims, and exact bind restoration cannot revive
  the owner, retry stop or issue a new lease. Independent fixture teardown
  must complete before success; a cleanup error cannot masquerade as expected
  review. The fixed consumer writes once then holds its FD; physical I/O failure,
  mid-transfer interruption, target sessions, autonomous supervision and durable
  recovery remain separate. Old two-boot state acceptance remains required and
  passes. No product writable opener,
  LIO adapter, roster startup, coherent admission or persistent recovery follows.
  **Local acceptance:** Windows preflight/cross-compile, pinned whole Linux
  tagged vet/race, focused race count3, storage contracts and smoke ShellCheck
  pass. Native positive syscall cases skip explicitly on unsupported unique
  mount IDs; actual ARMv5 Linux6.18.54 qualifies the real-root fixture including
  UID/GID drift and the existing two-boot state lane. Cache-reusing API overlay,
  not clean Buildroot reproducibility, hosted feature or physical qualification.
  **Explicit supervision prerequisite (internal host/QEMU):** a blocking
  operation exclusively owns one already-active policy/mount/backing consumer.
  Scan immediately, then after a fixed one-second idle period; no overlap,
  catch-up, start/restart or detached goroutine. Accepted cancellation uses a
  fresh five-second operation context and requires verified stop/reap plus
  successful reference closure before policy release. Drift/exit/uncertainty
  remains review without retry; unaccepted canceled requests have no effects.
  Native race/count3 covers exclusion, policy fencing, cancellation during scan,
  source/exit/close faults. Actual ARMv5 four supervised policy cases and both
  existing real overmount-loss cases pass with the complete standard/two-boot
  lane. Join test supervision before independent disposal; no extra guest boot
  or product startup. This is not universal I/O interruption or a qualified
  hardware polling/resource budget. Full backend/code/access/allocation/global-
  use/session/credential composition and durable recovery remain prerequisites.
- **M9.1c — protected credential lifetime prerequisite.** The first-release
  decision permits root-owned recoverable plaintext (`0700` directory/`0600`
  document); encryption at rest is later work with an explicit key/recovery
  design, not an implied property. Internal root-only reader reuses revision
  store locks/checks/watch/claims, resolves all policy SecretRefs, rejects missing
  and identical byte values and backend-reserved names, and binds a fixed trusted
  consumer at acquisition. No document read API or provisioning/rotation writer.
  Private backing lifecycle retains its own credential/policy/mount/RW claims
  through uncertain preparation/stop/closure, without retry. Root-native and
  disposable actual mounted QEMU tests pass locally; buffers deny JSON/text
  disclosure and invalidate borrowed handles only after verified teardown.
  This is not complete LIO/target-wide admission. **Next:** qualify typed LIO
  credential install/readback and exact borrower teardown, compose target-wide
  multi-LUN/code/access/allocation/use/session/network ownership, design random
  generation/import provenance and protected provisioning/rotation recovery,
  then product startup and UI. Length checks are not entropy qualification;
  CHAP and root-only files provide neither transport nor at-rest encryption.
- **M9.1d — complete-target resource lifetime (internal prototype).** One
  private constructor now retains the exact selected target's existing Pin/RW
  roster, one coherent policy revision and one credential bundle through the
  existing lifecycle/supervisor. Refuse incomplete/extra/foreign/duplicate
  members and observed inode/device aliases across bind views. Order by explicit
  LUN number, not input position. Each member must match desired VolumeID/path/
  capacity and pass real descriptor/root checks; provisional claims roll back
  without closing caller references or preparing a backend on failed admission.
  The fixed backend borrows a defensive complete roster. Confirmed teardown of
  **every** process/session/kernel borrower precedes all data closure; all data
  closes precede any Pin release; complete metadata/mount closure precedes shared
  policy/credential release. Later-member drift or partial start/stop/closure
  remains terminal review without retry. Uncertain stop retains all sources;
  partial close retains remaining resources/global claims without reopening.
  Native race and actual disposable mounted ARMv5 LUN0/LUN7 two-file cases,
  512/4096-byte metadata, failed second-file rollback, later-file replacement
  and uncertain stop pass with the complete standard/two-boot lane. This is
  resource ownership, not LIO authentication/access enforcement or product
  eligibility. **Next:** implement a typed LIO adapter with complete-roster
  credential installation, redacted readback and verified borrower teardown;
  qualify actual retained-descriptor binding, idle/session refusal and safe
  rollback under fault injection before joining code, media, allocation,
  access/global-use/network owners. Do not expose target operations or promote
  desired enable/access to authority. Provisioning, durable uncertainty recovery,
  product startup, UI and physical/recovery qualification remain separate gates.
- **M9.1e — typed credential install/readback (private prerequisite).** The
  fixed Linux configfs sink borrows backend-owned TPG/auth directories, requires
  root-owned writable configfs and rechecks confined named-ACL topology against
  supplied descriptors. Complete peer matching precedes a single attempt;
  fixed leaves receive opaque buffers directly, exact bounded readback accounts
  for show/store newline differences and wipes transient scratch. CHAP unsets
  stale outbound fields. Partial I/O, observed drift or uncertainty permanently
  enters review without retry/rotation. Native race/refusal tests and actual
  fresh-source default ARMv5 zero-data-LUN CHAP/reciprocal protocol cases pass,
  including foreign same-configfs ACL refusal and object teardown before claim
  release. All old protocol/session/data assertions remain. **Following M9.1f**
  composes the sink inside the fixed complete-target backend, not a per-operation
  callback. **Next:** qualify retained code/network and exclusive writer authority,
  complete access/session observations and partial-install faults,
  writer exclusion, non-forcing session refusal and retained-file control binding
  with actual multi-LUN I/O. Only after these gates may product lifecycle,
  durable recovery, startup and authenticated UI transactions be composed.
  Disabled snapshots are not atomic/continuous history proof; configured mutual
  credentials are not required-mutual enforcement or kernel memory erasure.
- **M9.1f — retained-storage LIO composition (private prerequisite).** Capture
  a validated immutable target definition; independently retain root-only
  configfs directories and every exact admitted LUN descriptor. Create NEW
  objects only and witness each directory/link before use/removal. Bind data
  through integer-only proc-FD values, never desired paths. Fixed typed CHAP
  installation/readback stays inside this backend; refuse unsupported mutual
  enforcement before effects. Separate partial-start state from readiness.
  Recheck enabled state, credentials, authentication flags, exact storage
  properties and each ACL mapping's access attributes. Require the optional
  non-forcing idle-disable primitive before any portal/data binding. One stop
  attempts verified disabled/session-idle state and owned-object teardown
  before the containing Owner releases any source; uncertainty retains all
  remaining references in terminal review, never force/retry/reopen.
  **Locally tested:** native/cross-compile contracts, actual guarded ARMv5
  complete target with LUN0/7,512/4096-byte RW data and real qualified mount;
  original-file readback, changed second member/mapping quarantine, injected
  uncertain-stop retention/no-retry and independent fixture disposal. Actual
  write-only configfs refusal/acceptance and native RED/GREEN protect control
  open modes. Old separate protocol gates plus standard/two-boot tests pass.
  **Next acceptance packets, before product composition:**
  1. M9.1g below now proves this adapter's per-initiator RO/RW and ungranted-LUN
     denials through real clients, not the separate manually configured fixture.
  2. M9.1g now proves established-session stop refusal, SAME-client fresh I/O,
     retained resources and terminal review after logout. Pending-login
     side effects, admission fencing and exclusive portal/configfs mutation
     authority remain open; established-session proof is not those guarantees.
  3. M9.1h below proves early/later setup collisions and referenced-storage
     partial teardown. Still fault every store/readback/close/delete boundary, including later
     members; qualify one-attempt cleanup, remaining-reference retention and
     bounded resources. No partial success, adopted foreign object or force.
  4. Compose retained runtime-code/network and protected registry/storage/
     allocation/global-use authority under documented lock order. Desired
     policy, this loopback prototype and point-in-time snapshots supply none.
  5. Only then add durable lifecycle/recovery, root-only secret provisioning/
     rotation, product startup and authenticated UI transactions. Keep physical
     media/NAS installation behind independent hardware/recovery gates.
- **M9.1g — adapter access/session proof (locally tested prerequisite).**
  Two CHAP peers with distinct credentials: exact primary LUN0/7 RW, peer
  LUN0 RO roster, precise write-protected/ungranted-LUN SCSI refusals, crossed
  credentials/foreign IQN denied, independently preserved original data.
  A separate real Owner stop with one established libiscsi context refuses;
  that SAME context performs fresh reads and writes on BOTH LUNs afterward.
  All sources remain held in terminal review; logout never restores authority,
  and lifecycle calls never retry. Independent QEMU-only idle/disposal checks
  remove witnessed objects before fixture source release without resetting
  backend/Owner state. Native RED/GREEN consumer contracts require separate
  exact access/session markers. Final native, actual guarded ARMv5, old protocol
  gates and standard/two-boot tests pass; no product startup/HTTP/NAS operation.
  **Next:** M9.1h adds three real fault cases; still fault every
  mutation/readback/close/delete boundary, including later
  members; prove residual resource retention and no foreign-object adoption.
  Qualify exclusive writer/portal authority and pending-login behavior before
  composing code/network/registry/storage/allocation/global-use ownership.
  Define durable recovery and new-login fencing explicitly: refused active
  teardown keeps the target enabled and resources live, not fully revoked.
- **M9.1h — bounded configfs faults (locally tested prerequisite).**
  Actual guarded ARMv5 exercises an existing target before effects, an existing
  second storage after first-LUN setup, and a separate test-owned LUN holding
  the first storage through partial teardown. Foreign identity/data remain
  preserved; successful cleanup precedes source release, while uncertain
  teardown keeps complete descriptor/Pin/mount/policy/secret claims in terminal
  review without retry. Independent witnessed fixture disposal is not product
  recovery and never resets lifecycle state. Mandatory exact result evidence,
  native contracts/race, actual old protocol gates and standard/two-boot pass.
  The initially invalid double-link trigger is diagnosed and retained as an
  exact kernel EEXIST/no-created-link regression; no retention assertion is
  weakened. **Next:** complete store/readback/close/delete fault and resource-
  bound campaigns; qualify writer/portal/pending-login authority, then retained
  code/network/registry/storage/allocation/global-use and durable recovery.
  No product activation, HTTP, hardware/NAS action or exhaustive-coverage claim.
- **M9.1i — exact owned-target topology (locally tested prerequisite).**
  Generate immutable expected directory names from captured policy and pinned
  kernel defaults, not observations. Census target/TPG, ACLs/LUNs/portals,
  per-peer mappings and owned LUN/mapping/portal directories. Accept at most
  64 entries per directory, detect overflow/partial/error results, reopen
  confined `.` with an independent offset, bracket original configfs identity
  and owned-entry checks. Check before/after enable and around active attribute/
  credential observations. Never census unrelated targets as though this Owner
  owned the global fabric. Actual foreign-ACL RED precedes implementation;
  final guarded ARMv5 foreign ACL/LUN/mapping refusal preserves foreign objects,
  retains complete sources on uncertain stop and keeps no-retry review.
  Native/14 marker contracts/all old actual gates/standard two-boot pass.
  **Next:** M9.1j adds bounded portal/extra-TPG cases; still qualify concurrent
  shared-portal and link/name-change cases, max-policy
  resource/FD campaigns, complete write/readback/close faults and independent
  writer/portal/pending-login admission. Snapshots cannot detect a mutation
  restored between scans or supply atomic enable/writer exclusion. Then compose
  protected code/network/registry/storage/allocation/global-use and durable
  activation/recovery. No HTTP/startup/physical device authority is added.
- **M9.1j — bounded foreign endpoints (locally tested prerequisite).**
  Actual guarded ARMv5 adds a NEW guest-loopback portal under the owned TPG
  and a separate NEW default-disabled sibling TPG with no portal. Observation
  refuses both; one stop preserves foreign identity and complete claims in
  terminal no-retry review. Prove the distinct partial outcomes: foreign
  portal leaves the owned TPG disabled but retained; sibling TPG blocks target
  removal after owned TPG teardown. Independent witnessed fixture disposal
  releases sources without resetting lifecycle state. Fifteen mandatory result
  contracts, native vet/race/repetitions, fresh guarded guest/all old gates and
  standard two-boot pass. Product backend behavior/privileges remain unchanged.
  **Next:** shared-portal/concurrent writer/pending-login admission, max-policy
  FD/resource and complete write/readback/close fault campaigns; compose actual
  code/network/registry/storage/allocation/global-use ownership and durable
  activation/recovery. These bounded cases are not global writer exclusion,
  foreign session fencing, a recovery API or hardware qualification.
- **M9.1k — declared backing exposure admission (private prerequisite).**
  Check the selected target's ENTIRE roster against validated canonical SMB/NFS
  paths on the same logical VolumeID. Equal/ancestor/descendant/root overlap
  refuses even for RO grants or desired disabled targets. Check before resource
  transfer, credential preparation and LIO configfs effects; close singleton
  policy-bound bypasses. Desired saves and advisory previews remain possible.
  Native tests cover component boundaries, RO/RW, logical-volume separation,
  unchanged input and no partial output. Mandatory standard ARMv5 fixtures use
  actual mounted Pins/RW files and retained policy/CHAP owners: a later-member-only
  conflict must reject without backend effects or retained claims, preserving
  caller resources and original data. Native vet/race/repetitions, actual
  standard ARMv5/two-boot regression and fresh guarded LIO/all old gates pass
  locally; cached overlays do not establish clean-build or EX4 qualification.
  **Next:** qualify actual object aliases across paths/logical volumes, shared
  protocol/global-use ownership and concurrent activation/foreign consumers under
  explicit lock order. Passing lexical isolation is NOT global-use/writable
  admission. Keep runtime/network/allocation, durable recovery and hardware gates.
- **M9.1l — cooperative actual backing-object ownership (private prerequisite).**
  Require the SAME internal authority at every writable constructor, including
  older singleton paths. Observe each actual RW descriptor against its held Pin
  before an atomic whole-roster reservation keyed by device/inode, not path,
  VolumeID, mount ID, target label or open-description identity. Bound the roster
  and complete authority; reject uninitialized/closed/reviewed authorities.
  A later collision must reserve no earlier prefix and consume no caller file
  or Pin. Keep reservations until verified whole-backend stop, all data and Pin
  closures and source release; uncertainty stays terminal review without retry.
  Lock order is lifecycle → individual Pin, separately lifecycle → authority;
  the authority never calls consumers/sources or performs I/O under its lock.
  **Tests:** actual independent-open ARMv5 tracer RED/GREEN; actual mounted
  later-member-only target refusal and singleton reuse; mandatory ARMv5
  concurrent admissions with exactly one winner and verified whole-stop reuse;
  full tagged vet/race, old LIO gates and standard/two-boot regression.
  Native actual-object positive cases SKIP on the local WSL 6.6 kernel without
  unique mount IDs; aggregate success is not positive syscall qualification.
  Existing tests pass locally, including fresh guarded LIO/all old gates and
  actual standard/two-boot regression. No serialized use claims or recovery
  reset, product opening/activation, HTTP, NAS or physical disk operations.
  The mandatory real mounted ARMv5 concurrency/reuse fixture now passes locally:
  join both independent admissions before release, require one winner and one
  conflict with caller handles intact, run/reap the actual first child, verify
  every member closure, then reuse the losing original handles through the
  SAME authority and require a fresh child write/verified stop. Standard and
  complete two-boot regression pass; this replaces the missing local native
  positive evidence, not the native unique-mount guard or clean-build CI.
  A mandatory actual later-FD-close fault also passes: the earlier data FD
  closes, but all metadata/source/whole-object claims remain in terminal review;
  fresh independent earlier-object admission refuses and lifecycle calls never
  retry or launch. This prepared-only fault deliberately closes a caller-owned
  descriptor first; it is not active-LIO recovery, media I/O or ECC evidence.
  Actual mounted capacity qualification also passes: 63 distinct prepared
  singleton objects leave one slot; a two-file target refuses without publishing
  a prefix, the unused first input admits as object64 and another refuses;
  verified closure frees two slots for a complete target through the SAME book.
  No injected inode/map identity or backend start; standard/two-boot pass.
  Kernel-independent native JSON/reconstruction refusal and empty-close tests
  execute under race count3, independently of the skipped statx-positive cases.
  **Next:** integrate this authority into a qualified product composition and
  separately fence external/cross-protocol access, foreign target/session use,
  allocation and retained storage/network lifetimes. Distinct authorities do
  not coordinate; success is NOT complete global-use/writer exclusion.
- **M9.2 — Target model.** Stable target/LUN identity, backing volume/object,
  capacity/allocation policy, initiator access and protected authentication
  secrets. Secrets are not returned by read APIs or exposed in diagnostics.
  **M9.2a — internal desired file-LUN model (locally tested prototype):**
  `internal/iscsipolicy` uses shared VolumeIDs and their exact desired revision,
  independent typed target/LUN/backing IDs, explicit capacity/block size,
  allocation, target state and per-peer LUN grants. Each backing has one owner;
  equal/ancestor same-volume paths, orphan backings, repeated LUN identities/
  numbers, cross-target grants and read-only escalation refuse. The initial
  canonical ASCII IQN/CHAP profile has explicit bounds and distinct symbolic
  credential references, not secret resolution or worldwide name uniqueness.
  Strict JSON requires a LUN number even when zero; every failure returns zero
  and a constant redacted error. Windows preflight, pinned whole Linux tagged
  vet/race, 2048 fixed malformed-input cases and the pure standard ARMv5
  same-boot fixture pass locally; the existing two-boot state tests also pass.
  This is a cache-reusing source overlay, not a full new Buildroot image, target
  authentication/session test, hosted feature or physical qualification. There is
  no HTTP/store, listener, backend config, secret/file open or product activation.
  **Next:** decide/qualify backend naming, LUN-addressing and allocation modes;
  bind protected credential references and storage/global-use/network authority;
  define coherent persistent policy ownership rather than independently saving
  this document alongside SMB/NFS. Extend legacy names/auth only through explicit
  compatibility decisions. Do not turn syntactic `enabled` into startup behavior.
  **M9.2b — internal registered-volume/backing review (prototype):** compare
  the desired file-LUN policy with the protected registry, complete mounted-ext
  census and coherent SMB/NFS policy inside one shared read/recheck bracket.
  Preserve independent iSCSI/volume/registry revisions, unknown/conflicting/
  missing/clone states and unresolved physical evidence. Unknown logical IDs
  cannot bind by UUID; only an exact single scoped observation carries actual
  physical/MD topology counts. Count distinct referenced registry IDs and
  same-volume root/equal/ancestor SMB/NFS path exposures (including RO) per
  stable BackingID. Exposure remains advisory, not admission or activation.
  Raw observations reject JSON; invalid whole evidence or final drift yields
  zero composite, even with no desired LUNs. No backing/credential file is read.
  **Acceptance:** bounded 64-backing/multi-target tests, alias/clone/unknown/
  conflict/unresolved cases, volume-scoped path boundaries, no shared mutable
  result, whole-census/registry-ABA/cancel refusal, plus actual ARMv5 disposable
  MD census reconciliation and restoration during final checks. Preserve the
  old whole-scope tests and require the new guest assertion in standard smoke.
  **Next:** do not use this diagnostic as an opener token. M9.1b must separately
  obtain retained qualified file/mount authority, prove capacity/allocation,
  guard symlink/hardlink aliasing and global-use/session races, and bind protected
  credentials. Coherent durable all-protocol policy ownership, network listeners,
  product startup, UI and legacy import remain separate work. No physical test
  or persistent registration/activation is authorized by this prototype.
  **M9.2c — coherent all-protocol desired state (internal prototype):** one new
  `phantowd-nas-service-config` schema1 envelope contains the existing strict
  file-service and iSCSI formats. All seven revision/binding values agree;
  registry/device generations remain separate. Bounded raw-envelope validation
  retains nested bytes for independent strict decoders and child limits, with
  zero/redacted failure. Linux adapter reuses the single-document revision engine
  under a lifetime private-directory lock, fixed0600 files and one rename/sync.
  No old-format automatic import, pending promotion or empty-corruption fallback.
  **Acceptance achieved locally:** Windows strict-model/API/cross-compile; pinned
  whole Linux tagged vet/race and focused count3; existing/new seven-boundary
  SIGKILL old/new nonempty whole-policy campaigns count3; actual ARMv5 standard
  smoke and clean generated-disk two-boot nonempty SMB/NFS/iSCSI persistence,
  pending/corrupt preservation, stale/mixed refusal and later coherent reopen.
  **Next:** protected single state owner, explicit legacy format migration,
  filesystem-qualified power-loss recovery and runtime freshness/claim ownership.
  Never configure old/new stores as independent authoritative writers. No new
  HTTP, product startup, credential/backing opening or target activation. Coherent
  desired state is necessary but not admission; retain the M9.1b use/access/session
  and backend gates. See the [contract](src/phantowd-api/internal/naspolicy/README.md).
- **M9.2d — Retained coherent desired-policy owner (internal prerequisite).**
  Reuse the revision engine behind a private initialized-state owner, not a
  second parser/writer. Bounded opaque all-protocol revision claims fence both
  publication and Close. Fresh defensive values are not authority; a service
  owner must retain its claim until independently confirmed consumer teardown.
  Bracket fixed-name reads with metadata and mutation epochs; refuse restored
  ABA, cross-mount/symlink reads and loss/overflow/uncertainty without retry.
  Preserve claims/flock in review; never implicitly stop/release a consumer.
  Explicit no-claim commits start a verified new epoch. Exercise native race,
  bounded/no-leak/forgery/cancellation and six publication-failure boundaries;
  keep the existing ARMv5 two-boot nonempty policy lane and require claim fences,
  coherent epoch advancement and permanent restored-mutation quarantine.
  These tests/implementation do not install a product service owner or establish
  power-loss recovery, session/global-use/credential admission. Next privately
  compose policy claims with qualified service, identity and mount ownership,
  define exclusive product state placement/format migration, then qualify
  supervision/controlled activation and durable operator recovery. No new HTTP,
  extra guest boot, backing open or NAS operation follows from this prerequisite.
  **Local acceptance:** Windows/API/ARMv5 cross-compilation, whole pinned Linux
  tagged vet/race, focused owner/store count3, shell/storage contracts, actual
  ARMv5 standard smoke and the complete two-boot state fixture pass with the
  mandatory owner marker. Acquisition/Commit/Close races and restored mutation
  during decode are covered. Cached overlay, not a clean hosted/physical test.
- **M9.2e — Privately compose policy and backing lifetime.** Implemented as an
  internal host/QEMU prototype, not product activation. Acquire an Owner-private
  revision claim, match BackingID to mounted VolumeID/path/size, reuse descriptor
  admission and bracket kernel/readiness observations with policy verification.
  Release only after verified stop/reap and successful data/metadata/mount-root
  closure; uncertainty retains claims and prevents publication/Close without
  retry. Failed admission consumes no caller resources. Desired target state
  and symbolic credentials are not execution, access or allocation authority.
  **Local acceptance:** whole pinned Linux tagged vet/race and focused count3,
  Windows preflight/cross-compilation, shell/storage contracts, actual ARMv5
  standard smoke and complete two-boot state pass. Three policy lifecycle cases
  plus both actual mounted-loss cases retain the private claim. Native close
  faults and pre/post-start mutation remain distinct from real guest admission.
  Next compose qualified code/backend, registry/media identity, access and
  allocation, global-use/session and protected credentials, then product
  supervision/recovery. No extra guest boot, HTTP surface or NAS operation.
- **M9.3 — Guard mutations.** Create/enable/disable/grow/remove operations check
  real initiator/session ownership and backing-volume state. Prevent local
  filesystem mounting while an initiator owns the LUN; prohibit unsafe shrink.
  Session presence and disconnect races need observed pre/postconditions.
  **M9.3a — research-only idle-disable prerequisite:** pinned ordinary configfs
  disable is forced. An optional default-off research patch exposes the existing
  force-zero path under the TPG access mutex; a guarded QEMU fixture requires
  an established session to survive refusal with fresh I/O, then verifies idle
  disable, coherent core enabled state, exact RTPI reuse, new-login refusal and
  explicit data-preserving re-enable. Fresh combined strict/guarded and unpatched
  default actual ARM926 guests pass locally on 2026-10-05; the four-way option
  matrix is native-contract coverage, not four guest builds. The original
  prototype's omitted core bookkeeping has a preserved actual RED/GREEN gate.
  This does not guard other mutations: pending logins can be interrupted,
  concurrent writers/shared portals and product transactions remain open.
  See the [research-only contract](support/ISCSI-LIO-RESEARCH.md#optional-non-forcing-disable-research-profile).
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
  A/B slots are a candidate, not an assumed fit or implementation. Static
  analysis of the final stock updater confirms legacy XOR/CRC checks rather
  than cryptographic authenticity, destructive writes to the kernel/ramdisk/
  rootfs MTD targets, and optional rescue/front-controller paths. The packed
  rootfs stream is bad-block-aware and omits OOB; it is not a flat raw-NAND
  image. Stock rescue and error recovery have not been demonstrated at runtime,
  so none is an installer or rollback plan. No production layout is selected:
  it must preserve user data and per-unit identity, tolerate data disks being
  absent/replaced, and have bootloader-readable rollback proven on sacrificial
  exact-model hardware before a writer is implemented. See the
  [EX4 board research status](board/wd/ex4/README.md).
- **M10.2 — Trust and release discovery.** Retrieve immutable GitHub Release
  metadata/assets; verify signatures against pinned trust roots, exact model/
  revision/channel, hashes and version policy before writes. HTTPS alone is
  insufficient. Define signing-key rotation, compromise/recovery, offline use,
  rate-limit/network failure and owner-authorized rollback policy.
  The host-only GitHub reader now handles opaque signed query parameters on
  the exact HTTPS release-asset CDN without treating them as authenticity.
  Real local HTTP/TLS redirect fixtures preserve signature-before-payload and
  hash checks; public transport errors redact signed URLs while retaining
  programmatic cancellation/cause checks. API metadata URLs remain query-free.
  This is a tested transport primitive, not device trust-root provisioning,
  target installation or a published firmware qualification.
  **M10.2a — host installer prerequisite (partial; host-integrated):** optional
  `--installer-version` uses the existing bounded SemVer comparison against the
  authenticated `minimum_installer`. It runs after signature/schema/exact-target/
  channel checks (and immutable signed tag matching for GitHub), before payload
  I/O or staging. Equal/newer versions pass this prerequisite; older versions
  refuse, including a prerelease below a stable minimum. Invalid supplied syntax
  fails before HTTP. Omission preserves integrity-only behavior, without an
  installer assessment. Windows complete host vet/unit and pinned Linux whole
  host-tool vet/race pass; generated HTTP fixtures assert request boundaries.
  The module tree remains identical after rebasing onto qualified PR #75.
  This caller-supplied version is not device attestation, installation permission,
  persistent anti-rollback, or a target transaction. No signing/schema/trust-root
  change, firmware build, physical operation or release qualification follows.
  PR #76 subsequently passes its own exact `f247139` host check and integrates
  as `bb9802e` with expected/checked/integrated complete tree `238dbd00`.
  **M10.2b — strict host manifest/payload boundary (partial; locally tested):**
  signed schema1 root/artifact fields require exact decoded spellings and all
  required non-null fields/types, bounded lists and well-formed encoding.
  Case aliases/duplicates, unknown fields, surrogate repair, wrong shapes and
  unbounded nesting cannot produce a VerifiedManifest. The previous signed
  root/artifact case-alias acceptance reproduces twice before the fix. Actual
  HTTP fixtures refuse malformed signed metadata before any payload request.
  Payload hashing consumes at most signed size plus one byte, rejects changed
  opened size and retains size/hash/metadata checks. Whole Windows host vet/unit
  and pinned Linux whole host vet/race pass. No signature bypass, schema/CLI/
  trust-root change, firmware build, physical operation or installer is claimed.
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
  A bounded build collector now supplements upstream `legal-info` with the
  authenticated original Buildroot archive, preserves upstream warnings and
  refuses conflicting existing output. This closes one source-input omission,
  not complete corresponding-source review or public source publication; exact
  project/modified Buildroot/config/toolchain coverage remains a release gate.
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
| Samba credential adapter and active-session revocation | Native source/runtime/failure tests, M2; account-scoped disable/revoke is QEMU-verified, product integration/handle semantics remain open |
| Supported new/legacy filesystems and RAID modes | Corpus plus empty-media validation, M3 + M8 |
| First-enrollment/reset presence and certificate trust | Threat model and recovery UX, M5 |
| Dual-port modes and safe network rollback | Isolated policy tests + exact-device evidence, M6 + M7 |
| Fan/watchdog/power-control commands | Verified controller protocol and thermal instrumentation, M7 |
| Target backend and LUN migration | ARMv5/runtime ownership tests, M9 |
| Flash layout, A/B feasibility, trust-key recovery | NAND/boot/rescue evidence and review, M10 |
| Performance targets and qualification duration | Baseline hardware measurements and declared protocol, M11 |

## Next bounded work packets

Current priority (2026-10-06): **M4.4 separate Samba-specific service Owner
→ M3 production roster/qualification
+ M4 durable activation Owner**. Keep local-first validation and exact-head
integration serialized; do not restart a heavy qualifier for each intermediate
checkpoint. The actual cooperative target concurrency/reuse fixture passes
locally, but native positive tests skip on the unsupported local kernel.
Separate Samba Owner host/disposable-QEMU development is approved. Its first
owned-group prerequisite does not complete retained dynamic code/configuration,
identity/storage authority or product activation. Keep the static/non-root Owner
unchanged, qualify the separate bootstrap boundary and retain all inputs until
verified complete-group stop. NAS/disks and persistent operations remain excluded.

M4.4's owned-group prerequisite is now locally host/ARMv5 qualified: fixed
guarded bootstrap entry, pinned helper, real distinct-account write/read/denial
checks, unchanged capability/namespace/root boundaries and verified whole stop.
It is not the retained-input service Owner. Complete the remaining packet in
this order, preserving the [full contract](support/SAMBA-RUNTIME-PROFILE.md#samba-specific-owner-integration-packet-hostqemu-scope-approved):

1. Retain independently validated code-only tree descriptors and original
   identities; keep the exact census separate from the composed service root.
   The private shared preparation helper now passes local native and actual
   ARMv5 checks, including caller closure, cancellation, complete release and
   unchanged generic dynamic/root refusal. Static lifecycle/drift/forced-stop
   checks are requalified. This prerequisite releases its Samba inputs before
   service construction: live dynamic retention is still required, not complete.
   The fixture now also qualifies separate code-only/service roots, unchanged
   exact census after configuration exists, and same-object read-only code views.
   A byte/mode-identical copied catalog is refused in an actual private ARMv5
   view. These observation descriptors close before launch; this does not
   complete a race-qualified constructor or live input ownership.
   The next QEMU-only composition now retains that closure across actual Samba
   execution, normal stop, live mode drift and forced stop of a frozen group.
   Caller closure, actual executed-object identity, permanent review after mode
   restoration, retained references and explicit verified release all pass.
   Generic static/non-root admission is unchanged. This closes the disposable
   code-lifetime tracer, not trusted product manifest/construction or the config,
   identity, state and storage authority requirements in steps2/3 below.
   Fix the expected closure/ABI and trusted manifest source, not self-measured
   dependency candidates. Qualify same-byte file/directory/alias replacement,
   caller closure, constructor failure and cancellation before launch.
2. Bind protected bounded configuration/NSS inputs, identity-authority passdb
   revision and descriptor-bound storage grants at construction. Mutable Samba
   state has an explicit protected roster and legitimate-mutation contract,
   separate from immutable code/configuration. No per-call backend/path changes,
   automatic account creation, mount/import or product listener.
   The guarded Samba fixture now qualifies the immutable configuration part:
   seven independently expected config/NSS files are retained with exact census,
   hashes and original identities through actual child execution. Config views
   are read-only/nosuid/nodev/noexec, separate from executable code and writable
   state. Caller closure, live mode drift/stop, retained review, restoration
   refusal and verified release pass locally on ARMv5. The regression also
   qualifies recomposition of config after the nonrecursive service-root bind.
   This does not qualify a product renderer/identity revision, mutable passdb,
   state ownership or descriptor-bound storage; those are still the next inputs.
   The existing Plan now also derives bounded, granted-only native NSS
   candidates under the identity/mounted-roster locks, with independent Unix
   parsing, exact UID/GID-census refusal, private groups, desired-state drift
   and unchanged journal/passdb identity checks in a disposable ARMv5 fixture.
   These documents are not installed in the daemon. The internal identity
   consumer now re-observes the exact expected fingerprint, retains Owner
   authority across caller work and refuses Owner close until explicit release.
   Drift/uncertain admitted observation is sticky review; credential changes
   and revocation remain available. Local native lifetime/mutation/copy/race
   tests pass. The actual ARMv5 credential fixture also qualifies unchanged
   evidence, busy Owner close, real disable/new-login denial, re-enable without
   review revival, stale acquisition and release without identity mutation.
   Complete API overlay smoke and separate two-boot tests pass; the probe
   launches no descendant and is not the daemon's service Owner.
   Next compose that token into actual same-object NSS/passdb/state/storage handoff;
   do not replace that requirement with another candidate/snapshot check.
   A separate native enrollment lookup now breaks the bootstrap dependency:
   confirmed desired-disabled Unix identities can produce lookup-only documents
   before passdb enrollment, without loosening the enabled-service Plan. The
   non-recovering Owner reader and bounded renderer run under the identity lock;
   cancelled/incomplete/drift/review inputs refuse atomically, credential backends
   are not queried and JSON is blocked. Native tagged vet/race, host preflight,
   actual ARMv5 API overlay smoke and the separate two-boot state suite pass.
   Missing/duplicate/altered lookup evidence is refused. The same frozen source
   also passes complete cached local integration on `fa4f25a`, including every
   later Samba/SMART lane; all 862 packaged API files, the embedded/installed/
   exported API and seven artifact hashes independently agree. Hosted and
   independent clean-build qualification remain separate; the documents are
   not installed in a daemon or qualified through native libc.
   The separate fixed campaign now also qualifies actual ARMv5 libc consumption
   of two real Owner-created private identities, in a new read-only tmpfs root
   with private mount/network namespaces, nobody/zero capabilities and no
   shadow/state/data grants. Actual changed-UID, extra supplementary-group and
   foreign-user documents refuse; a fresh restored lookup passes. Owner state
   remains unchanged and every capture verifies group absence. All 29 Linux
   driver tests, tagged vet and focused ARMv5 old/new Samba gates pass locally.
   This is not retained identity/configuration authority or daemon installation;
   its test-only source increment is not included in the earlier full image.
   The independent native tracer now derives an exact three-file protected
   configuration plan from the opaque Owner candidate, retains original
   descriptors during actual libc lookup, closes temporary callers before
   execution and verifies group absence before release. A real mode change
   refuses; restoring permissions does not match the admitted generation.
   Final actual ARMv5, all 30 Linux driver tests/lint and focused native race
   repetitions pass with unchanged base and no descriptor leak. This is not
   a retained identity lease, sticky service review or descriptor-bound product
   root construction; the fixed guest-only writable fault anchor is not a
   product shortcut. A fixed read-only QEMU worker now receives four duplicated
   original configuration objects (root plus three files), with role/parent
   checks and late mount/metadata/byte fencing. Its bootstrap clones originals
   before namespace change, poisons the source pathname and attaches the same
   objects; the actual libc probe verifies escape FDs are absent after exec.
   Seven admission refusals preserve callers/FD counts, and late mode drift
   refuses before launch with capture review surviving restoration. All 31
   driver tests and old/new ARMv5 gates pass within the same guest budget.
   This is read-only worker handoff, not retained identity/service authority,
   descriptor-bound product code/root construction or credential backend.
   A separate credential-only QEMU composition now fixes its backend at
   `identityowner.OpenWithSMBBackend` and retains the complete code roster,
   independently expected native configuration and original writable state.
   Twelve-object worker handoff masks both source paths, attaches original
   objects and closes inherited escape FDs. Actual two-account disabled-first,
   sealed-stdin password and separate enable cycles preserve each SID; verified
   settlement/close restores the initial FD count. All 33 driver tests and older
   ARMv5 gates pass within unchanged 60/180-second fixture/guest budgets. Complete
   checks bracket each worker; duplicate pre-admission hashing is eliminated,
   not replaced by cached launch authorization. This is not a daemon, continuous
   identity lease or durable product quarantine/recovery. The factory/fixture
   remain trusted test-only composition; product ownership is not established.
   The same runtime also passes complete cached local integration on `8b1f9ec`,
   including every later lane; all 874 packaged/source-archive API files,
   installed/embedded/exported API bytes and seven artifact hashes agree.
   This does not qualify independent clean builds, release licensing or EX4
   operation, and does not close any of the following composition gates.
   A newer QEMU-only native daemon now uses the SAME retained code/config/state
   as those Owner-enrolled credential workers. Actual two-account authentication,
   wrong-password denial, all114 original code views, restricted root/caps,
   verified group stop/reap and no-FD-leak pass in the official local wrapper:
   all35 driver/seven loader tests, both complete campaigns, base unchanged.
   This does not borrow the earlier fixture's revocation or identity lease.
   Next qualify live-session revocation in this restricted profile, continuous
   identity/storage authority and protected product construction. Session-control
   workers need an explicitly qualified PID-generation/revocation boundary;
   do not grant an unrestricted `/proc` or infer session absence from exit0.
   The same frozen runtime passes complete cached local integration on8cb0b86:
   all877 packaged/archive API sources, installed/embedded/exported API bytes
   and seven artifact hashes agree. Every later guest lane also passes. Own
   hosted/independent clean-build qualification remains pending; this is not
   product construction or physical EX4 evidence.
   The next local tracer now passes Owner-bound **idle** disable against that
   same daemon: same-SID disabled journal, two complete stable-absence
   inventories, refused new login and unaffected second-account login. All36
   driver/seven loader tests, both actual ARMv5 campaigns and focused native
   race-count3 pass. Single-use start/check/stop avoids recursive runtime gates;
   complete code/config/state and live daemon checks bracket workers once each,
   without increasing status/revocation budgets or granting `/proc`.
   This newer tracer has no deliberately open session and is not included in
   the earlier full image. Next hold two fixed actual client sessions under
   owned groups; require complete qualified-generation observations before
   dispatch, one target-only logoff, target absence and continued peer access,
   failed fresh target login, uncertainty/no-retry refusal and verified whole
   client/daemon teardown. Do not infer live revocation from an empty inventory.
   This active-session tracer now passes the official local ARMv5 wrapper:
   all37 driver/seven loader tests and both campaigns, two complete qualified
   session records before dispatch, one Owner-bound target-only logoff, two
   complete absence observations and the SAME peer session/server generation.
   Fresh target login is denied; peer login, whole-group stop/reap, final FD
   equality and unchanged base are mandatory. The backend-bound private witness
   rejects JSON and host/race-count3 tests refuse partial, foreign or replaced
   evidence. Native fixture status/revocation budgets are fixed4/10 seconds;
   ordinary adapter2/5 is unchanged. Separate startup20/idle20/session45 phases
   avoid sharing an already-consumed deadline; enrollment60/guest180 remain.
   No guard or privilege is relaxed. Frozen57ee527 now also passes complete
   cached local integration, including all later guest lanes; all880 API
   source/package/regular archive files, installed/image/exported API bytes and
   seven payload hashes agree. Own hosted and independent clean-build/release
   qualification remain separate. Next qualify continuous identity/storage
   authority and protected product construction. An additional internal
   `RetainSMBFileServiceSnapshot` now retains only the exact pointer adapter
   fixed at Owner startup; foreign adapters refuse even with identical evidence.
   Root/race tests and an actual ARMv5 native-backend read-only probe qualify
   lifetime, close refusal and unchanged release before daemon startup. Generic
   snapshot leases still assert no SMB binding, and the new token is not a
   continuously composed runtime handoff: their full evidence includes mutable
   Samba journals, and Verify calls passdb under the Owner lock. Never recurse
   into that lease from a worker/runtime gate or silently refresh its review.
   A confirmed account transition needs an explicitly qualified successor/fence;
   unknown drift, wrong Owner/backend, uncertain stop or partial evidence refuse.
   The separate internal `SMB(id).DisableForFileService` now qualifies only an
   explicit single-account disable under the Owner lock: complete before/after
   evidence must preserve every other journal/identity/passdb row and all census
   reservations. It atomically transfers the existing bounded slot to a NEW
   token, never refreshes the old token, and keeps review/retention on uncertainty
   without retry. Root tests cover capacity16, concurrent Close, census drift,
   wrong/stale/unbound tokens and cancellation after intent. Actual ARMv5
   qualifies the SAME peer session and successor retained until verified whole
   stop. Preparation20 is distinct from live45; enrollment60/guest180 remain.
   A combined45-second attempt expired at login verification, while an
   instrumentation-only control passed; this is not a deterministic timing or
   older hosted-census fix. No admission or privilege is relaxed.
   This fixture acquires AFTER daemon startup; do not mark the complete Owner
   done. Next packet, still host/disposable QEMU only:

   Complete cached local integration of `cd9b2a5` passes the full existing lane,
   including both ARMv5 Samba campaigns and synthetic SMART replay/capture.
   Independent source/package/archive comparison covers all 883 tracked API
   files; installed/image/exported API and seven artifact hashes agree. This
   does not qualify clean reproducibility, release licensing or physical EX4.

   Teardown prerequisite: `identityowner.Close` now closes its fixed backend
   before releasing stores. Root-isolated real-lock regression proves retained
   root/registry/native/Samba authority after a modeled external close error,
   sticky redacted review and no retry. Normal teardown retains the journal
   during backend close and is idempotent. Qualify failed-Open cleanup and
   low-level close faults separately; process exit is not product recovery.

   The first `NativeIdentityServiceQEMU` normal-lifecycle trace now passes:
   complete startup eligibility brackets exact-backend identity retention;
   identity verification brackets actual daemon start; one exclusive timed
   supervisor serializes complete scans and stops on accepted cancellation.
   Atomic redacted status stays readable but grants no authority. Full runtime
   closure precedes identity release, and uncertainty keeps review without retry.
   Actual ARMv5 proves pre-/post-start close fences, canceled/duplicate refusals,
   manual/timed scans, competing-observation refusal, accepted cancellation,
   retention after stop, closure-before-release and final FD equality. Both
   campaigns/40-driver/seven-loader/all old guards pass. This is NORMAL ONLY;
   do not borrow the static Owner's fault qualification for this coordinator.

   A subsequent actual ARMv5 trace now qualifies one state-directory alias
   replacement on guest tmpfs. Valid original descriptors survive capture
   construction; complete admission refuses before the worker runs. Independent
   read-only witnesses prove owned daemon/client stop and an unconsumed pending
   capture, while code/config/state and busy identity authority stay retained.
   Restoration and repeated Close do not revive it. Child process exit after
   those witnesses is fixture disposal, not recovery; clients were not active
   in this fault trace. Mode drift refuses earlier and is not that pending branch.
   The final 42-driver/seven-loader lane uses one compilation/base and three
   fresh service/native/lifecycle guests, each180, with all old guards and equal
   code census. Cached full/hosted/clean/hardware qualification remains separate;
   the remaining fault variants, product command and storage gates below stay open.

   Explicit target-only `Disable` is now routed through this retained
   coordinator's gate and SAME Owner/backend. Actual ARMv5 proves two held
   sessions, qualified stale/canceled refusal, the verified atomic successor,
   SAME peer session/generation, target-login denial, Owner Close refusal,
   serialized mutation and retention until complete closure. All42/seven tests
   and three campaigns pass with original guards/guest180. Added live45 and
   post-observation20 phases are independently bounded; no new guest/privilege
   or automatic retry is introduced. Whole-image/hosted/clean qualification
   and broader faults remain separate.

   - Construct against one startup-fixed runtime/backend, retain identity BEFORE
     any descendant starts, and refuse a foreign runtime even with equal bytes.
   - Serialize external coordination without Owner/runtime gate recursion;
     observe complete identity/code/config/state under bounded supervision.
     Unapproved identity changes and uncertain observations must stop, preserve
     review and never automatically restart or mint a replacement lease.
   - Qualify drift/exit/cancellation and partial/uncertain stop/close. Current
     pins must remain held until whole descendant stop and closure are verified;
     a repeated nil Close is not proof that an earlier uncertain close recovered.
     Use disposable subprocesses for deliberately quarantined references; verify
     actual whole-group stop independently before those subprocesses exit.
     Test unexpected Unix/passdb changes, same-bytes configuration/state
     replacement and mode drift, a real daemon exit, cancellation inside a
     retained worker, pending-capture uncertainty and failed closure. Require
     sticky review, no restart/lease replacement, busy identity Close and no
     repeated uncertain teardown. Restore inputs only to prove non-revival;
     restoration is not recovery. Never release/force-close a private FD merely
     to make a fixture's descriptor census pass.
   - Preserve the locally qualified explicit target-only Disable and verified
     successor under coordinator serialization. Do not accept a caller-selected
     backend/runtime or refresh a stale token. Extend native fault proofs for
     uncertain intent/transition and simultaneous cancellation. Product
     supervision needs a
     separately qualified command/coordinator contract; the initial exclusive
     loop intentionally refuses concurrent operations and supplies no HTTP API.
   - Compose the trusted retained-storage roster and descriptor-bound grants
     with the SAME service Owner, including real effective-access/refusal cases.
   - Only then wire product authorization/startup and user management; keep
     HTTP/service activation, real disks and durable recovery as separate gates.

   It does not
   establish data-handle semantics or qualify hardware/migration/recovery.
   Never bootstrap by
   fabricating enabled journals/SIDs, copying TDBs or
   passing enrollment lookup as active-service evidence. Closing/reopening an
   identity Owner is new admission, not continuous retained authority.
   The guarded Samba Owner now also retains its original writable tmpfs state
   root and six fixed root-only role directories. Actual ARMv5 verifies matching
   child objects and writable/nosuid/nodev/noexec views; normal TDB/log changes
   are allowed, live directory-mode drift stops the group, review survives
   restoration and verified teardown releases code/config/state together.
   Native tests cover same-mode replacement, real kernel ACLs and incomplete/
   unprotected directories. This is not a passdb-file or persistent-state
   authority. The guarded state-source handoff now retains seven read-only FDs,
   clones their mounts before namespace isolation and attaches them inside the
   private child. Actual ARMv5 masks the old source pathname, verifies real SMB
   readiness/same objects/protected writable views, checks input-FD closure
   before exec and steady-state counts after normal/config/state stop cases.
   The failed cross-namespace legacy bind is not a pass; no source-path fallback
   or generic extra-input API is added. Actual ARMv5 now also qualifies five
   late-input constructor refusals with partial-pin cleanup, closure of every
   temporary caller input, copied argv/credentials and forced-stop state review
   with retained code/config/state and explicit verified release. The parent
   constructor refuses repeated objects/mixed filesystems before publication;
   no generic launch option or new privilege is added. Next attach the SAME
   actual identity authority/NSS/passdb and
   storage leases. A first fixed observation worker now runs actual ARMv5
   `pdbedit` against the daemon's same retained state-directory objects inside
   the restricted root, despite masking the source pathname. It accepts empty
   regular stdin only, checks duplicate late-input refusal and caller closure,
   keeps bounded listing bytes private and verifies single-use/group absence/
   release with no FD leak. Its mandatory evidence passes with all old guards;
   the closure adds only that fixed tool. This synthetic-account tracer is not
   real Owner enrollment/revocation or a complete credential backend. Next bind
   the existing identity Owner and Owner-derived NSS to this actual state view,
   then qualify credential changes and revoke against the running daemon;
   no passdb copy, unrelated token or arbitrary tool/argv injection.
   This worker increment's own combined source `c4ed376` also passes complete
   cached local Buildroot/QEMU integration, including the new mandatory worker
   evidence, all prior Samba gates and final SMART lanes. All 857 tracked API
   files independently match compiled and collected source; image/installed/
   exported API and seven distinct expected artifact hashes agree. This does
   not borrow ancestor qualification or establish clean/hosted/product/EX4 proof.
   A subsequent fixture-only ARMv5 campaign also qualifies worker cancellation
   before admission, late protected-directory mode loss before launch, sticky
   review after restoration, complete input retention and verified leak-free
   release. Native tagged vet/race-count3 and strict evidence checks pass. No
   production API changes; focused qualification does not replace a new full
   packet or clean/hosted validation. Same real Owner/NSS/state/storage remains
   the next composition requirement, not another synthetic account authority.
   Whole-root/code/config/data construction, durable review and
   product lifecycle/HTTP remain open.
   The complete combined source on336c29f now also passes ONE cached full local
   Buildroot/QEMU integration, with independently verified seven exported
   hashes, embedded/installed/exported API and all853 compiled/archive source
   files. Hosted checks must still qualify their own exact PR head; no clean
   reproduction, product authority, release compliance or EX4 gate is inferred.
   The combined descriptor-handoff/admission/forced-stop source `303adae` also
   passes complete cached local integration with all 854 independently matched
   compiled/archive files, matching image API and seven hashes. This is the
   packet's own full result, not inherited ancestor qualification. Hosted checks
   must qualify their own exact PR head; product and hardware gates remain open.
   The fixture now requires the already-supported virtual entropy provider,
   backed by host kernel randomness rather than a fixed seed. This removes the
   measured initial enrollment wait without extending its180-second deadline;
   missing-provider execution fails before staging/authentication. A previous
   complete local timeout stays failed. Renewed complete cached local
   integration on `faf1c88` passes all old/new guest lanes and independently
   verifies embedded API and collected source contents. It does not substitute
   for this increment's own clean CI or qualify product activation/hardware.
3. Integrate serial revalidation and lifecycle supervision: drift/source loss or
   unexpected exit stops the known group before any input release; uncertain or
   forced stop retains authorities in review. Test restoration/no-restart,
   incomplete cleanup, repeated Close and complete-group absence, not just PID
   exit. Only afterward compose durable activation/recovery and authenticated
   web management with the production storage/identity Owners.

The packets below retain earlier dependency context, not current PR status.
See [current gaps and acceptance sequence](IMPLEMENTATION-STATUS.md#next-implementation-sequence).

1. **M0.1:** exact-head integration of router/race correction and Samba
   boundary characterization is complete in merged PR #40. Continue tracking
   the unrelated intermittent two-boot QEMU state-volume `EBUSY` issue; a
   passing run does not prove its cause or resolution.
2. **M3.1b:** finish trusted discovery without adding a public storage-selection
   API or automatic mount/import. PR #41 adds duplicate valid SCSI VPD serial/NAA
   WWN reporting, redaction, schema-v2 partition-parent topology, metadata and
   generation rechecks, and the fixed-path opener/source-set primitives. Its
   exact-head host and ARMv5 QEMU checks pass. PR #42 now includes a fixed,
   requestless,
   peer-authenticated broker service; API remains non-root, and the broker
   accepts no caller paths, names, commands or partial selections, owns/closes
   descriptors and returns only bounded, redacted observations. QEMU
   SysV/mdev setup grants only `0440` to whole-disk nodes `sd[a-g]` for its six
   eligible fixture disks plus the mounted root device; the separate
   provisional udev rule covers `sd[a-d]`. The
   broker requires `no_new_privs`, has no effective/permitted/inheritable
   capabilities and no supplementary groups beyond the read-only device group.
   `support/test-api.ps1` passes, including host tests, `go vet` and ARMv5
   cross-compilation. Exact-head host workflow `36364383665` and ARMv5 QEMU
   workflow `36364383677` passed on `7254555`; PR #42 was merged to `develop` as
   `059fa24`. The QEMU smoke verifies API/broker separation, whole-disk `0440`
   permissions and hotplug recheck, and emits only redacted ambiguity status.
   This is fixture evidence only: the broker observes its own mount namespace,
   does not read disk content, and this does not prove global consumer
   exclusivity or authorize probing, mounting, import or mutation. Keep
   production init, EX4 SATA/device naming, bay mapping, stable identity and
   compatibility explicitly unresolved.
3. **M3.3 / M8.1:** Keep image inspection offline and generic until exact WD
   layouts have attributable evidence. The host toolkit now compares raw MD
   v1.0 component sets; the focused ARMv5 QEMU fixture exercises that command
   with two mdadm-authored 32 MiB tmpfs components and requires checksum,
   identity and complete-role agreement. Host tests, vet and the focused QEMU
   wrapper pass locally; the wrapper reuses existing caches and creates no
   persistent container or volume. The result still says
   `wd_compatibility=unqualified` and grants no mount/import authority. Next,
   build a sanitized, versioned corpus for actual EX4 data-volume layouts by
   reconciling stock firmware parsing logic with a separately approved,
   read-only data-volume observation when expendable media is available. Never
   infer an allowlist from synthetic or unrelated-model samples. Then define
   persistent logical volume identity separately from bay location and specify
   safe adoption/recovery semantics; mounting remains gated on those proofs.
4. **M2.4 / M2.5:** M2.4's trusted backend is bound once to `identityowner.Owner`;
   enrollment and explicit enable/disable use that backend, and invalid/missing
   Samba configuration is rejected before Owner state creation. PRs #47 and #48
   are merged to `develop`; host checks and exact-tree ARMv5 QEMU checks pass.
   The earlier PID-only characterization and Buildroot `--without-json`
   limitation are historical. Local Buildroot enables Jansson JSON without
   AD-DC; the account-scoped logoff is sent at most once and complete session
   inventories verify target absence, while a stale-generation control is
   ignored. The fixture confirms active target sessions are revoked, new
   authentication is denied and a same-IP peer remains usable. Host/race/fuzz
   tests plus full local ARMv5 QEMU and two-boot checks passed on 2026-09-29.
   Product startup/config, HTTP authorization, review/recovery UX, open-handle
   and durable-reconnect semantics remain unqualified; no HTTP endpoint exists
   and enable is never automatic. Disabling may interrupt active transfers.
5. **M1.3 / M5 follow-on:** only after the owner/revocation contract is stable,
   connect the internal credential channel to a production-owned listener and
   explicitly authorized operator workflow. Add review reconciliation around
   qualified primitives; preserve uncertainty and never persist or replay secrets.
6. **M4.1:** identity and storage evidence now compose in local QEMU through a
   lock-coherent fixed-roster collector and non-serializable planner adapter.
   Next, derive the production roster from complete M3.3 discovery plus an
   evidence-backed layout/compatibility qualifier, persist and supervise the
   M3.4 owners, then add native candidate validation. Do not mark M4.1 done or
   activate services until physical inventory completeness, compatibility,
   storage/identity freshness and transactional configuration replacement are
   owned together.
7. **M5:** expose completed backend outcomes incrementally, with disabled controls
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
