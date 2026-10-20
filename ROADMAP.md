<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation roadmap

Reviewed: **2026-10-17**. This is the product specification and work breakdown,
not a release announcement. The [README](README.md) is the concise entry point;
component contracts remain authoritative for implemented behavior.

The dated [code-to-roadmap comparison](IMPLEMENTATION-STATUS.md) records
implemented evidence, missing product integration, planning estimate bands and
the immediate execution sequence. Estimates are not release qualification.

Current M0 gate: the complete `dedafa6` qualifier passes eight Samba campaigns,
then reaches its unchanged 1,800-second outer limit. File/file-source, the union,
later SMART lanes and the audit remain unqualified. This supersedes the earlier
`0beb01e` seven-campaign/held failure without repairing its intermittent cause.
Focused passing components cannot qualify that failed complete run.
Require causal diagnosis/calibrated fixture decisions, complete qualification
and audit; never replace failed results with selected passes or relax proofs.
See [implementation status](IMPLEMENTATION-STATUS.md) and the
[focused staging contract](support/QEMU-FAST-TESTS.md#smart-report-staging-checked-disposable-image).

## Immediate NFS original-peer compensation packet

The opt-in `source-owner-daemon-loss` ARMv5 reproducer currently detects the
original mountd exit through scheduled supervision, then fails stopped proof.
The existing five code/source/policy-loss/combined profiles remain passing;
this new reproducer is not an additional passing capability.

Next acceptance work, before claiming independent-daemon compensation:

1. Keep the original Owner/backend/join/runtime lifetime; admit at most one
   bounded compensation after review without granting normal service authority.
2. Withdraw owned exports and stop original NFSD/daemons using retained controls,
   code, state and namespace references. A missing daemon must not prevent
   settlement of remaining peers; do not reopen data by path or retry effects.
3. Preserve original detection and stop errors. A reviewed Stop is not normal
   success; independently verify original process wait/group absence, empty
   export state, NFSD controls and fixed listener absence before reporting stop.
4. Keep reviewed authority and original references; refuse restart/release and
   test those refusals without changing generic process/Owner semantics.
5. Run native/race checks before the explicit ARM test, then regress all existing
   modes under their unchanged budgets. Extend identity/source/channel/state,
   partial-start and uncertain-close coverage separately; no broad fault claim.

This packet adds no HTTP activation, product recovery/restart, physical-disk
operation or hardware qualification. First-release normal/unclean automatic
startup remains the separate required product contract below.

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

The single complete local qualifier for `94e791f` fails final Samba file-source
held-file admission after nine campaigns pass. Zero source-cost checkpoints and
6,717 ms localize the refusal before explicit source-cover injection, not its
inner cause. All 1,513 tracked/1,098 API inputs stay unchanged. Later SMART lanes
and strict post-success audit are not reached; generated artifacts are not a
new complete qualification. Next instrument that bounded first admission and
test the focused path. No timer/proof relaxation, full retry, hosted repair or
merge is inferred; [current gate](IMPLEMENTATION-STATUS.md).

A later local preflight passes file-source but fails fault/data. Fixed
failure-only telemetry now distinguishes the final complete-owner check after
the runtime probe returned nil: `after-runtime`, `verify-owners`, expired data
context. It does not qualify the whole operation or establish a universal cause
for older failures. New full/audit were not started, fixture-budget approval
remains pending and all original numeric/proof/authority limits are retained.

The retained identity lease now also preserves standard caller cancellation/
deadline classification at both admitted observation/derivation boundaries,
alongside unchanged sticky review. Four deterministic root-native RED/GREEN
cases, race3 and12 actual ARMv5 cases in the existing Owner guest pass; private
causes, automatic retry/revival and input release remain refused. This improves
future diagnosis without attributing or repairing earlier timing failures.
No numeric limit, full/hosted gate or product activation authority changes.

The optional fixed parent-share mount substitution now also passes: binding
the SAME directory at the parent path changes unique mount identity without
changing device/inode/content. Original-root-relative no-symlink metadata
fences reject that replacement before the next READ; verified stop, retained
review/originals, restored-metadata-only observations and retry/Close refusal
pass. Real directory/symlink/missing controls must execute, not skip, in the
pinned ARM guest; unsupported host kernels refuse without an identity fallback.
Eleven focused guests and pinned host/Windows checks pass on exact sources;
five fault kinds have10+136 receipt controls. No timer/fence/privilege widening
or new Docker storage/CI boot. Complete lifetime, request/OFD, uncertain-stop,
full/own-hosted/reliability/hardware/recovery/product gates remain required.

A fixed parent source-leaf substitution case now qualifies refusal after one
matched READ: byte-identical RAM copy is not the original object. Parent-
relative no-follow metadata checks bracket worker observations; next READ
returns zero metadata without advancing sequence, both groups stop, originals
and review remain, and restored metadata cannot allow READ/start/Close. Data/
base and reviewed FD counts remain unchanged. Its four input-fault kinds had
eight positive/109 malformed receipt controls. This is not complete source/
root/device lifetime or original OFD/request authority. Remaining uncertain
stop, SDK/construction, full/exact-head hosted, hardware/recovery/migration and
product gates are unchanged.
A complete clean focused union now passes ten ARMv5 guests plus pinned host
and Windows checks. Earlier healthy deadlines remain an engineering-reliability
gate; twelve new checks measured1.949ms in one guest are not a demonstrated
timing fix. Full/own-hosted/independent reproduction and product qualification
remain mandatory. Original owner fences and deadlines are unchanged.

A fixed optional ARMv5 canceled-collection case now verifies cancellation only
after original queued bytes appear, a joined bounded observer, zero returned
metadata/sequence, verified client/server stop and unconsumed original queue/
references in sticky review. Repeated READ/start/Close refuse with stable FDs
and unchanged data/base. This is collection cancellation, not confirmed client
completion or interruption of server I/O. Uncertain stop, original-source
lifetime, complete SDK/construction/OFD/request authority and all product/
hardware/recovery/migration gates remain.

A fixed optional ARMv5 missing-READ-acknowledgement fixture now verifies zero
metadata/sequence, the original 88-byte record left unconsumed, independently
stopped client/server groups and original references retained in sticky review.
Repeated READ/start/Close refuse with stable reviewed FD counts and unchanged
data/base. Byte count is not authenticated record content or a successful
client completion. Normal client bytes, launchers, privileges and time limits
remain unchanged. Next: uncertain stop, original-source lifetime
and construction/SDK closure, complete S4/S5/S6 and explicit request/OFD
admission before pending-I/O or product activation.

Three fixed optional ARMv5 cases now qualify original module/configuration/
receiver drift between completed READ requests. Each proves zero next frame,
verified client/server stop, complete original retention and repeated
READ/start/Close refusal even after restoration, with stable reviewed FD counts
and unchanged data/base. Restored metadata observation never clears the code
keeper/runtime review. The older negotiation-only drift fixture is reconciled
to that same retention contract, not aggregate healthy-release FD equality.
Next: uncertain stop and construction/SDK closure, then complete S4/S5/S6
and explicit pending-I/O admission. No product activation or hardware gate is
waived by these between-request observations.

An optional ARMv5 worker-exit fixture now qualifies loss between two requests:
one READ is independently matched, the original worker is terminated via a
generation-bound pidfd, the next READ returns a zero frame and both Owners
retain review/original pins after independently verified client/server stop.
Retry/restart/close refuse; data/base stay unchanged. Runtime Close now refuses
review before any disposal, with a real descriptor-effect host regression.
This is partial S5, **not interruption of pending I/O**. The separate input-
drift and missing-acknowledgement cases above add coverage, not complete S5.
Uncertain stop, retained SDK/construction/OFD/request qualification
and the exact regression union remain required.

The optional capture lane now qualifies two actual one-byte READs on the same
authenticated ARMv5 handle. Kernel-credentialled VFS metadata matches every
remote FileId/session/tree/worker/local-object field against independent STATUS
and the retained client tuple. One real O_RDONLY worker descriptor is selected
by a bounded proc census; an O_PATH object pin survives until verified stop.
Client-first dual locks bracket complete inputs, original worker and TCP/
namespace fences around each READ. Explicit CLOSE/data/base/FD equality pass
within unchanged deadlines after removing a duplicate tracer-only sweep.
This is **not an OFD or pending-request lease**. The separate fault cases above
qualify bounded review containment only. Finish SDK/construction/fault coverage
and exact regression union before any
pending-I/O admission or product activation. No physical NAS work is authorized
by these observations.

### Earlier capture prerequisites (historical checkpoints)

Dedicated capture OPEN now also binds and rechecks the original client/worker
processes, four retained namespaces and reciprocal kernel TCP pair in ARMv5.
Complete client/runtime/STATUS fences are serialized under fixed client-first
lock order, with no replacement peer on recheck. Explicit CLOSE, verified server
stop, data/base/FD equality and strict host/ARM regressions pass. Next, retain
the original worker data-FD and consume bounded VFS records to compare remote
FileIds with independent STATUS/local-object evidence; no READ/frame/request
authority or product activation is claimed by the current observation lane.

The capture OPEN lane now also qualifies two independent STATUS observations
on the original retained worker generation/executable/group/endpoint and local
file view; session/tree match the original client handle. Its fixed STATUS-only
bootstrap reuses the unchanged native twelve-input boundary and complete input
fences. Actual ARM, data/FD/base equality, host checks and original runtime
regression pass. Next, retain/recheck original process namespaces and reciprocal
TCP, then consume bounded VFS records to match remote FileIds to the local object.
No worker data-FD pin, READ/frame/request authority or product activation is
claimed; full/hosted/recovery and complete fault gates remain mandatory.

The optional capture OPEN lane now authenticates the original ARMv5 client,
opens synthetic data O_RDONLY and explicitly closes the same handle through
real Samba. Complete original client/bootstrap inputs remain revalidated and
retained until verified client/server stop; unchanged data and FD equality
pass. No READ/frame or independent original-worker lease is claimed. Next,
qualify the original worker generation and its FileId/local-object/transport
relationship before consuming bounded read samples. Full/hosted/product and
physical EX4 gates remain independent.

The capture module and dedicated account-bootstrap are now independently
declared/retained in a fixed private runtime profile. Actual ARM smbd/NEGOTIATE,
stop-before-release, existing synthetic passdb refusal without mutation, sticky
review/reference retention and FD equality pass; the original runtime also
passes. This runtime-only lane is partial S2 input composition, not frames.
The dedicated fixed client process adapter now passes host and ARM parser/
lifecycle-refusal tests, plus scoped host race checks; the newer OPEN lane above
also composes its complete retained root/bootstrap census with the authenticated
daemon. Next, qualify original worker/FileId/local-object/transport
matching and actual read/close/fault outcomes.

A dedicated fixed read-only capture client now passes host mock orchestration
(three positive flows, 121 refusals) and ARMv5 ELF compilation; authenticated
OPEN/CLOSE is now exercised by the separate guest above. It permits at most
two reads on one original handle and
imports no mutation accessor. The old close-only variant remains unchanged.
This is an integration prerequisite, not a completed client/worker bridge.
Next, retain independently expected client/module/bootstrap closures and prove
the actual authenticated OPEN, original worker/channel and remote/local match.

The optional dedicated VFS capture fixture now implements bounded synchronous
and asynchronous read sampling with two ordered nonblocking records and sticky
failure, without retaining FSA pointers in completion callbacks. Twenty actual
ARMv5 cases use real Samba registry/tevent/kernel sockets but synthetic opens
and a thin local-pread backend; data/FD equality and two-positive/30-malformed
receipt controls pass. This advances partial S1/S3 only. Next, include the
capture module/complete input closure in the retained daemon runtime, confirm
the original client's wire OPEN before two sequential reads, and join every
record to the same original worker, remote FileId and local object. No active
SMB worker, product activation, WRITE, full SDK or full/hosted qualification is
claimed by this fixture. Existing loader CONNECT refusal and launchers remain.

An earlier component-only follow-up passes host checks and all seven fresh ARMv5
Samba overlay guests. One authorized original IPC$ session remains under the
SAME planned service's exclusive supervision. Source-alias loss stops client
and daemon, retaining reviewed identity/storage/runtime despite restoration
or repeated Close. Older observers refuse the extra group. This is not a new
complete image or normal full-close/in-flight/durable-handle qualification.
The separate OpenSSL PR's earlier own QEMU run fails native account Enable at
the cumulative 60-second fixture deadline; its earlier source-child failure
is a separate historical observation.
That dated failure is not waived by a local result; new-head hosted checks
remain required before integration.

The newer focused `file` guest qualifies one actual original data opening:
the same composed service retains/matches its original O_PATH object and exact
session/tree/server/open identity through a complete exclusive supervised scan,
verified cancellation group stop and full runtime Close before release. It is
the ninth campaign at the fully audited checkpoint. The newer `file-source`
guest adds original-open-file source-alias loss as the mandatory tenth campaign;
all ten actual ARMv5 overlay guests pass with independent saved-log/source-witness
replay. Verified client/daemon stop retains the original file, 15 inputs and both
authorities in sticky review despite restoration/repeated Close. Frozen
`382004a` additionally passes complete cached integration and a separate exact
full-image/source/archive/SBOM audit. Own-head hosted qualification remains required.
The fixed exit fault runs within the same exclusive supervisor, correcting a
controlled fixture alias race without retry or relaxed proof/deadlines. In-flight
faults, durable reconnect and recovery remain open.

The latest fully audited local checkpoint `3ccc2df` selects Go 1.26.8 and host OpenSSL
3.5.9 and passes the
complete cached Buildroot/host/ARMv5 lane: all ten independently enrolled
Samba scenarios and both synthetic SMART lanes. Independent post-terminal
auditing matches all 1,026 API inputs to compiled package/source archive and all
1,370 tracked build witnesses, with 25,468 unchanged audit rereads. Configured
stripping, installed/image/exported
API, seven hashes, Linux AND headers 6.18.55, actual selected/installed Go SDK,
SBOM, release and legal sources agree. The OpenSSL recipe/four patches/original
and legal source/license/SBOM match; its three installed objects reproduce built
bytes after configured RPATH normalization. Actual Buildroot Python passes
mapped-library/version/certificate/private TLS 1.3 checks; see
[exact qualification](IMPLEMENTATION-STATUS.md#current-combined-local-qualification).

This combined checkpoint includes the desired SMB/NFS backup/reviewed-restore
workflow, sanitized snapshot report, supplied-TMPDIR staging fix and the
exact-proof worker-log correction. The original complete
scenario and independent artifact audit pass after that correction, without
changing proof bytes, output caps or deadlines. Seven intact Samba guest logs
also pass independent strict replay with four negative controls each; all ten
are verified by the original full controller and union. No saved-log replay is
claimed for lifecycle/file/file-source; incomplete capture is excluded.
Own-head hosted acceptance, clean reproduction and product/hardware gates remain
open. Do not infer pending-I/O, physical disk failure or installability.

The QEMU lifecycle fixture separates preparation (20 seconds) from revocation
(45 seconds), changing the combined allowance from 45 to 65 seconds. Original worker/service/readiness/stop/
guest limits and authority checks remain intact; this is not a speedup or a
demonstrated causal fix for hosted timeouts.

Disposable fixtures qualify same-authority planned startup/data access,
exclusive serial supervision, cancellation/verified stop, retained originals,
full-close-before-release, idle source-alias loss and original-owned idle exit.
The exit proof requires its retained worker capture to be unconsumed and
settled; reviewed authority is not released or automatically restarted.
Normal held-session retirement and original-open-file cancellation/closure
also pass in separate fresh guests. The newer mandatory file-source campaign
qualifies source-alias loss with that original idle opening, not in-flight
transfer loss or physical disk failure; its complete cached image audit passes.
An unchanged-source CPU-only differential reproduces the cumulative Enable
expiry locally, with a different inner worker boundary; normal-quota full native
qualification passes. This supplies a diagnostic loop, not a causal hosted fix.

The QEMU-only native driver now separates preparation (20 s) from enrollment
(60 s), instead of their shared 60 s allowance: aggregate 80 s, not a throughput improvement. Its
original parent, single-use handoff and uncertain/expired/canceled refusal
remain enforced. Actual-call-site RED/GREEN and typed post-revocation refusal
regressions pass. Low quota completes enrollment but still refuses a later
unchanged live-session 45 s deadline; normal CPU2 native and the complete current lane
pass. Worker/readiness/stop/guest limits and exact proofs are unchanged.
This qualifies the accounting/diagnostic changes, not every hosted failure.

After source restoration, two normal coordinator `Close` attempts are also
refused while the same runtime inputs and both original authorities stay retained.
QEMU-only failure diagnostics accept only fixed redacted labels and cannot satisfy
the exact proof contract; the intermittent failure cause remains unresolved.

This is not held-session/mid-transfer fault coverage, uncertain construction/
teardown, product recovery or production storage/identity composition.
The separate core PR passed its own hosted checks and merged into `develop`;
this OpenSSL update's own hosted promotion, independent clean reproduction, complete advisory
review, hardware, migration, recovery and signed release gates remain open.
Earlier PR #128/#129 checkpoints failed hosted coordinator-continuity checks; local success
is not their causal fix. Keep existing guards and finite budgets. No HTTP
service activation, NAS operation or installable firmware is introduced.
Historical task evidence below retains its original source scope.

Status vocabulary:

- **Implemented / host-tested**: code and deterministic local checks exist.
- **QEMU-tested**: actual ARMv5 guest behavior passed within the documented fixture.
- **Hardware-observed**: a bounded EX4 experiment, not complete support.
- **Product-qualified**: all acceptance, security, recovery and hardware criteria
  for an advertised capability have passed. No milestone has this status yet.
- **Planned**: specification only. A library is not a deployed product service.

| Area | Evidence and limits |
| --- | --- |
| Build/tooling | Pinned Buildroot 2025.02.18 LTS / Linux 6.18.55 LTS; current cached local source/image/SBOM audit and earlier clean CI. Exact-head hosted checks remain required; independent reproducibility was demonstrated for one earlier commit, not every revision. |
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

Use [host wrappers](README.md#fast-checks), the pinned Linux test scripts in
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
  **Complete API host checkpoint:** the `ce31105` code passes the whole Windows
  API/UI wrapper (Go1.27.0, portable packages/selected contracts/cross-compile)
  and pinned Go1.26.8 Linux wrapper (ordinary package suite, QEMU-tagged vet and
  selected proc diagnostic, non-root). This is not complete race/root lifecycle,
  full image/SBOM/hosted or release qualification.
  **M0.1a — bounded host startup and settlement:** current cached timeout1800/
  kill-after30 begins inside the container and cannot bound Docker creation or
  host CLI stalls. Capture each invocation's exact client/container association;
  bound startup and metadata queries separately from active validation. Timeout,
  missing reply or client termination must retain uncertain source/job evidence,
  never imply that its container stopped. Stop only a proven owned disposable
  target, verify retirement before source cleanup, and never automatically retry,
  restart the daemon, prune resources or touch unrelated workloads. Preserve
  all existing active budgets/proofs, image/volume reuse and headroom guards.
  Test delayed/no creation, created-not-running, late replies, query timeout,
  uncertain stop/cleanup and healthy actual lifecycle before default adoption.
  An explicit opt-in [host guard](support/CACHED-QEMU-HOST-GUARD.md) now implements
  bounded metadata/startup/active waits, original-client settlement, exact owned
  cleanup and retained uncertainty. Nineteen local fake-process cases plus
  mocked PowerShell delegation/default-profile checks pass. No actual Docker
  lifecycle is inferred from the reproduced/fixed auto-remove/client-exit race.
  No external daemon-stall repair is claimed; default adoption and
  late-daemon/unsettled-client/host-cancellation qualification remain open.
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
  changes use QEMU; board changes use the relevant current probe. Host toolkit
  CI selects and verifies the exact compiler from `GO_VERSION` in
  `versions.env`, independently of module minimums; pin-only push/PR changes
  trigger host checks. Local selector execution and path contracts pass;
  exact-head hosted verification remains a separate gate.
  Windows host iteration has a no-Docker preflight and an optional Linux/amd64 test runner
  that reuses only an already-present read-only Buildroot cache; it must not
  pull/build an image or create a volume. Preserve isolation, exact-source
  hashes and clean-build/reproducibility lanes. Cache hits are an optimization,
  never qualification evidence.
  The local API overlay's explicit `-IncludeStateReboot` selection now reuses
  the existing seed/verify two-kernel harness after the normal smoke, in one
  bounded container. Default CI/mode and360s container/240s smoke/60s-per-state-boot
  limits remain unchanged. Actual three-boot success qualifies clean policy/
  credential retention and existing Samba access, not automatic NFS/iSCSI
  activation, unclean recovery, complete firmware or physical power loss.
  Keep command-boundary isolation/no-retry controls for both selections.
  Cached-full INT/TERM diagnostics now preserve an active Samba log prefix
  (1 MiB artifact/16 KiB console) before tmpfs cleanup. Only the caller declaring
  the existing bounded group timeout defers controller exit until foreground
  cleanup; no timer or proof is relaxed. Actual-driver host controls and a real
  Docker PID1 timeout with stub guest commands pass. This is not an ARM/full-run
  qualification, repair of intermittency or guaranteed SIGKILL/durable logging.
  **Failed-start test precondition corrected:** a real owned child with held
  output-copy completion reproduces kernel-group absence while original Wait is
  still pending. Retain PID/review until both are observed; the older assertion
  now explicitly awaits the SAME original Wait before demanding PID release.
  Separate test-only observation is bounded at2s, without signals/stop retries
  or product-timeout changes. Selected full native/race3/58controls and existing
  static ARMv5 guest pass, including3runs each of both cases. Exact historical
  scheduling cause remains unproven; this is not a complete-image repair.
  **Approved coherent revocation packet, host/QEMU only:** one fresh complete
  original-backend session inventory now proves simultaneous original-peer
  continuity and original-target absence instead of adjacent status workers.
  Native units/vet/race3/80controls pass; earlier ARM native fails earlier in
  Disable's4s status post-admission, with25.94s still left in the live phase.
  That observer is not reached in the failed checkpoint. The subsequent source
  adds guarded QEMU-only capture partition/direct-child CPU diagnostics; four
  selected package units/vet/race3 and58/80controls pass, then focused native ARM
  and independent replay pass with all original proof/caps. Coherent observation
  finishes32223ms of45000;48cost rows include8status captures377--528ms.
  No causal repair of historical intermittency is established. Keep earlier
  failure, CPU scope and individually rounded metrics explicit; no unchanged
  retry, wider worker/parent allowance or complete-image qualification follows.
  Earlier ordinary-native45019ms failure and full-image timeout remain
  failed historical evidence. No cache/lease, retry, continuous guarantee, HTTP,
  privileges or timer changes implied.
  - Keep the original opaque pair/backend binding and current decoder/limits.
    Refuse missing/extra/ambiguous sessions, changed peer/generation, wrong backend,
    incomplete/invalid output, expired/canceled or late-nil completion. Do not turn
    an incomplete observation into the exact changed-pair sentinel.
  - Test both properties on the SAME complete point-in-time inventory. An
    observation is not a retained session, continuous guarantee or activation
    authority. Preserve standalone readers until their consumers are audited.
  - First host tests, then the existing native guest at original45+15, work/worker/
    settlement/guest bounds and exact campaign proof. Replay the original failed
    guest as a mandatory negative. Full host race, full image/audit and hosted
    qualification remain separate gates; do not select retries as proof.
  **Earlier completed native timing contract:** coordinated fixture-only budget design is
  approved and implemented: ordinary-native work300s, one fixed settlement
  deadline at original work deadline+30s, host360s including30s boot/final
  margin. Other guests retain180s. Nine sequential phase caps still total255s;
  native4s status/20s revocation and generic2/5s worker limits remain unchanged.
  Maxima are not minimum runtime, and an outer extension does not repair child
  expiry. Earlier hash/allocation/applet/scratch/PGO measurements do not supply
  a new end-to-end optimization to adopt. The
  [timing-contract work packet](support/QEMU-FAST-TESTS.md#native-timing-contract-decision-gate)
  specifies complete hierarchy/cleanup reserves, actual-runner clock tests,
  unchanged proofs/default union, focused-first verification and own-head/full
  integration gates. The focused original trace and complete cached local
  integration now pass, followed by an independent exact1088-source/image/
  SDK/legal/SBOM audit. Own-head hosted checks remain required; historical
  intermittent failures are not declared repaired by these successful runs.
  It supersedes historical suggestions below to repeat
  already completed profiling. No product or generic timeout changes follow.
  Planned fixture phases now preserve their original parent and reject late
  completion or repeated/skipped transitions; fixed child proof also requires
  a live parent. Existing40/20/20 phases,90 child and guest/worker caps remain.
  Deterministic Linux/vet/race3 and distinct ARM data/fault campaigns pass with
  unchanged source/base witnesses. This is orchestration correctness, not a
  hosted timing repair, complete current-image qualification or permission to
  widen the separately pending planned budgets. Synchronous cleanup already
  executing is not made interruptible by context propagation.
  Planned-service caller profiling now distinguishes pre-check/runtime/final
  intervals and the actual inherited entry budget without weakening any check.
  Normal and declared0.85CPU controls pass; a deliberately forced post-success
  diagnostic measures16.637s total/19.998s available, including1.875s pre-check,
  12.876s runtime and1.886s final interval. Its failure is not a real timeout or
  qualified campaign; the temporary injection is removed exactly. The older
  failure remains unreproduced. Do not keep repeating unchanged cohorts/CPU
  sweeps or old hashing work: resolve the pending fixture-budget contract, or
  profile the next genuine failed trace. Current full/hosted gates remain.
  **Current source-loss gate:** earlier `5b90e22` failed final file-source
  quarantine/supervision despite nine accepted campaigns. Instrumented code
  checkpoint `5245ada` now passes the original complete cached lane, all ten
  campaigns/strict union, both SMART lanes and exact 1,472/1,067-input audit.
  This is not a demonstrated intermittency repair or integration waiver;
  independent clean/own hosted/product qualification remain open.
  Bounded failure-only cumulative step costs
  now distinguish held-client setup, observations, first scan and verified
  cover from final settlement. Host vet/unit/race and scoped ARM healthy checks
  pass; failing ARM emission/root cause remain open. Preserve all action limits,
  exact proof and1024-byte output cap. Use this minimized feedback loop before
  another diagnostic retry; neither isolated nor later full success resolves
  intermittency without a causal regression. See the
  [exact complete checkpoint](support/DEPENDENCY-REVIEW.md#current-combined-cached-qualification-2026-10-14).
  [Contract](support/QEMU-FAST-TESTS.md#failure-only-source-fault-checkpoint-costs).
  The local Linux API runner now has an explicit non-root/no-capabilities/no-new-
  privileges profile, four CPUs/2 GiB/256 PIDs/1 GiB disposable tmpfs and a 180s
  Linux-suite timeout with 10s termination grace. It bypasses ownership repair,
  forbids pulls, retains all four existing Go commands and refuses timeout/OOM
  without retries. Windows command-boundary tests cover six refusal cases;
  actual pinned Linux vet/units/tagged vet/proc diagnostic pass under inspected
  cgroup/mount limits. Workflow contracts route wrapper-only changes to cheap
  host checks, not QEMU/B3 rebuilds. This is not ARM, full-image, power-loss,
  general performance or product qualification; Docker preflight connectivity
  is outside the Linux-suite deadline.
  Native session-worker timing now has an explicit fixed profile, rather than
  doubling an aggregate command timeout. A slow-worker host model and controlled
  ARMv5 diagnostic reproduce the final-subdeadline failure. The fixture profile
  covers three complete inventories and one control: each worker remains capped
  at4 seconds, total verification20 seconds including bounded polling/parsing.
  Ordinary commands remain status2/total5; shorter parent deadlines always win,
  unknown profiles refuse before effects, and control is sent at most once.
  A successful status result after its own child deadline must also refuse,
  clear captured output and stop polling even if its parent is still live;
  the non-root regression reproduces this defect before the guard and passes
  after it. The phase-profile checkpoint passes the original ARMv5 union;
  combined-source complete cached integration and independent924-source/package/
  archive/strip/image/seven-artifact comparison now also pass. Own hosted
  qualification remains separate; cache success is not an independent clean build.
  Regression must execute in the ordinary non-root Linux lane, not silently
  skip until late QEMU. Original complete campaigns, full image/source matching
  and own hosted qualification remain required; no physical performance or
  product deadline is inferred from emulator timing.
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
  The 2026-10-08 compound lifecycle replay completed candidate/startup but
  exhausted guest180 before fault. The current one-compile Samba lane separates
  candidate/startup/fault into independently enrolled guests. All six actual
  ARMv5 traces, complete original proof union, equal full censuses and base
  hash pass locally; 61 Linux verifier tests reject missing, duplicate,
  wrong-phase and census-mismatched evidence. No state or authority crosses
  boots, and worker/readiness/stop/guest limits stay unchanged. Candidate's
  separate declaration/prepared-input workloads use two serial30 contexts,
  explicitly replacing shared30; parent cancellation, late-result refusal
  and no continuation/retry after uncertain first work pass fake-clock tests.
  This is fixture orchestration only. New exact-source image/archive audit,
  own-head hosted checks and independent clean qualification remain mandatory;
  do not declare intermittent hosted enrollment or historical EBUSY fixed.
  The lifecycle fixture now separates original held-client preparation20 from
  actual disable/successor/peer/new-login verification45, replacing shared45
  with a combined contextual allowance65. SAME authority crosses the seam;
  uncertain/expired work never continues/retries, shorter parent bounds both,
  and late success refuses. Actual runner virtual-clock RED/GREEN, pinned
  Linux tagged command vet/tests/race3, Windows preflight and one focused
  actual ARMv5 lifecycle pass. Worker/readiness/stop/guest180 limits unchanged.
  An unchanged fresh guest also passes; another fails on an independent worker
  deadline at client preparation. Do not conflate these with hosted continuity
  expiry. New full source/image audit, repeatable-load and own-head hosted
  qualification remain open; this is not a product timing policy or speedup.
  Fixed QEMU-only live-operation/worker-stage telemetry now distinguishes
  shared-phase expiry from an internal worker deadline without logging raw
  output, account names or secrets. Pinned host/race/ARM-cross tests and one
  focused native guest pass; a same-source reduced-CPU control exhausts the
  unchanged45s parent at changed-pair post-admission, while an earlier local
  run expires an internal execution deadline with parent headroom. Latest
  hosted integration fails later at fresh login. These are measured distinct
  boundaries, not a causal fix. Next establish worker-cost/scheduling evidence
  before changing fixture orchestration or refreshing heavy CI; preserve every
  identity/session/admission/stop proof and do not enlarge timeouts blindly.
  After observed shared-budget refusals and explicit operator approval, the
  native-only fixture now separates live continuity/revocation45 from fresh
  authentication15, a combined allowance60 rather than shared45. SAME authority
  crosses this seam; uncertain/late/canceled first work cannot continue, and
  monotonic deadline checks reject exact-boundary late nil results independently
  of timer-goroutine scheduling. Actual-runner virtual-clock RED/GREEN, pinned
  tagged command vet/tests, phase race3, ARMv5 test cross-compilation and Windows
  API/UI preflight and the actual ordinary-profile native ARMv5 guest pass.
  Independent original-log replay refuses five invalid/incomplete proofs.
  Reduced-CPU stress completes both phases and authority closure, then fails
  the unchanged180s guest limit before data/final proof. Do not promote this
  partial result or claim a deadlock/hosted cause. Full default-union/image
  and own-head hosted requalification remain open.
  No per-worker/readiness/stop/guest180 or product limit changes, proof removal,
  retry or activation. First-phase expiry remains a hard refusal, not rescued by
  the authentication budget. This is accounting, not measured acceleration.
  The host refusal path now automatically summarizes only bounded fixed-label
  worker observations, with explicit non-qualifying/partial coverage, missing
  data unavailable, and last reported failure preserved after successful cleanup.
  Malformed/over-bound rows refuse all totals; helper failure cannot change the
  original exit1/verifier/deadlines. Host77 tests/lint/actual shell failure-block
  checks and complete actual ARM failure-log replay pass; no new guest/image
  qualification is claimed. Current CPU-reduced stress fails enrollment before
  the hosted fresh-login gate. A temporary single-variable preemption-off
  experiment does not pass it and is fully removed. Do not adopt that flag,
  claim a root cause from summed rows or refresh heavy CI on this diagnostic.
  A test-only identical-input ARMv5 digest comparison now measures the current
  bounded Go reader, chunked memory control and complete existing BusyBox process.
  All six1/16MiB lanes execute three times with exact digests and unchanged base;
  the base applet matches the pinned target bytes. The measured process is slower
  than the Go file path, so do not adopt it as an admission optimization. Sparse
  large-input samples and included process overhead cannot establish compression-
  only, complete-census or physical performance. Production checks/deadlines and
  the original hosted qualification gate remain unchanged.
  A later QEMU-only runtime data-clock diagnostic passes deterministic host,
  redaction and race tests without changing limits or proof. Two actual fault
  controls refuse at different earlier/untyped boundaries and do not exercise
  its row. Preserve both failed traces; target emission, exact hosted failure
  reproduction and repair remain open. Do not promote host-only instrumentation
  as successful guest qualification or retry unchanged controls until one passes.
  A further ARMv5 trace identifies `verify-owners` with an expired context even
  though its error chain lacks the deadline cause. The three planner context
  guards now preserve `ErrNotReady` plus cancellation/deadline, verified by a
  real admission RED/GREEN and host/race checks. A subsequent normal fault guest
  passes original proof with unchanged limits. This is error fidelity and one
  focused pass, not a timing/hosted repair or complete-image qualification.
- **M0.4 — Maintain release inputs.** Dependency update changes include source
  signatures/hashes, ARMv5 compatibility, package configuration, vulnerability
  review, license material and regenerated SBOM. Test the selected package set.
  **Samba follow-up:** current target4.22.11 must be re-evaluated against the
  newer stable line before release. Qualify the candidate's authenticated
  sources, six-patch disposition, ARMv5 footprint, private module/reader ABI,
  disabled-first credentials, exact status observations, ACL/streams/charset,
  session/source-loss proofs and migration. Do not reuse4.22 private layouts or
  enable experimental persistent handles as an upgrade shortcut.
  [Dated upstream findings and acceptance packet](support/DEPENDENCY-REVIEW.md#samba-update-follow-up-2026-10-14).
  The [dated dependency review](support/DEPENDENCY-REVIEW.md) now identifies
  Linux 6.18.55, host OpenSSL 3.5.9 and Go 1.26.8 as separate update packets.
  Go 1.26.8 has authenticated SDK/source/license and focused host proof on
  frozen `c995c6e`: ordinary/race/22 fixed fuzz campaigns, seven tagged authority
  packages/race3, ARMv5 cross-build and 64 Linux driver tests pass. Successor
  `01e6045` also passes toolkit ordinary/race/five fuzz campaigns and all six
  actual Samba ARMv5 campaigns compiled with the candidate. The complete
  original proof union, runtime census, unchanged base and independent trace
  replay pass; all 1,083 API/toolkit/harness inputs remain unchanged. At that
  earlier component snapshot the base still used Go 1.26.6; component execution
  was not a complete new image or full-image adoption. The feature now selects Go 1.26.8 through one
  exact-state, idempotent Buildroot recipe/hash patch and an early installed-SDK
  version check. Real-package RAM fixtures verify coherent application,
  refusal without effects and stale-SDK rejection. Frozen `970483e` now passes
  one complete cached Go 1.26.8 integration, every original campaign and an
  independent exact954 image/source/package/archive/SDK/license/SBOM audit.
  All 11,510 installed SDK files match the selected SDK and all 1,237 tracked
  witnesses remain unchanged. This supersedes the old complete Go 1.26.6 image
  as the latest local checkpoint; it is not independent clean reproduction,
  exact-head hosted qualification, complete advisory review or EX4/release
  qualification, nor a speedup or hosted-timeout fix.
  See the linked review.
  Linux source/signature/license authentication, unchanged-symbol ARMv5 kernel
  compilation and the original standard QEMU smoke now pass locally. Five
  firmware configurations/release files, both source hashes and the qualified
  GPL patch/driver coherently select 6.18.55; cheap local preflights pass.
  Complete new-output toolchain/kernel/header/userspace integration now passes
  locally on frozen `fb2f68c`: original host/fuzz/MD/state/launcher/runtime/loader/
  atomic/three-Samba/SMART gates and independent exact935 source/archive/license/
  strip/image/seven-hash audit. Actual kernel/header/SBOM/rootfs/legal sources
  bind55 and linked Go remains1.26.6. Exact-head hosted, clean reproduction and
  resolved EX4/physical/release gates remain open; no old image proof is borrowed.
  The 2026-10-08 frozen `4ca65d5` successor also passes the complete cached
  driver and independent exact937 source/package/archive and all original
  artifact/metadata/license audits. Its four-job quota ceiling reaches every
  Buildroot parallel consumer. QEMU-only fixed phase observations cannot
  replace acceptance; two added source files leave the normal product API
  and all seven final artifact hashes unchanged. This is local integration,
  not hosted timeout resolution, measured speedup or clean reproduction.
  The review distinguishes host libraries from linked Go target runtime,
  exact backports from base-version CPEs, and upstream ignore lists from product
  dispositions. All-package/call-path review remains open; no CVE-free or timeout
  fix claim follows from the partial review or focused kernel probe.
  The pinned Buildroot archive producer now has a one-line success-cleanup
  patch, gated by exact original/patched helper and patch hashes. The actual
  unmodified producer fails the temporary-file regression; the patched producer
  preserves compressed bytes, exclusions, unrelated CWD files and repeatability.
  Idempotence and unknown/missing/symlinked input refusals pass in disposable
  RAM. The QEMU driver qualifies/applies it before package builds. The complete
  cached host/ARMv5 build on frozen `d232054` and an independent post-terminal
  read-only audit now pass: exact935 package/archive inputs, zero generated-marker
  exemptions, declared licenses, configured strip/image/export and seven hashes.
  All original Samba/SMART gates are unchanged. No manual historical-marker
  deletion, error/interruption-cleanup claim, clean reproduction, full release
  compliance or native Samba timeout resolution is inferred.

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
  The source-backed [ownership map](STATE-OWNERSHIP.md) identifies current role
  names/writers and constructor effects. Administrator/CHAP Store/Owner opening
  establishes sync boundaries; IdentityOwner startup can also recover interrupted
  Samba intents to review. Do not construct these owners merely to observe boot
  state. Network/TLS ownership, product provisioning, full role/consumer
  composition, retention/reconciliation and physical placement remain unqualified.
  **Normal API startup preflight (host-tested):** validate transport and
  incompatible development policy-store options before opening account/policy
  stores. Actual command-entry subprocess tests reproduce three earlier state-
  first refusals, then verify the corrected boundaries and two admission-order
  controls using only a temporary regular-file sentinel, never a state directory.
  Preserve root refusal, explicit state-option presence, deadlines and generic
  errors. This is option admission, not pristine classification, whole-root
  ownership, all later startup rollback, provisioning or recovery.
- **M1.2 — Explicit bootstrap and migration.** Define pristine, initialized,
  corrupt, incompatible and unavailable states. Enrollment is allowed only from
  proven pristine state. Version upgrades need checked preconditions, retained
  recovery evidence and no implicit empty-state fallback.
  **M1.2a/M1.3a — protected policy observation (host/ARM tested, not admission):**
  a bounded read-only observer/fixed NAS adapter distinguishes empty directory,
  valid current document, pending metadata, invalid/unsupported document and
  unrecognized entries; errors return zero. No sync/init/promotion/deletion/
  reset/lease, Owner admission or HTTP/startup. Empty directory is not NAS
  pristine; valid bytes do not prove acknowledged/durable publication. Format
  incompatibility and corruption are a combined diagnostic, not migration
  qualification. Lock/no-atime/no-follow/current same-filesystem, metadata/
  inotify and cancellation controls pass with whole tagged pinned host/scoped
  race3, Windows and strict2+123. The expanded ARM lane requires47 receipts;
  aggregate raw truncation is preserved and a same-source guest provides all
  complete receipts. **Next:** retain one product state authority across
  classification/admission, complete state-bundle/schema/provisioning/durable
  intent-review semantics, then operator-authorized reconciliation. Never use
  this value as permission or reopen an Owner automatically to erase review.
  **M1.2b — retained read-only policy authority (host/ARM tested):**
  hold the SAME directory/flock/codec/watch across serialized fresh observations,
  reuse the existing collector with confined read cursors and original metadata
  fences. Other writers cannot enter between reads. Drift/uncertainty keeps
  instance review after restoration; copied/serialized handles refuse. Explicit
  observer-only Close has no consumers/leases; close errors retain unattempted
  roots without retry. Controlled descriptor-close faults are not real EIO.
  Whole pinned API vet/unit/store race3, Windows and actual ARM52 receipts/
  strict2+133/unmount/base hash pass at unchanged bounds. No mutation/handoff/
  Owner admission/HTTP/startup. **M1.3b next:** specify durable intent/receipt
  records and recovery identity; interrupted publication without confirmed
  readback remains review. Keep state-bundle/provisioning and qualified physical
  placement separate. A volatile watch/value is never durable boot permission.
  **M1.2c.1 — policy-session declaration data (experimental prerequisite):**
  strict private opening/closure records bind installation/epoch IDs, exact uint64
  sequence and policy revision/hash; closure also binds the exact opening bytes.
  Match complete supplied data without treating record absence as pristine or
  a matching declaration as clean-shutdown/admission proof. Preserve independent
  incomplete/inconsistent diagnoses; malformed present records cannot hide behind
  another missing input. Retain4096-byte/depth2/strict-envelope/privacy bounds,
  exact same-revision byte equality and zero-on-error; never wrap counters.
  No ID allocation/succession authority, filesystem role, writer or boot behavior
  is added. Require native units/vet/race, bounded fuzz and two actual ARM receipts
  across existing API restart without relaxing old assertions or guest budgets.
  **Next:** specify a bounded separate session namespace and trusted root Owner;
  opening durability before effects, full role/consumer settlement before closure,
  uncertain-return evidence and explicit fresh-epoch reconciliation on qualified
  media. Do not insert new roles into existing fixed policy/history censuses,
  silently reopen a writer or infer historical syscall returns from byte equality.
  Qualified automatic recovery/service restart is now required for the first
  release; these codecs do not implement it. See the
  [selected recovery requirement](STATE-OWNERSHIP.md#first-release-automatic-recovery-requirement);
  physical/recovery/release gates remain.
  **Local acceptance:** Windows units, pinned Go1.26.8 vet/units/race3, 2,000
  bounded fuzz executions and actual standard ARMv5 smoke pass. Exact epoch,
  model and writer pairs bracket API restart; all old checks/caps retained.
  This qualifies declaration data only, not a persisted epoch or clean boot.
  **M1.2c.2 — fresh policy-session declaration journal (internal component):**
  fix one pre-provisioned owned0700 `policy-session` child of a borrowed original
  trusted parent. Reuse strict anchored Store/flock and fixed `epoch.json` /
  `.epoch.pending`, no constructor init/sync/deletion or existing-state adoption.
  One opening and one explicit closure publication, canonical exact-record
  envelope bounded12KiB; transaction1/2 differs from epoch/policy counters.
  Generate the epoch ID internally; capture trusted installation/sequence and
  backend once, never per-call paths/IDs/implementations. Any admitted uncertain
  publication/read/cancellation fences all further writes/observations. Close
  only releases references; it never invents a closure or deletes evidence.
  Require actual native lock/readback/concurrency and before/after mutation/Close
  controls plus the same disposable three-scenario fixture natively on tmpfs and
  in ARM. Preserve original opening, refuse matching existing evidence, verify
  closure/disposal/FD balance. Value/pointer formatting/JSON must remain private,
  copied handles invalid, and concurrent formatting must not copy mutable state.
  Keep old smoke proofs/budgets and require two exact journal receipts across
  API restart; this is not a new CI lane or a physical state-medium choice.
  **Next:** retained complete product root/role/consumer/history composition,
  absolute-parent/unique-mount and ABA/watcher coverage, complete constructor/
  temporary-close faults, durable review, successor/retention and writable-restart
  qualification. Empty role never proves pristine or permits erasing known errors.
  No product startup/HTTP, boot/recovery policy, service activation or EX4 writes.
  **Local acceptance:** portable Windows codecs and pinned native actual-I/O,
  fixture/vet/race3 pass without positive skips; final ARM standard smoke passes
  two exact journal receipts including private-copy refusal and all old checks.
  A real value-formatting metadata leak led to an opaque immutable handle/private
  state split, concurrent-formatting race controls and final-source ARM retest.
  This is not physical durability, full/media/two-boot or product root admission.
  **M1.2c.3 — compose fresh session and policy/history authority:** explicitly
  select a new private QEMU tmpfs three-role profile; create the session role
  before capturing the root witness, preserve the old two-role census unchanged.
  Retain actual root/policy/history/session locks; record exact owned-base opening
  before returning a usable edit writer. Guard every operation with its retained
  opening, under the same mutex. Explicit closure rechecks exact current and
  complete owned history before/after publication, seals further edits and never
  overrides review. Close only releases; no implicit closure or existing-state
  adoption. Incompatible ext4/crash/nonhistory combinations refuse before effects.
  Acceptance: native exact-profile census/refusals/vet/race and actual ARM five
  scenarios: normal alternating views, restored missing opening, policy commit
  followed by error, cancel after actual closure, Close without seal. Verify
  four real locks, no-effect terminal refusal, unchanged opening/history, preserved
  evidence and FD-balanced disposal. Require two exact receipts at old budgets.
  Still no product root/consumer/provisioning, durable review, successor/recovery,
  child ABA/watch completeness, physical-media or clean-shutdown authority.
  **Local acceptance:** portable Windows units and pinned native vet/scoped
  units/race3 pass; exact-census/profile controls execute, positive root lifecycle
  skips without mandatory unique mount IDs. Actual standard ARMv5 smoke passes
  all five scenarios twice with strict complete receipts and all old caps/checks.
  This does not qualify positive lifecycle race, media/two-boot/full integration
  or any product bootstrap/recovery path.
  **M1.2c.4 — joined session/history diagnosis:** compare declarations, exact
  opening checkpoint/current and complete operation history as one bounded
  observation. Reuse strict epoch/history codecs; include all fields in the4MiB
  bound and retain16-operation/4096-record/656128-policy limits. Exact opening
  revision/hash must bind the checkpoint itself, never a coherent later suffix.
  Validate present malformed data before a diagnosis, preserve known mismatch
  over missing evidence, and keep unconfirmed operations unresolved even with a
  matching closure. Five private redacted kinds grant no boot/recovery/action.
  The retained journal must compare supplied DATA under its own mutex/readback;
  the fresh writer supplies actual original history/current under all role locks.
  Run at initialization, accepted publication and before/after closure. Shared
  owned bundle decoder must retain filename/content binding, zero-on-error and
  cleanup, without caller backends or paths. Require native tuple/missing/invalid/
  privacy/concurrency/exact-inclusive-bound/fuzz tests and actual ARM coherent-
  suffix refusal, unresolved publication and canceled-closure sticky review.
  Strengthen existing session receipts, no new stage/cap relaxation. This is not
  existing-state provenance, a complete boot bundle or authorized reconciliation;
  all product/physical/succession/consumer/recovery gates above remain.
  **Local acceptance:** Windows portable tests, pinned native vet/scoped units/
  race3, exact inclusive aggregate/record/count and concurrency/privacy controls,
  2,000 opening-input fuzz executions and final actual ARM smoke pass. Root
  lifecycle skips natively without mandatory unique IDs. Two exact strengthened
  session receipts plus all old checks/caps required, no temporary diagnostics.
  First15s guest timeout has no isolated cause; measured diagnostic run passed
  at12.1–12.5s. Remove duplicated independent+joined complete comparisons at each
  boundary, not reference checks or cases. Native two-operation DATA benchmark
  records47% fewer allocations, not peak RAM/ARM/product or historical flake repair.
  **Next M1.2c.5 — explicit retained read-only session/history profile:** qualify
  an opt-in three-role collector with original root/policy/operations/session
  locks, fixed bounded schema/census, original files/mount/watch lifetime and
  exact checkpoint binding. Existing two-role OpenHistory must remain strict,
  never autodetect/adopt/upgrade. Read all present evidence before diagnosis;
  pending is metadata-only review, never recovery/promotion. Constructor must
  never initialize/sync/delete, and every drift/cancel/close uncertainty stays
  review. Test missing/foreign/mixed layouts, restored substitutions, full actual
  lock exclusions and read-only byte/metadata/FD invariance. Reuse existing host/
  QEMU tooling and measure cost first; no new default historical build stages.
  This still cannot supply complete product credential/identity/registry/secret/
  network roles, succession/retention, consumer settlement or recovery permission.
  **M1.2c.5 local acceptance:** explicit OpenSessionHistory/ObserveSession uses
  original root/policy/operations/session locks and the existing no-atime/census/
  unique-mount/watch engine, with pure strict expected-identity journal/named-
  history bridges. All three pending roles latch review before any content read;
  wrong-profile methods refuse, old profiles never autodetect. Portable Windows
  bridges and pinned native vet/scoped units/race3 pass; positive native root
  lifecycles skip without unique IDs. Native Close-only eight-position two-op
  roster controls pass before/after close, no raw-FD retry/recycled-FD damage.
  Actual standard ARM10 scenarios twice cover closed/open/missing, three pending,
  restored file/mount, malformed and read-error cases. Four actual locks, owned
  checkpoint, copied/wrong-profile refusal, sticky review, byte/stat/atime and FD
  invariance/known-name disposal pass with all old proof and unchanged budgets.
  **Next:** qualify all constructor/temporary-witness/cursor/watch-close failures,
  larger rosters/namespace/content/bounds and full role bundle. These synthetic
  observation locks do not grant writer handoff/reopen, pristine, checkpoint
  provenance/succession, durable quarantine/reconciliation or product admission.
  Keep actual writer-process/reboot/medium/physical and release gates separate;
  no boot/recovery default follows from matching records.
  **M1.2c.6 — explicit administrator/CHAP diagnostic readers:** reuse the protected
  retained read-only namespace engine with fixed role names and original schema
  decoders, no per-read codec/backend. Retain actual original writer lock, file,
  unique mount/path/census and watches. Return only private missing/valid kind
  and exact revision, never names/verifiers/SecretRefs/material. Preserve root-only
  CHAP opening and canonical account-v1 bytes; no KDF/authentication, Store/Owner
  sync, enrollment, consumer handoff or automatic missing-state setup. Pending
  must suppress all content reads; malformed/replaced/uncertain state stays review
  after restoration. Wrong-profile calls and copied handles must refuse. Test both
  schemas, exact revision/byte bounds, no private serialization/formatting, actual
  lock exclusion, unchanged bytes/stat/atime and FD-balanced known-name disposal
  in the existing bounded standard ARM guest. This is not the whole-state owner,
  pristine classification, product credential provisioning or recovery admission.
  **Local acceptance:** pinned native vet/scoped units/race3, fixed-schema metadata/
  privacy/bounds/refusal and Windows portable checks pass. Native full positive
  lifecycles SKIP without unique mount IDs. Actual standard ARM10 cases twice
  cover both profiles' valid/missing/pending/restored/malformed state, actual lock
  exclusion, copied/wrong-profile refusal, zero pending reads, ordinary exact
  byte/stat/atime preservation and FD-balanced disposal. Seven strict receipt
  pairs/all prior assertions pass at unchanged15s/240s/360s limits. No new default
  lane, Docker image/volume, NAS operation or status-producer work. Full credential
  constructor/temporary-close/watch/namespace faults and whole-product ownership/
  consumer/provisioning/reconciliation/physical qualification remain required.
  **M1.2c.7 — stored identity-document comparison:** compare a complete supplied
  registry/native/optional-enrollment journal roster using the existing strict
  decoders, without constructing IdentityOwner or opening/recovering stores.
  Exact naming/identity/revision links, duplicate/orphan/SID refusal, native
  operation ordering and interrupted phases must yield private no-action results.
  Validate all present bytes before semantic diagnosis; known contradictions
  must not become mere missing data. Require explicit complete roster, exact
  uint64 revisions and inclusive individual/count/aggregate bounds. Retired
  registry states remain explicitly unsupported, never erased or reused. Test
  immutable bytes, privacy, concurrency and actual ARM synthetic comparisons in
  the existing standard self-test/receipt pair. This is not a filesystem census,
  Unix/passdb observation, writer handoff, recovery or startup admission. Next
  integrate retained namespace observation with complete product roles/consumers.
  **Local host acceptance:** Windows portable/root fixture and pinned Linux tagged
  vet/scoped units/race3 pass. Exact uint64, inclusive individual/count/aggregate
  bounds, privacy, input immutability and concurrency controls pass. Reproduced
  known-link/missing-evidence precedence and fixture serialization-oracle defects
  are corrected without changing original decoders or serialization refusals.
  No positive filesystem/runtime ownership or startup permission follows.
  **ARM acceptance:** actual standard ARMv5 smoke passes eight synthetic cases
  twice across API restart and all previous assertions; eight strict receipt
  pairs/unchanged limits, no new default stage or producer experiment. Retained
  identity filesystem provenance, all product-role/consumer ownership, durable
  reconciliation and media/full/hosted/physical/release gates remain open.
  **M1.2c.8 — explicit retained identity namespace reader:** root-only fixed
  root/registry/operations/account/optional-smb layout, actual original flocks in
  documented deterministic order, complete bounded census, unique mount/path and
  file/directory watches. Reuse protected read-only/no-atime/chunk/Close engine;
  compare complete original current records with M1.2c.7. Any pending role must
  suppress all content reads; empty present enrollment child is unavailable, not
  absent. No Owner/Store construction, sync, recovery, live identity/passdb check,
  handoff or admission. Require original-lock exclusion, wrong/copy refusal,
  restored sticky review, malformed/missing/partial state and ordinary exact
  bytes/stat/atime/FD preservation in existing bounded ARM smoke. Preserve old
  profiles/proofs/caps. Maximal1024-account roster descriptor/resource needs,
  complete constructor/temporary-close/watch/namespace/cancel faults, real writer/
  restart/media provenance, whole-role/consumer and product qualification remain.
  **Local acceptance:** pinned tagged vet/scoped units/race3 and nine-family
  refusal controls pass; positive native lifetime SKIP for the non-root profile.
  Actual ARM8 scenarios twice cover valid/missing registry/empty enrollment,
  three pending roles, observed substitution/restoration and malformed state.
  Six actual directory locks, wrong/copy refusal, zero pending reads, ordinary
  byte/stat/atime invariance and FD-balanced known-name disposal pass with all
  old checks and unchanged shared15s/240s/360s caps. No new default guest or
  producer work. Complete constructor/temporary-close/watch/namespace/cancel/
  read/close faults, maximal-roster resources, actual writer/restart/media and
  whole-product/physical/release qualification remain open.
  The [proposed operation-evidence contract](src/phantowd-api/internal/revisionstore/RECOVERY-DESIGN.md)
  separates local commit records from client response delivery. It is a design,
  not an implemented journal or approved admission protocol. Implement in order:
  **M1.3b.1/b.2** strict private intent/receipt codecs and pure diagnostic matcher;
  this first slice is approved and implemented in
  [policyevidence](src/phantowd-api/internal/policyevidence/README.md), without a
  collector or effects. Schema1 records are flat/bounded4096bytes, fixed exact
  keys and local-confirmed phase, nonzero opaque IDs, consecutive uint64 revisions
  and exact policy-byte SHA-256. Explicit complete/absent/unavailable role inputs
  yield six redacted diagnostic kinds; every kind grants no action. Validate
  current whole NAS schema/revisions, reject foreign/orphan/mismatched evidence,
  distinguish no recorded operation from pristine, and refuse generic JSON and
  ordinary formatting leaks. Never infer earlier fsync returns/client delivery.
  Acceptance: nonempty three-protocol pair, every tuple/role refusal, complete
  byte bounds, maximum revisions, exact-byte changes, privacy, whole host vet/
  units/race, bounded fuzz and same-boot pure ARM checks; no collector, journal
  writes, recovery/replay, admission/HTTP/product activation or device operation.
  **M1.3b.3** retained read-only evidence collection (partial experimental
  [Linux implementation](src/phantowd-api/internal/policyevidencefs/README.md)); the
  [collector proposal](src/phantowd-api/internal/policyevidence/COLLECTOR-DESIGN.md)
  specifies a separate fixed record namespace, retained originals and sticky
  uncertainty. A Linux adapter regression proves ancestor/sibling locks do not
  exclude the existing policy Store; the actual policy lock must remain held.
  Independent child probes require exact unique receipts, not merely exit0.
  The collector retains root/policy/record directories and actual Store lock,
  no-atime read-only original files, complete bounded census and mutation watches.
  Unique mount IDs and a fresh path witness reject root/child/file overmounts;
  kernels without the feature refuse instead of degrading. Whole-role reads feed
  the existing pure matcher, publish no raw bytes or leases, and latch review on
  drift/cancellation/I/O/close uncertainty. No file initialization/sync/write or
  recovery/Owner/HTTP/product startup. The root/record layout stays experimental,
  not product namespace or physical placement approval. Current native WSL
  verifies unsupported refusal with positive lifecycle cases explicitly skipped.
  Actual ARMv5 standard smoke checks all six kinds, actual Store exclusion/release,
  stable FD counts, four bind substitutions, nine unsafe layouts, pending/writer/
  read/cancel/watch faults, private/copy refusal,12 concurrent reads and controlled
  close uncertainty twice across API restart. Exact2 receipt controls pass.
  Remaining: full constructor/namespace/read/close/fault/atime/content/bounds and
  independent-writer qualification on supported media; supplementary close tests
  now cover all 11 file/directory positions in the two fixed profiles with controlled
  before/after-real-close failures (22 cases), exact safe FD reuse, sticky review,
  remaining-original/lock retention and disposal baseline. Native Close-only
  units/race3 and actual standard ARM Open/OpenBundle cases twice across restart
  pass with the existing 15 s fixture / 240 s guest limits. This is not constructor,
  watch-close, kernel/media EIO, complete lifecycle race or durable qualification;
  no positive native Open lifecycle race,
  durable-quarantine or physical-storage qualification is implied;
  **M1.3c** one-attempt writer with preserved base and every interrupted boundary:
  **c.1 private preparation (implemented, host/ARM prototype)** validates the exact
  coherent base plus Store-encoded next revision before internally generating an
  opaque operation ID, retains defensive base/candidate copies and exposes only
  private intent data. No receipt/write/admission or single-use authority. Host
  bounds/privacy/entropy controls, actual temporary Store byte parity, race3 and
  bounded2000fuzz pass; existing ARM fixture reuses the real preparer/Store and
  requires unconfirmed without receipt, twice across restart. Production entropy
  follows pinned Go's fatal-source policy, not fake-reader recoverability.
  **c.2 retained writer authority/namespace** must qualify the explicit bounded
  operation-bundle protocol and preserve the original lock into effect ownership,
  not close/reopen the observer. The selected product
  direction is current policy plus per-operation bundles, not immutable policy
  generations/manifest. The experimental bytes are not a frozen compatibility
  contract; physical placement/provisioning and product publication remain open.
  **c.2a anchored history comparison (host/ARM prerequisite):** inspect a complete
  supplied operation set against an independently trusted exact checkpoint and
  current policy. Reuse strict record/bundle codecs; require unique operation IDs,
  contiguous exact revision/hash links and locally confirmed interior records.
  Preserve unconfirmed/incomplete tail diagnoses, refuse forks/gaps/byte changes,
  and validate all present records before a redacted result. Bounds16 operations/
  4MiB are inspection limits, never permission to truncate/delete history or move
  its checkpoint. Native units/race and the existing ARM smoke exercise this
  model; original bounds/boot count stay fixed. No filesystem census/provenance,
  multi-operation writer/recovery, HTTP or product service authority follows.
  **c.2b retained history observation (host/ARM prerequisite):** an explicit
  experimental `OpenHistory` fixes canonical operation-ID filenames, binds them
  to strict decoded intents and owns an independently trusted exact checkpoint.
  Reuse original root/policy/operations locks, complete bounded census, confined
  original files, unique mount identities and serialized rechecks/watches.
  Enforce16 records and4MiB wire aggregate before data reads; metadata-only pending
  means review before any content. Refuse mixed profiles and restored drift.
  Standard ARM tests two coherent operations, actual Store exclusion, pending,
  naming/substitution and count/byte limits plus six close boundaries in both
  controlled modes. This does not qualify every larger roster/constructor fault,
  checkpoint origin, historical completeness, physical state or writer admission.
  Next: design the separate root Owner retaining original locks into a bounded
  multi-operation writer in disposable fixtures. A read-only Observer is never
  upgraded implicitly into write authority; define its diagnostic epochs around
  owned mutations without suppressing external drift. Do not close/reopen across
  admission, prune/rebase the checkpoint, retry uncertain effects or activate
  product services implicitly.
  **c.2c bounded multi-operation publication (QEMU-only prototype):** fresh tmpfs
  root Owner mode retains root/policy/history locks and exact initial checkpoint.
  Create a distinct operation-ID file per revision; preserve exact base/intent,
  publish policy once, verify readback, then publish local confirmation. Retain
  immutable original record descriptors/metadata/watches across later operations;
  fresh bounded reads must still match the checkpoint chain. Preflight count16/
  4MiB checkpoint/current/encoded-record limits, never prune/rebase to fit them.
  Match the exact pending create/modify/write-close and cookie-paired move event
  profile; never reset/drain watches to waive drift. Unknown event behavior fails
  closed, not automatic retry. A successful distinct next revision may proceed;
  every admitted uncertain return fences the whole lifetime and fresh IDs too.
  Tests cover two operations, concurrent stale loser, preserved first original,
  canceled intent/policy/receipt, post-success policy error, immutable write-open,
  same locks, repeated no-effect refusal and balanced closure. Native child
  journal tests actual16/17 files and watcher-enrollment cleanup regression.
  This does not complete production c.2/c.3: next qualify this mode's own partial
  write/sync/close/rename/directory-sync and process-loss boundaries, supported
  filesystem/restart behavior, retained constructor/close faults and worst-case
  resource bounds. Older one-operation process-loss tests do not transfer.
  Only then admit explicitly provisioned product state, diagnostic epochs,
  durable review/reconciliation and HTTP/service ownership; no observer upgrade
  or NAS writes are authorized by this prototype.
  **c.2c.1 typed protocol-view transaction bridge (QEMU-only):** reuse the same
  writer mutex across expected revision, coherent view editing and the original
  intent/policy/receipt transaction. No alternate store, backend or caller ID.
  Exercise nonempty SMB/NFS then iSCSI changes, persisted whole-policy readback,
  different-protocol concurrent proposals with one winner, unchanged bytes/census
  on stale/rebound/pre-canceled input, and sticky review after actual intent
  publication. Switching protocols/contexts must not retry uncertain work.
  Retain first-record identity/bytes, original locks, FD-balanced close/disposal
  and all existing scenarios/caps. Require two complete writer receipts plus the
  existing model receipts across standard API restart; missing/changed/extra
  rows cannot qualify. Native positive skips on unsupported mount identity must
  not count as lifecycle evidence. No product constructor, existing-state opener,
  HTTP, backing/credential access, activation or physical operation follows.
  **Local acceptance:** pinned native vet/units/race3, exact-pair refusal controls
  and actual ARMv5 standard overlay pass. Both model/writer pairs bracket API
  restart, with all old checks/budgets. A failed fixture capacity increment was
  reproduced in native512/4096-byte maximum-value drafts and corrected without
  changing model limits. Separate historical media/loss, two-boot/full-image,
  product bootstrap/recovery, physical and release gates remain unqualified here.
  **c.2d qualify history publication before product admission:** keep the new
  writer behind its QEMU-only fresh-state constructor until its own fault corpus
  passes. Start with native real-file fault controls, then the pinned ARM media
  lane; older one-operation receipts cannot count for the new journal.
  **c.2d.1 implemented/ARM fixture-qualified:** copied second-operation-only
  profiles,14 native returning journal boundaries and seven native third-policy
  boundaries;21 real SIGKILLs with the actual runtime history reader pass.
  First-original capture precedes second effects via two PID/root/challenge gates;
  full first-record metadata/atime, original refs, no pending diagnosis and known-
  loss review survive. Complete143-receipt media lane and2positive/329negative
  controls pass, retaining all previous proof. New group14.13s fits existing
  Go45s/guest60s/outer180s; no stage/timer increase.
  **c.2d.2 partially implemented, synthetic ext4 only:** closed marked guest/
  fixed-device fresh-state construction, normal successive writes, real EROFS,
  ENOSPC/zero available blocks and sticky review after restoration pass. A clean
  producer exit followed by a new read-only reader verifies exact original
  evidence; this is not writable restart admission or an OS reboot. The full
  optional lane passes148 ordered receipts/2positive341negative controls only
  in an isolated run at unchanged45s/60s/180s limits. Its first extended run passed
  all new cases but timed out in an older loss case; worst-case timing remains
  open. Serialize heavy native qualification before timed guests; do not mask
  this conflict by dropping proof, widening budgets or claiming hosted repair.
  **c.2d.2 synthetic ext4 losses now fixture-qualified:** explicit optional
  `history-ext4` profile covers all21 syscall-boundary SIGKILLs, original first
  record/locks/full statx/atime and actual runtime reader after RO remount. Pending
  has no diagnosis; matching confirmation never erases known-loss review. Its28
  receipts/2positive89negative controls and unchanged default148 receipts/2+341
  pass separately on the same frozen source at existing45s/60s/180s limits. No
  default guest or replacement of tmpfs proof. An actual EBUSY control explains
  initial post-policy-rename remount failures: release only the checked temporary
  mutable-policy capture before second effects; confirmed-history and directory/
  lock pins remain retained. Do not force/retry remount or relax identity checks.
  **c.2d.2 outstanding:** selected product state-medium qualification,
  writable process/system restart, real constructor/temporary-close/watch/EIO
  faults, worst-case16-record/4MiB resources, and product checkpoint provenance/
  retention/review/reconciliation. The EX4 state medium remains unselected.
  Success-boundary SIGKILL is not interruption inside a blocked syscall or power
  loss; the complete contract below is not wholly qualified by c.2d.1.
  - Fix syscall/fault plans at construction, never per-operation or from HTTP.
    Cover short/partial and full write, file sync, file close, before/after rename
    and directory sync for second intent, policy and confirmation. Preserve first
    confirmed record's original descriptor, exact bytes and metadata throughout.
    Capture completion/close uncertainty without raw-descriptor retry; retained
    original references survive any uncertain constructor/teardown result.
  - Real SIGKILL probes use the original bounded PID/challenge/gate discipline.
    Parent captures original root/policy/history/first-record references and
    verifies actual child flocks before loss, then verifies death/reaping before
    acquiring observation locks. Reacquired observation locks never confer writer
    admission. Open the actual history reader with an independently supplied exact
    checkpoint; do not initialize/delete pending evidence or manufacture recovery.
  - Every pre-rename pending boundary is metadata-only review with no diagnosis.
    A published intent with old policy may observe intent-base; new policy without
    confirmation may observe publication-unconfirmed; published matching receipt
    may observe local-confirmation. **Every killed writer still requires review**,
    including matching receipt or apparently empty second operation. Verify no
    retry/new-ID/service action, no changes to first record and bounded FD disposal.
  - Keep the existing media guest selectors/catalogue closed and all old receipts,
    normal unmounts and unchanged base checks mandatory. Measure the shared Go45s/
    guest60s/outer180s and resource budget before adding cases; do not widen limits,
    suppress old tests or add a default CI guest implicitly. If it cannot fit,
    report the measured conflict rather than claim composite qualification.
  - Same-kernel tmpfs SIGKILL is not physical persistence. Separately qualify a
    supported local filesystem, process/system restart, ENOSPC/read-only behavior,
    worst-case16-record/4MiB memory and time, persistent checkpoint provenance,
    bounded retention/review and explicit reconciliation. Product capacities and
    compaction require a designed protocol, not silent deletion at record16.
  **c.2d.3 clean two-boot prerequisite implemented/ARM fixture-qualified, not
  product recovery:** explicit `history-reboot` profile passes two distinct kernels
  on the same private32MiB RAW working disk. Actual history reader, complete bound
  receipts/normal exits/unmounts, exact file bytes/selected stable metadata, unchanged
  boot2 whole-disk hash and seed/base hashes pass. Go phases0.93s/0.29s fit45s/60s
  each and180s combined; no default CI stage. All148default receipts independently
  pass. First pre-boot snapshot failure required only private-tmpfs TMPDIR export;
  container read-only/no-swap/resource policy was not relaxed. The acceptance
  boundaries below remain requirements, not writable adoption authority.
  - Keep the manifest-verified base and seed disk read-only; put the one writable
    virtual working copy, caches and all receipts in bounded private host tmpfs. No
    physical device passthrough, host ports/NIC, product init or persistent volume.
  - Boot1 creates only a fresh generated namespace, publishes two nonempty
    three-protocol revisions, verifies close and normally unmounts. Emit a bounded
    PID/challenge/root-bound proof; require normal guest exit before boot2.
  - Bind boot2 to the same actual virtual working disk and exact first-boot namespace;
    its known synthetic checkpoint is an independent test input, not inferred
    from the records or advertised as product checkpoint provenance. Observe with
    the real history reader after a verified read-only mount; never open a writer.
  - Independently compare complete original file bytes and captured stable
    filesystem metadata across boots. Do not compare kernel mount IDs or process
    descriptors across kernel lifetimes as though they were stable identities.
  - Require both complete boot receipts, original seed/base hashes unchanged,
    normal unmounts and complete temporary teardown. Fail closed on absent,
    duplicate, foreign, stale, out-of-order or partial boot evidence; never compose
    partial successes. Specify and measure bounded per-boot/whole-run resources
    before enrollment; never silently expand an existing lane or default CI.
  - A clean two-boot pass proves only that synthetic observation scenario. Abrupt
    power/cache loss, real EIO, writable admission/reconciliation, trusted product
    checkpoint, durable review and physical EX4 recovery remain independent gates.
  A separate [strict anchored Store prerequisite](src/phantowd-api/internal/revisionstore/ANCHORED-STORE.md)
  now retains the actual child lock under a borrowed parent, does not sync on
  open, returns exact bounded readback and fences pending/unknown entries plus
  every attempted-mutation error. This is not the root Owner, a namespace decision,
  logical single-attempt protocol or complete c.2/c.3. Existing adapters unchanged.
  A separate [QEMU-only one-operation prototype](src/phantowd-api/internal/policytransaction/README.md)
  now composes an original root/unique-mount/watch and both strict Store locks,
  privately creates/initializes only fresh tmpfs state, and fences a single
  operation through base/intent -> policy -> exact readback -> local receipt.
  Eighteen whole-method/cancellation/drift cases verify actual file phases,
  original locks, one concurrent winner, review despite matching receipt and
  no second attempt; existing standard ARM fixture repeats them twice. This is
  partial c.2/c.3/c.4, not product namespace approval, existing-state admission,
  every interrupted syscall/real media fault, durable quarantine or recovery.
  **c.3 durable base/intent before policy** must forbid initial pending/unresolved
  evidence and every second attempt after uncertain I/O, even bare Store ErrIO;
  never exploit Store's later pending cleanup or mint a new ID to bypass review.
  **c.4 exact readback/receipt** must test each write/sync/rename/close/return
  boundary, keep uncertain confirmation and distinguish local return from HTTP
  delivery. **c.4a method-boundary process loss (ARM fixture-tested)** now uses
  actual SIGKILL at seven intent/policy/readback/receipt gates, retaining original
  read-only references before loss and acquiring diagnostic locks only after
  verified death. Repeated exact byte/statx observations preserve review even
  with empty journal or matching receipt. Product code is unchanged: all new
  process/observer logic is test-binary-only, not writer re-admission/recovery.
  **c.4b declared syscall-return boundaries (host/ARM fixture-tested)** now adds
  21 actual SIGKILLs across intent/policy/receipt for partial/full write, file
  sync/close, before/after rename and directory sync. A sealed QEMU-only profile
  is fixed at strict Store construction; normal callers pass no plan. Returning
  gates fail/poison rather than report success. Pending is metadata-only to the
  test observer and suppresses matching; a separate no-atime oracle verifies
  synthetic staged bytes, never promotion/replay. Original18-case ARM smoke
  also passes. Existing NIC-less media guest now requires121 receipts/two Go PASS
  lines under unchanged60s/180s limits and a shared45s test allowance; both closed
  selections and2+283 parser controls prevent helper SKIP/unknown-test drift.
  **c.4c retained bundle diagnosis (experimental host/ARM)** adds an explicit
  fixed-profile read-only opener using the same original-lock/mount/census/watch
  engine, not writer adoption or autodetection. Portable bounded comparison
  distinguishes six redacted kinds; malformed input yields no partial diagnosis.
  Repeat all28 loss gates with the runtime reader, independent pre-loss metadata
  witnesses and actual root/policy exclusion. Either pending role refuses before
  data reads; matching receipt/empty journal never grants action. Standard ARM
  also checks six kinds, pending/read/cancel/restoration/profile controls. This
  is not complete fault coverage, durable quarantine or product boot wiring.
  Still required: in-flight kernel-I/O interruption and real errors, complete
  constructor/close campaigns, system restart, persistent medium,
  qualified product observation wiring, durable quarantine and authorized recovery.
  **c.5 retention/reconciliation** requires bounded evidence preservation
  and explicit authorization; none is implemented by preparation;
  **M1.3d** explicitly authorized reconciliation; **M1.2c** complete boot bundle.
  Missing/mismatched evidence never authorizes replay or service startup. The
  schema API, namespace/atomic-publication strategy, low-space retention and
  durable-review recovery require explicit decisions before the respective
  mutating implementation. Existing adapter/Owner semantics remain unchanged;
  the optional anchored profile has its separate stricter refusal contract.
- **M1.3 — Recover interrupted operations.** Extend current journal semantics
  to an explicit review/reconciliation workflow. An intent plus missing reply
  does not imply failure or success. Preserve orphaned publications; compare
  fresh observed state before any authorized recovery. No blind replay/deletion.
  **M1.3e — Automatic boot recovery and service restart (required; not implemented).**
  Ordinary unclean shutdown must not require routine panel confirmation. Use
  the [boot/recovery acceptance matrix](STATE-OWNERSHIP.md#required-bootrecovery-acceptance-matrix),
  retaining the distinction between an open confirmed session and unresolved
  effects. Specify the complete installation/role/history/identity/storage/credential/action matrix,
  independently trusted checkpoints, durable recovery progress and lock order
  before adding mutations. Reacquire fresh qualified authorities and start only
  desired-enabled services after coherent dependencies/readiness checks; never
  reuse prior-boot leases or a bay-derived identity. Preserve desired-disabled
  services and original interrupted evidence. Unresolved/unsafe cases withhold
  affected admission and notify, not blind replay, pending deletion, an empty
  mountpoint, reviewed-Owner reset or a restart loop. Prove isolation before
  allowing unaffected services. Acceptance: real SMB/NFS/iSCSI access after
  normal and ordinary unclean fixture reboot without a manual action; actual
  interrupted recovery at each durable boundary, stale/missing/clone/permission/
  credential faults, ENOSPC/read-only/cancel/cleanup uncertainty and disabled
  services. Host/QEMU evidence must preserve exact data/state and include real
  readiness/closure, not only a matching diagnosis. Physical power loss, EX4
  medium/cooling/compatibility/recovery remain separate gates. Existing Owner
  review semantics remain unchanged until a separately qualified handoff exists.
  Current software evidence includes real NFSv3/TCP policy/data access across
  two clean QEMU boots, with denied writes/clients and verified normal teardown;
  this does not complete product startup, unclean recovery or the fault matrix.
- **M1.4 — Qualify filesystem durability.** Exercise write, rename, file/directory
  sync, ENOSPC, read-only storage, corrupt/truncated files, replacement/symlink
  attacks, concurrent writers and process exits at each durable boundary.
  Clean reboot and process exit are not power-loss guarantees.
  **M1.4c — read-only bundle diagnosis (ARM fixture-tested):** the real retained
  reader now observes all six evidence kinds and both pending roles on the fixed
  synthetic ext4 device after a verified read-only remount. Original references,
  complete census/statx including atime, exact current/operation bytes and FD
  baseline bracket the runtime lifetime; actual policy/root exclusion remains.
  The test refuses outside the bounded32MiB VersatilePB media fixture, restores
  the mount before cleanup, and shares the existing guest/time/resource limits.
  No product/writer changes or physical placement, durable quarantine, restart,
  power-loss/recovery/admission qualification is implied. Persistent-format
  selection remains a separate decision, not inferred from these experiments.
  **M1.4a — abrupt policy writer (native/ARM fixture-tested; not complete):**
  a test-only child holds the actual revision-store lock while its parent
  confirms exclusion, then sends SIGKILL at seven write/sync/close/publication
  boundaries. Reopening returns the exact old/new nonempty SMB/NFS policy,
  never staged or mixed components; pending evidence survives observation,
  stale commits refuse and explicit subsequent commits succeed. Three native
  Linux race-enabled repetitions and whole tagged API vet/race tests pass.
  That original native campaign uses tmpfs regular files without mounts/devices;
  production code and firmware inputs are unchanged. Its result was not ARMv5/EX4
  execution, real ENOSPC/read-only-media qualification, power interruption,
  selected state-medium durability or an implemented reconciliation workflow.
  The optional `support/test-revisionstore-media.ps1` follow-up now executes
  both SMB/NFS and SMB/NFS/iSCSI profiles on synthetic ARMv5 ext4: all14
  interruption stages pass in two consecutive snapshots. Exact old/new policy,
  pending evidence, live lock and signal-exit checks are unchanged. This extends
  process-interruption qualification, not sudden-power-loss evidence.
  **M1.4b — actual full/read-only media (ARM fixture-tested; not complete):**
  the same generated32-MiB ext4 lane requires real zero-available-block
  exhaustion and read-only remount, failed owned Commit/sticky review, retained
  exclusive lock, refusal after space/mount restoration and exact confirmed
  three-protocol state after explicit fixture close/reopen with no consumers.
  Pending evidence remains. A bounded fresh-file tail fill fixes the harness's
  disproved assumption that one growing file's ENOSPC implies a full filesystem;
  no production error behavior or zero-space predicate is relaxed. Two actual
  guests, pinned host vet/unit/race3, Windows checks and strict2+64 pass.
  This does not complete M1: product provisioning/placement, durable review,
  power-loss/cache-flush/failing-device tests and operator recovery remain.

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
  substitute the backend. The base executor now fences every operation before
  its first close and preserves a terminal close error without retry or later
  false success, including empty observations. Real-file fault/concurrency
  regressions pass in ordinary and tagged Linux race tests; separate unmodified
  ARMv5 normal-path campaigns and complete cached image integration pass on the
  combined checkpoint, with all 928 API source/package/archive files and the
  configured strip/installed/image/export bytes independently matched. These
  do not prove injected kernel EIO, native-wrapper teardown, clean-build or
  physical-device qualification, or
  resolution of the independent promotion-blocking timeout.
  Failed `identityowner.Open` now also propagates redacted cleanup uncertainty:
  early backend closure and post-lock Owner cleanup preserve the original
  admission error plus review/unavailability instead of discarding the result.
  Confirmed cleanup retains exact errors; no new handle or retry is introduced.
  Whole isolated Linux identityowner race-count3 covers real lock retention/
  release with modeled external teardown. This is not kernel-close EIO,
  durable quarantine/recovery, new HTTP/startup or physical qualification.
  Reopened intent becomes
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
  metadata for review (including ext state not marked clean, errors, unknown
  state flags, or journal/orphan recovery indicators, independently of the
  raw clean bit); even a clean `metadata-observed` result remains
  `wd_compatibility=unqualified` and cannot authorize migration, assembly or
  mount. The host inspector's ext schema2/image-set schema3 correction has
  actual parser/CLI RED-to-GREEN evidence, complete Windows/pinned Linux tests,
  and a focused MD/ext2 QEMU consumer check using an earlier audited base.
  The orphan indicators remain bounded superblock observations, not validated
  chains, recovery, new firmware qualification or physical-disk compatibility.
  Static review of the extracted stock installer found data-array
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

**Original source/runtime join (QEMU-only):** reserve original export-root and
runtime-input handles together with full candidate matching and both parents'
Close exclusion. The separate fixed 32 MiB synthetic-source profile requires
actual mounted-set authority, normal release/FD balance and retained review
after path replacement/restoration. The finite source consumer now joins three
original roots and a read-only original volume anchor to fixed filehandle/cache
roles and actual RW/RO/denied-client NFS I/O, mapping and normal settlement.
It does not supply live policy/identity leases, sole kernel/export ownership,
complete faults or product startup/recovery. Next qualify cancellation, partial
startup/withdrawal/stop, live source loss and retained uncertain consumers, then
bind real policy/identity authorities; do not widen the generic launcher.

**Live source binding (QEMU-only):** current names are compared beneath the
original volume with original directory tuples, retaining first-cause review.
An optional separate source-loss guest requires same-payload replacement with
a real client file held open, restoration refusal, ordinary client unmount
EBUSY and retained original daemon/kernel/source/input references. Do not weaken
the single-use kernel component to run two lifetimes in one process. Client
mount EBUSY is not proof of server data-volume busy state or product quiescence.
The fixed fixture now withdraws exports/flushes caches and verifies original
kernel/daemon/group/listener stop under an independent five-second cleanup
budget after canceling its admitted request. The shutdown-only role has no data
roots and zero capabilities after setup. Original reviewed parent/client refs
remain; cached identity does not certify complete quiescence or pending I/O.
An additional optional combined source/mountd-loss guest now requires original
command exit outside its normal lifecycle, sticky daemon review and retained
kernel/rpcbind/client authorities. Cleanup must retain the actual reviewed-stop
error while a separate read-only original-owner witness verifies group absence
and retained pins, then continue stopping remaining owned resources. No generic
Stop success/release or product health is inferred. This is not a daemon-only
fault or hard-crash campaign; all earlier separate modes remain required.
Next qualify independent owned-daemon exit/partial-start/stop/close faults,
mount/device disappearance and pending-I/O cases, followed by real policy and
identity authority, protocol/reclaim and qualified boot recovery. VM disposal
must never satisfy the product settlement or automatic recovery acceptance.

**NFS input-reservation prerequisite:** the QEMU-only typed reservation now
compares the complete candidate definition/evidence and blocks parent input
closure until explicit unstarted release. Changed input state retains review
and original references. This is not a source/daemon activation backend: next
bind it to original export roots without a descriptor getter or runtime-to-
storage lock inversion, then prove real export/client I/O and fault settlement.
Equal text/revisions do not replace retained policy/identity/storage provenance.

**Session-observation producer gate:** real disposable ARMv5 evidence shows
Samba 4.22.11 can return exit zero and decodable empty sessions after a source
database open failure. The QEMU STATUS boundary now refuses unexpected stderr
without diagnostic-text matching; this does not qualify producer completeness.
Before product absence/revocation admission, reproduce init/open, traversal,
partial/malformed-record, callback and JSON failures and establish a strict
all-or-error producer result. Checking only outer traversal NTSTATUS is not
sufficient: a record callback can stop traversal while the backend returns a
nonnegative count. Preserve original complete-inventory, identity, process,
closure, descriptor and fixed-budget proofs. See the
[optional refusal probe](support/QEMU-FAST-TESTS.md#optional-samba-status-source-refusal-probe).

Session-only revocation/continuity now selects `-j -p`; the native helper has a
separate fixed verb, while tree/open-file consumers retain full status. This
does not repair discarded session traversal status. The next producer slice
must first reproduce malformed-record/callback-stop and serializer failure on
synthetic state, then make those failures explicit and all-or-error. Do not
treat normal empty JSON, source-path existence, a clean stderr or successful
outer traversal status as a completion certificate. Qualify both healthy and
faulted actual ARM producer paths before product absence authority; retain
source-scoped native/race, bounded guest, closure/FD and old-negative replays.

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
  `BuildFromLeasedNASOwners` additionally reads the original retained NAS policy
  lease, derives with the retained identity lease and mounted roster, and
  rechecks the same policy claim after the storage → identity locked work.
  The existing ARM API fixture requires commit/close fences, canceled/released
  claim refusals, equal text/new revision and sticky policy replacement review,
  with unchanged identity evidence. The helper opens/recovers no writer,
  acquires/releases no lease and returns candidate data only. Bracketed samples
  are not atomic three-owner admission, policy-Owner provenance, applied state
  or the product history/boot/service coordinator. Callers must keep/recheck
  their original authorities through independently verified settlement.
  The optional source-runtime fixture additionally borrows the original NAS
  policy/identity claims and roster at construction, verifies complete candidate
  equality before runtime reservation, and rederives around subsequent checks.
  Actual source guests use fresh RAM policy/empty identity-ledger Owners and a
  real Unix census; required receipts include released-claim/freshness/cancel
  refusals and parent-close exclusion before existing I/O/fault assertions.
  The wrapper never releases borrowed claims, and reviewed joins keep original
  references. This does not establish atomic admission, continuous in-flight
  monitoring, managed/passdb account coverage, product history/boot or a complete
  policy/identity fault matrix. Those remain required for product activation.
  Normal source execution additionally uses separate server Start/Check/I/O/Stop
  calls, keeping the original two daemon lifetimes, NFSD controller and exports
  alive between calls. The join rederives original policy/identity/storage
  evidence around running checks; a private bounded export-table observation
  detects changed identity, metadata or bytes. Explicit normal stop withdraws
  exports, verifies/stops NFSD, then mountd/rpcbind and FD/reference closure under
  one combined independent five-second budget. Old fault profiles and their
  budgets remain separate. No runtime gate spans identity/storage callbacks.
  A fixed private backend now joins the normal real-source campaign to the
  experimental Owner: original candidate/input checks, real start/check/stop,
  exclusive idle cancellation and explicit release only after fresh stopped
  observations. NFSD transactions use new descriptors beneath original controls;
  fixed RPC absence and the private export table supplement the profile. Copied
  handles/concurrent loop operations refuse, without restart or new privileges.
  The one-shot original-source QEMU constructor issues an Owner retained across
  calls; join/root gates cover each backend operation, not a whole campaign.
  Fixed synthetic I/O uses the Owner gate; remaining parent closure additionally
  requires that original Owner to be closed. An optional policy-loss campaign
  requires scheduled detection of byte-identical RAM policy replacement, actual
  verified stop, retained original claims/source references and sticky review
  after restoration, without manual detection, restart, retry or release.
  Replacement is populated outside the watched role before atomic exchange;
  no missing/partial-file window can stand in for equal-byte identity loss.
  This does not qualify the complete periodic real-server matrix, partial-start/live
  fault compensation, client quiescence, domain census or boot/recovery; those
  remain required before product service activation or persistence.
  M4.1 remains incomplete until fresh storage and identity evidence are
  collected together through production owners and native validation plus
  configuration replacement are owned transactionally before product service
  changes.
  Isolated-root preparation now retains an immutable desired SMB policy inside
  the existing Plan. `SambaShareCandidates` pairs exact source-root requests
  with `/shares/<share-id>` sections and the same NSS/freshness context. The
  renderer preserves RO/RW grants and source-overlap checks; whole-volume `.`
  refuses only this isolated path. This is candidate-only host work, not a
  completed storage/native-Samba composition. Next acceptance must acquire the
  complete roster before admission, hand off exact declared descriptors into
  the restricted native namespace, exercise real writer/reader/denied clients,
  and stop all descendants before releasing any source pin. Source loss and
  uncertain closure must retain review without fallback/restart. Storage checks
  must not recurse from backend/runtime workers into held mounted-roster locks.
  The QEMU-only handoff now retains original per-share `O_PATH` descriptors,
  gates teardown and duplicates only those originals. The actual launcher guest
  proves two RO/RW roots, caller-copy closure, effective non-root ownership,
  kernel `EROFS`, legitimate data mutation, source-loss review/restoration
  refusal and final FD equality. This is storage-side lifetime evidence, not
  Samba access or namespace containment. The focused launcher guest additionally
  admits actual healthy mounted share pins before a controlled premature
  original-FD close: repeated release/use requests preserve review, later input,
  original grant mounts and complete roster; fresh admission refuses. Independent
  exact-object fixture disposal cannot revive the lifetime or release its
  reservation. All old controls, FD equality, deadline and base hashes remain
  required. Kernel EIO/live-service close faults, durable recovery and complete
  Plan/identity/runtime composition remain required.
  Host-only real `O_PATH` release characterization additionally passes tagged
  vet/package race-count3: preclosed originals retain reviewed handoff exclusion,
  later/replacement inputs remain untouched, concurrency cannot retry and known
  closure stays idempotent. This covers the existing bookkeeping contract,
  not admission of actual mounted authority, kernel EIO or guest fault recovery;
  it does not replace the actual controlled mounted guest case above.
  A distinct fixed QEMU data profile now qualifies individual original FD
  admission, nonrecursive native clones and real RW/RO SMB transfers, Unix
  ownership, kernel `EROFS`, symlink denial and stop-before-release/FD equality.
  It uses synthetic two-root documents after the prior identity runtime closes;
  it does not consume this complete-roster pin or continuously retain identity.
  Next bind the exact desired candidate/complete Plan and SAME storage/identity/
  backend/runtime before startup, qualify effective multi-user grant/ACL access
  and source-loss/uncertain-stop retention, then complete image integration.
  The fixed data prerequisite is not M4.1/M4.4 completion. Daemon data
  handles must not broaden credential workers' configuration/state-only profile.
  A positive guarded ARMv5 admission fixture now builds the isolated candidate
  with the SAME actual identity Owner/native backend and mounted roster, retains
  both authorities, matches exact RO/RW declarations and original objects,
  closes caller copies, recompiles fresh evidence and releases in order. Desired
  round-trip/stale refusals and normal volatile-anchor restoration are checked;
  the complete local three-campaign union passes without wider limits. This
  still starts no daemon from that candidate. The next composition must keep
  management lookup distinct from granted-only service lookup while preserving
  one Owner/backend/passdb, qualify descriptor-bound native configuration and
  effective access, then supervise complete identity/storage drift and settlement.
  `Plan.SambaRoleCandidate` now supplies an inert same-Plan pair: complete live
  native management lookup (including disabled/ungranted users) and unchanged
  granted-only service lookup/grants/root requests, bound to one freshness tuple.
  Missing unrelated native census IDs refuse only the paired candidate; existing
  share-only admission is unchanged. Retired rows remain reserved but omitted.
  `SambaRoleDocumentsQEMU` renders separate bounded trees with identical fixed
  global/passdb paths and no management share sections. Host coverage includes
  missing census, zero/unsupported plans, maximum live/retired capacity, copy/order
  independence, all freshness dimensions and JSON refusal. The original focused
  ARMv5 lifecycle campaign now passes on `7614c3e`, exercising paired rendering
  against the SAME actual native Owner/mounted roster and unchanged base. The
  complete cached integration on `f40fd82` and independent 930-input source,
  configured-strip/image/export and seven-artifact audit also pass. Hosted and
  independent clean-build qualification remain separate. This does not authorize two-role runtime
  construction, native validation, service bootstrap or product activation.
  The inert retainer additionally accepts the same-Plan paired candidate and
  matches its complete management expectations against the existing retained
  management roster before pinning service configuration. Original complete late
  revalidation and daemon-start refusal remain. The native credential renderer
  now preserves the already complete files-only NSS profile without appending
  duplicate tables. Host matching and actual temporary-Owner renderer regression
  pass; original all-three ARMv5 union on `79b5229` also proves management matching
  against the actual native Owner/mounted roster and preserves original guards,
  deadlines and base. The later complete cached image/source audit extends this
  focused proof; see [implementation status](IMPLEMENTATION-STATUS.md).
  This is not two-role startup authority or a fix for PR #123's native
  outer timeout. Continue to same-state original-object construction/access,
  complete storage/identity supervision and recovery before product activation.

  A QEMU-only prepared coordinator now retains its SAME Owner/backend, original
  complete storage roster and share pins, privately copies policy and compiles
  paired roles itself. Retained identity verification and planning share ONE
  fresh complete observation under storage-first locks. Normal preparation,
  observation, policy-copy/foreign-roster refusal and runtime-close-before-
  original-release pass host/race and the complete original three-guest union.
  This is not this milestone's completion: that prepared checkpoint had NO
  planned daemon Start, product policy authority or HTTP route. Frozen `19d1891` passes the
  complete cached host/ARMv5 driver and independent exact941 source/image audit;
  hosted exact-head, independent clean and hardware qualification remain.
  New code checkpoint `8dcd541` adds normal single-use paired-role startup in
  host/disposable QEMU with those SAME authorities, freshly recompiled on both
  sides. Original-object RO/RW child views, canceled/duplicate refusal, busy
  authority, live observation and full close-before-release pass the complete
  original three-guest suite. It has no HTTP/product policy surface; the new
  normal trace explicitly claims no data transfers by this coordinator.
  Code checkpoint `e3e1d5b` additionally qualifies six fixed data clients through
  that SAME retained service: exact SMB read/write bytes, Unix ownership,
  kernel read-only and symlink/write denial, genuinely enabled ungranted
  authentication refusal and verified closure before release. Host/race and
  all four actual ARMv5 guests pass; canceled/repeated probes refuse. This is
  not a complete ungranted UNC/mixed-ACL matrix or ongoing health claim.
  The new data scenario has its own fresh enrolled snapshot after measured
  cumulative overload, using the SAME single compilation. All prior proofs,
  complete per-guest hashes, worker/readiness/180-second bounds and privileges
  remain mandatory; no retry, borrowed state or extra firmware build is added.
  Frozen `2ce88f0`/`aa88877c` additionally passes the complete cached host/ARMv5
  driver and independent exact943 package/archive/image/kernel-header/SBOM/
  legal/linked-Go audit, with every before-build source hash unchanged.
  Next qualify constructor/late-close uncertainty, broader effective grant/ACL
  access and complete drift/settlement supervision. The earlier prepared941
  own hosted run still fails; this local success is not its repair. Guest
  isolation is not a proven hosted timeout fix. All hosted/independent-clean,
  hardware and product-activation gates remain open.

  The source-restoration/Close follow-up now reproduces retained-input/original
  authority release despite coordinator review. The coordinator's reviewed
  Close admission is fenced before low-level teardown; the original actual
  fault guest requires two refused Close attempts, retained runtime inputs and
  both original busy authorities. Missing/false `close_refused=true` refuses.
  Pinned Linux vet/unit/race3, Windows API/UI/ARM cross and the actual normal
  data/close-before-release control pass. No deadline, privilege, low-level
  cleanup or recovery contract changes. This is focused correction only: new
  exact source/package/image audit, own-head hosted and broader uncertain-close/
  held-session/product recovery gates remain separate.
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
  A separate reproduced cancellation defect is corrected: a probe that returns
  ready after its context ends cannot advance the process generation. Original
  and derived monotonic deadlines bracket the callback, verified failed-start
  cleanup is retained, and only fixed context causes accompany `ErrNotReady`.
  Native/race and eight-case ARMv5 regressions pass in the existing Owner guest
  without broader timers or an extra boot. This does not repair or explain the
  intermittent Samba admission failure; exact-head full/hosted gates stay open.
  **NFS typed-input prerequisite:** `Plan.NFSv3TCPCandidate` now retains exact
  per-export/client rules and root/storage tuples with the complete Plan
  freshness, caller-independent copies and JSON refusal. Empty configured policy
  is disabled, missing/zero state refuses, and GSS never falls back to AUTH_SYS.
  Host/native planner race and actual same-Owner ARMv5 candidate checks pass;
  this supplies no mount lease, kernel authority or service activation.
  The separate [NFS runtime packet](support/NFS-RUNTIME-PROFILE.md) proposes a
  fixed-backend kernel-service Owner with policy/storage/code retained until
  verified settlement. Host/QEMU implementation is now approved. The new
  `qemu`-only lifetime captures a typed candidate and trusted fixture backend,
  serializes transitions, starts once, preserves configured-disabled state and
  retains terminal review after partial startup, drift or uncertain closure.
  Its shared six-case guest campaign is memory-only (`kernel_backend=false`),
  not retained kernel/storage/code authority or a product constructor. Thirteen
  behavior tests, pinned native race3 and the current standard ARM smoke pass;
  an earlier session-observer role-bind failure remains unexplained despite a
  later passing instrumented run. Do not expand the generic
  launcher or copy the clean-reboot fixture into a product constructor. Complete
  kernel/userspace/export/consumer shutdown, NLM/NSM and boot/recovery composition
  remain required alongside physical gates.
  Pinned source audit now identifies legacy transaction-file snapshot/EBUSY
  behavior, namespace-keyed controls and zero-thread listeners. A GET-only
  Netlink observation prerequisite can expose actual listener addresses, but
  must avoid name-based family lookup/module autoload, handle per-pool thread
  attributes and refuse incomplete replies. Source inspection is not runtime
  qualification or approval of a backend; the packet records exact acceptance.
  The read-only prerequisite now executes in the guarded QEMU fixture: complete
  non-autoloading catalogs, correlated fixed GETs, original namespace lifetime
  and the actual loopback listener identity. Native negative/race and strict
  receipt controls pass; local ARM smoke and both clean-state boots pass without
  another boot or larger budget. Receipts require `listener_identity=true`.
  This is test-only observation, not an implemented Owner, atomic census,
  complete stop proof, NLM/NSM recovery or automatic product restart.
  The existing disposable clean-reboot fixture additionally reads back the pinned
  kernel's exact version/thread/listener profile before startup, after startup
  and client I/O, and after stop. Host controls and actual three-boot ARMv5
  regression pass; strict receipts require both running profile and stopped
  readback. This is not complete quiescence, NLM/NSM recovery or a product Owner.
  The guarded reboot fixture now owns a retained NFSD kernel component rather
  than invoking `rpc.nfsd`: original network/mount/control references, fresh
  descriptor-relative transactions, one loopback socket handed to the kernel,
  exactly two threads and single-use verified stop/release. Uncertain settlement
  withholds policy/server-mount release. Native race/strict receipt controls and
  actual standard ARM plus both clean boots pass; receipts now require
  `retained_kernel=true`. This is not yet the full service backend or exclusive
  product authority; qualify retained userspace/code/storage composition and
  complete constructor/drift/close/pending-I/O/lock-recovery faults next.
  **Retained-source prerequisite:** Linux/QEMU now borrows the original complete
  roster lease, compares candidate storage, and retains per-volume pins plus
  independent `O_PATH` export directories. Parent closure is blocked while pinned;
  missing/symlink/replaced roots refuse and restoration cannot erase review.
  Native/race and standard ARM prove two requested RO/RW roots, whole-volume
  semantics and verified reference disposal, without a service or data access.
  Complete policy/identity/runtime/state handoff, consumer-stop authority and
  injected constructor/close faults remain required before backend activation.
  **Supervision prerequisite:** the NFS Owner now holds one exclusive loop over
  running/disabled state, with serial complete scans after fixed idle intervals
  and independent verified stop on accepted idle cancellation. Drift/admitted
  cancellation/uncertain stop retain authority and review without restart.
  Native behavior/race checks and standard ARM bind automatic directory-loss
  detection to original mounted-roster pins, but only a synthetic consumer.
  Complete real-daemon/kernel fault supervision, retained policy/code/state and
  automatic boot recovery remain required; do not treat model stop as quiescence.
  **Userspace code expectations:** one inventory now produces a bounded union
  for the three current fixture programs, and a strict QEMU-only consumer builds
  the existing code Plan. Actual cached Buildroot metadata (9objects/12bindings)
  reaches that consumer under pinned native race3; no inspected ELF executes.
  Next stage the closed code-only tree independently from mutable state/data,
  retain original read-only code/alias identities, verify actual ELF/loader/NSS/
  module requirements and constructor/drift/close faults, then compose a dedicated
  NFS launcher. Do not broaden the static launcher or reuse Samba privileges;
  unsigned expectations do not qualify provenance, NLM/NSM or product admission.
  **Retained-code prerequisite:** an explicit diskless ARM fixture now stages
  the actual9-file set in protected tmpfs and retains original code/root/namespace
  identities. Normal closure/FD balance, constructor rollback (including a
  hash-correct non-ELF file) and byte-identical overmount/restoration review pass.
  Host receipt transport/counts are strict. The same isolated guest now also
  executes the actual loader's fixed list-only mode for all three programs,
  through an unchanged static launcher/non-root observer in the retained root.
  Complete per-entry graph/union matching, original code/namespace/root fences,
  verified child stop/reap and FD balance pass; no daemon entrypoint runs.
  Qualify remaining symbol/NSS/module/ISA requirements and namespace/close faults,
  a descriptor-bound dedicated launcher and verified consumer settlement next.
  This QEMU-only collector is not product privilege/provenance or exclusive NFSD
  authority, and it does not implement normal/unclean boot recovery.
  **Configuration/state prerequisite:** the guarded input constructor now binds
  nine independently rendered configuration documents and two original fresh
  mutable directories to retained code under the same private gate. Native/race
  and actual ARM prove rollback/nonfresh refusal, mutable atomic file replacement,
  normal FD closure and separate configuration/state replacement review after
  restoration. An explicit final EOF fixes the first real constructor regression.
  This supplies no sole-writer/role/source authority, actual NFS config/NSS or
  state-format verification, product persistence or daemon privilege choice.
  Next construct the dedicated service view/bootstrap from these SAME inputs
  with policy/identity/source/kernel authorities and verify actual startup,
  I/O and all consumers' settlement; preserve ordinary unclean-boot recovery.
  **Finite real-consumer prerequisite:** the guarded ARM lane now executes
  retained `exportfs -s` against populated/empty synthetic etab controls under
  the original input gate. Detached descriptor-derived mount clones are prepared
  before namespace change, then attached to the private fixed view; no source
  path fallback or generic-launcher widening. Actual constructor rollback,
  close exclusion, unchanged table, verified group/FD closure and all previous
  proofs pass. Root/capability-zero is a fixture profile, not product admission.
  The old secinfo rendering mask omits `secure` without kernel export features;
  retained input still requests it, but listing cannot attest kernel enforcement.
  Next qualify actual exports/config parsing, rpcbind/mountd and real NFSD/source/
  identity/policy/state ownership together, complete stop/faults and automatic
  ordinary unclean-boot recovery. Never infer complete service stop from PID exit.
  **Real rpcbind prerequisite:** the original-input guarded ARM fixture now
  starts one foreground rpcbind, verifies accepted NULL RPC, actual UID/GID1,
  zero effective/permitted caps with only three startup bounding bits, original
  code/private view and positive PID/listener binding. Group/listener/FD closure
  passes before known fixture-leaf cleanup; all old proofs stay mandatory.
  The pinned TCP path ignores `-h`: require its exact wildcard profile only with
  lo as sole UP interface and a NIC-none guest. Product address/interface policy
  remains unqualified; do not copy this fixture's network or privilege choice.
  **Real mountd/channel prerequisite:** actual foreground mountd is now composed
  within that same original gate and live rpcbind lifetime. Exactly three
  original kernel cache-channel O_PATH references feed fixed private file mounts;
  metadata collection never consumes kernel messages. Require actual O_RDWR FDs
  bound to the original identities/private mount IDs, accepted MOUNTv3 NULL,
  owned PID/listener, UID/GID0/caps0/NNP and verified group/listener/FD settlement.
  Unknown output refuses. Uncertain mountd settlement retains rpcbind/inputs.
  The real ARM regression catches proc-network forced revalidation invalidating
  retained source dentries; check held metadata without named source rewalks.
  This is not fresh named-registry completeness or kernel sole ownership.
  **Retained NFSD composition:** the same original daemon/input/channel lifetime
  now encloses the concrete retained kernel controller: two threads, original
  loopback TCP/2049 socket, accepted NFSv3 NULL, exact profile and live original
  daemon observations. Verify kernel stop/refused connection/FD closure before
  daemon teardown; uncertainty retains both daemon chains. One shared QEMU-only
  implementation preserves the old reboot wrapper's synthetic-disk guard.
  Fragmented startup notices are pending only within the existing readiness
  budget; unknown output refuses. No general launcher/privilege expansion.
  Next compose complete original domain/export/source authority, actual data/permission
  access, full stop/fault coverage and normal/unclean automatic recovery before
  activation. Do not infer exports, complete backend or a product privilege design
  from this root/capability-zero, lo-only/NIC-none fixture.
- **M4.3 — Access semantics.** Specify SMB3 grants and denied cases; keep SMB1
  disabled. Support explicit NFS client/network rules, export paths and numeric
  identity/squash policy. NFSv3 compatibility has guest evidence; NFSv4 is a
  separate protocol/identity/recovery qualification, not an assumed feature.
  **M4.3a — export identity continuity:** the Linux combined/NAS stores now compare
  consecutive committed policies under the original store lock after CAS and
  before pending-file operations. A retained export UUID must keep its logical
  VolumeID, expected filesystem UUID and relative root. Pure operation preparation
  applies the same check before operation-ID allocation/intent admission. Access
  changes, additions/removals and a genuinely new export ID remain valid desired
  edits. Refusal must preserve current/pending evidence and a healthy Owner.
  This is not a permanent registry: before product activation, persist complete
  binding/retirement history in the single authoritative configuration with
  explicit schema migration. Qualify removal/reappearance across multiple edits,
  reboot, restore, rollback/checkpoint changes, missing/ambiguous history and
  interrupted migration. Bound resource use without silently dropping retired
  IDs or treating absent history as permission to reassign them. Preserve source
  identity independently of bay/path and require separately qualified consumer/
  filehandle handoff. No adjacent-revision check completes this release gate.
  Management must distinguish this known pre-effect rejection from I/O or an
  uncertain save, with a redacted actionable response and no automatic retry.
  The development adapter now returns a known422 refusal, with real-store
  unchanged-policy/no-pending tests and HTTP/HTTPS guest proof in both clean
  boots. Corrupt current state remains503 on GET and PUT. The browser retains
  rejected drafts only after a complete bounded fixed reply and requires fresh
  preview; unknown outcomes retain reconciliation/no-retry. This does not close
  permanent retirement, product recovery or live service admission gates.
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

  Retained runtime-input release acceptance: after verified process absence,
  the first descriptor-close failure must remain observable on every later
  Close, stop releases of all not-yet-attempted inputs and keep runtime review
  without retry or restart. Successfully closed inputs remain released; the
  errored descriptor must not be assumed open. Code, management/service
  configuration, mutable state and executable pins require negative coverage,
  including replacement noninterference and later-role retention. Already-
  closed-file Linux regressions pass, as do separate normal static Owner/all
  three Samba ARMv5 campaigns. Complete cached integration and exact926-source/
  package/archive/configured-strip/image/export/seven-hash audit also pass.
  Native QEMU-wrapper terminal cleanup/error-state propagation remains a
  separately identified gap with a host-tested isolated follow-up. Actual guest
  fault injection, kernel I/O failure semantics and durable recovery remain
  open gates; these tests do not complete M4.4 or qualify a product runtime.
  Current native-wrapper close faults have fresh host RED/GREEN and race/vet
  proof on `3ffb811`; its original all-campaign replay passes service/native
  but lifecycle reaches outer180s. A temporary timing replay passes without
  proving the cause or resolution; it is removed. Optional bounded diagnostic
  JSON log output now preserves successful/failed fixture observations before
  cleanup, without modifying guest execution or acceptance. Reproduce/diagnose
  the intermittent timeout before current full-image/hosted qualification.
  The private worker boundary additionally retains only the first fixed
  phase/reason diagnostic, preserving review and internal cause inspection
  without exposing underlying output or secrets. Its gated observer must remain
  read-only after closure and refuse canceled/busy calls. Host-only bookkeeping
  and ordinary-adapter redaction tests pass; guest reports are diagnostic-only.
  Frozen `a257104` passes the original focused lifecycle and all-three ARMv5
  union, with all guards/deadlines and base hashes intact. No failure telemetry
  fires: qualify the failure path separately and reproduce/classify any timing
  failure before claiming its cause or resolution. Logging and positive normal
  execution alone are not a timeout fix, retry policy or product recovery.
  A later live-daemon guard fix preserves retained-tuple/bootstrap/process
  observation causes behind generic review-only text instead of discarding
  them. Public negative RED/GREEN, fixed-label redaction, pinned non-root
  Linux two-package vet/tests/race3 and ARMv5 compilation pass. The original
  focused lifecycle still fails peer-continuity45.125302s without CPU stress;
  keep that gate open. No timeout/authority/privilege/retry change is included;
  actual failed-worker classification and complete integration remain separate.
  A separate deterministic native-adapter inner-close regression now uses the
  real post-runtime step rather than a fabricated healthy runtime. It fails
  when repeated public Close forgets the original file error and passes with
  terminal first-error retention, operation fencing and replacement isolation.
  Focused host race3, root module tagged vet/five-package race3 and Windows
  preflight pass. Frozen `fdef51d` also passes the original all-three ARMv5
  union with unchanged guards/base/bounds. Actual runtime-close faults,
  complete changed-image/audit and durable recovery remain separate gates;
  the positive union does not identify the intermittent-timeout cause.
  A follow-up extends that terminal fence to the native session-pair and
  peer-continuity status reader, including the inner backend and pre-canceled
  admission. Real-file/canceled command-boundary RED/GREEN, pinned Linux tagged
  vet/tests/race3, Windows preflight and the actual ARMv5 native campaign pass.
  No worker is dispatched on the new refusals. Normal valid session parsing,
  complete runtime revalidation and all deadlines are unchanged. This remains
  focused qualification, not an uncertain runtime-close fault, full new image
  or the separate coordinator-timeout fix.

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
  The [Samba Owner packet](support/SAMBA-RUNTIME-PROFILE.md#samba-specific-owner-integration-packet-hostqemu-scope-approved)
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
  The internal digest calculation also refuses cancellation after the last
  pre-read check/EOF/finalization with zero digest/count. Three deterministic
  boundary cases reproduce the old result and pass after correction; pinned
  non-root Linux tagged vet/tests/race3 and ARMv5 test cross-compilation pass.
  Full byte/census/metadata/identity checks and budgets remain unchanged.
  `Inspect` already checks context before returning; no admission bypass,
  QEMU timeout fix, new guest or whole-image qualification is established.
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
  **Original-instance lifecycle fence now host/ARM-qualified:** both static and
  guarded Samba Owner constructors bind pointer identity. A native real-reference
  RED reproduced copied Close releasing original pins; real-constructor ARM RED
  admitted copied Start to the shared process set. Copies now refuse every
  lifecycle operation before gate/process/reference effects, even copies predating
  original review; pointer aliases remain valid. Existing static guest requires
  both copy-refusal flags and preserves all earlier proofs, without another guest
  or timer increase. Tagged unit/vet/race3, Windows,58 runner controls and separate
  Samba service normal-path/replay pass; no product activation or complete-image
  qualification. Adjacent handle types need their own copy/ownership audit.
  **Remaining constructor rollback ownership packet:**
  First slice implemented: local opaque review handles travel in original error
  chains, not a global latch or a healthy partial Owner. Code preparation and its
  static/configuration/Samba/pending/observer composition preserve nested review
  before unrelated cleanup. Actual static construction has a terminal single-FD
  seccomp `close -> EIO` regression; GC reachability, no retry, original causes/
  caller, independent subsequent rollback and bounded normal cleanup are checked.
  This is a pre-scan/no-child fault, not physical EIO or complete qualification.
  Retain the original error explicitly; string conversion loses ownership. The
  terminal test command retains it until exit. Product composition and remaining
  acquisition/temporary-close families are still prerequisites.
  Final serial native/tagged race3 and58 driver controls pass; unchanged120s ARM
  static guest requires nine constructor PASS rows in addition to all old proof.
  Separate normal Samba service/complete-log replay passes. One preceding
  parallel native run missed an unchanged one-second process probe wait; no
  intermittent-timing, complete-image or hosted repair is inferred.
  Cross-package slice: shared acyclic `constructionreview` classification now
  propagates opaque pinned/capture construction failures into containing owners.
  Actual lower-factory close-EIO tests cover outer rollback, read-only/executable
  validation and capture input failure; a real lower factory plus containing
  rollback boundary verifies retained parent references and both domain causes.
  That parent fixture is not successful bundle admission. No global latch,
  backend/descriptor injection, product startup or new live-service authority follows.
  Focused follow-up corrects the failed-start test's unsupported assumption:
  group absence alone is not original Wait completion. Deterministic real-I/O
  RED, full selected native/race3 and static ARM pass after explicit same-Wait
  observation; product process code unchanged, exact historical cause unproven.
  Approved coherent peer/absence inventory replaces only ordinary-native's
  adjacent post-revocation captures. The earlier ARM attempt fails BEFORE that
  path in a4s Disable-status worker, with25.94s parent remaining. Subsequent
  QEMU-only capture cost instrumentation and four-package native/race3 pass;
  actual focused native ARM plus independent replay now passes the coherent
  observation/fresh-login/data/closure proofs under original limits. This is not
  a historical timing repair or full/hosted/product qualification.
  **Required producer-completeness gate:** cached Samba4.22.11 source review
  finds discarded `sessionid_traverse_read` NTSTATUS in
  `source3/utils/status.c`. Successfully decoded JSON is not proof that every
  source record was traversed. Reproduce initialization, traversal/record decode,
  callback/serialization and partial-result faults using disposable state;
  require explicit failure with no accepted partial/empty absence result.
  Trace propagation through `sessionid_tdb.c`, `smbXsrv_session.c` and dbwrap;
  checking only the top status may miss callback-stop semantics. This is a
  static finding, not a reproduced binary failure. Qualify a bounded producer
  before any product revocation/absence authority. Do not adopt processes-only
  flags as a timing fix without equivalent complete-session/error coverage.
  - Audit `prepareRetainedCode`, ordinary/Samba Owner construction, configuration
    retention, pending-input composition and pinned-process construction. Record
    exactly which original/temporary/independent references exist at each failure;
    do not infer whole-lifetime safety from release-helper unit tests alone.
  - Apply the selected local no-child rollback versus retained-review contract
    to remaining families. Preserve original construction and cleanup causes;
    never return a healthy handle, silently drop partial ownership, retry uncertain
    descriptor closes or use garbage collection as the recovery protocol. Any
    opaque error handle requires explicit caller retention; no unbounded global
    orphan registry or implicit service restart.
    Extend the now-shared acyclic retention contract to remaining directory/state
    and temporary-close families. Never reverse `runtimebundle` -> `processowner`,
    inspect error strings, treat classification as execution authority or lose
    foreign review. Preserve both domains' causes and original error ownership.
  - Update every affected caller, including configuration/Samba wrappers and QEMU
    commands, to honor that contract. Partial preparation must not be revalidated
    into execution authority. Normal refusals and verified cleanup remain bounded
    and descriptor-balanced; caller-owned references are never consumed.
  - Add deterministic real-file fault controls at actual constructor rollback
    boundaries, then guarded RAM-only ARM tests with original-reference/cause
    checks. Retain unattempted originals where the contract requires review, verify
    reachability across collection, and prove no launch/retry or substituted-object
    close. Already-closed-file fixtures are not actual kernel EIO qualification.
  - Keep all existing healthy static/Samba proofs, profiles and worker/guest bounds.
    Do not open listeners, adopt product storage or enable web activation to make
    constructor tests pass; durable recovery and product composition stay separate.
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
  The QEMU-only native worker now checks the original context at its final
  result decision, after settlement/closure, post-admission and diagnostics.
  Late cancellation/expiry refuses output, preserves review/first failure and
  existing error precedence, without retry, extra admission or new deadlines.
  Real seam RED2, Linux vet/unit/race3, Windows and three ARM seam cases3 pass;
  the unchanged strict actual native Samba campaign passes separately. This
  point-in-time seam proof is not real admitted-worker fault injection,
  pending-I/O, a hosted timing fix, new complete image or product activation.
  **Dedicated pending-client handoff prerequisite, host/QEMU only:** a new fixed
  helper (not the generic/root launcher) accepts original RO root/program FDs
  and four independent anonymous pipes. It clones before mount-namespace
  separation, drops all UID/GID slots to65534/groups/caps and sets no-new-
  privileges before original-inode exec. Real Linux descriptor controls and a
  static synthetic ARM probe pass; malformed inputs refuse and group absence
  precedes original-reference release. Exact receipt negative controls pass.
  A separate guarded ARMv5 input probe now constructs and retains complete
  original client/library/loader/config/model and bootstrap roots, using
  independently expected hashes and the existing immutable code contract.
  Complete rechecks, wrong-hash/partial-cleanup/canceled/released refusals,
  independent caller closure, exact receipts and final FD/base equality pass.
  It starts no process; this is not actual libsmbclient execution,
  request/extent binding or pending-I/O qualification. A private serialized
  containing Owner now binds these complete original inputs to the dedicated
  adapter; full rechecks fence start/close and adapter settlement must precede
  complete input release. Its actual ARM never-started constructor/closure,
  partial rollback, independent caller closure, copy/cancel/busy/released
  refusals and FD/base equality pass. Host vet/unit/race3 and ARM cross pass.
  The separate optional `pending` guest now executes that real client against
  a freshly enrolled retained native data server: one pre-existing synthetic
  object OPEN/CLOSE, no WRITE. Actual loader execution, unchanged retained local
  object/bytes, client exit0/group absence, daemon stop and FD/base equality pass.
  Missing dynamic CP850 inputs and caller/target large-file ABI have RED/GREEN
  guards. Only the new client startup is calibrated12s after measuredOPEN5.557s;
  CLOSE5/parent35/guest180 and the existing ten-campaign union remain unchanged.
  This is focused healthy execution, not full-image/hosted or product proof.
  The new guest also requires two independent original server-side STATUS
  snapshots with unchanged server generation/session/tree/share-file ID,
  retained worker proc/start ticks, daemon parent/group, original smbd and
  matching original local metadata/device/inode. Actual ARM acceptance and
  Linux/race3/Windows controls pass. Separate native/planned service-name and
  client access-mask contracts have RED/GREEN guards; older observers stay
  unchanged. Complete runtime admission still brackets each fixed worker once;
  redundant new-observer scans are removed without deadline changes.
  The same optional guest now qualifies the original owned client/worker TCP
  connection: client proc/start/parent/group captured before Wait, retained
  net/mount namespaces, executable/fixed credentials, complete bounded FD
  censuses and reciprocal inode/cookie/principal/endpoints; same-reference
  checks and both verified stops precede release. Complete input/server/object
  fences remain, with a one-second query cap and all existing parent limits.
  Actual ARM healthy binding, strict mandatory receipts, original bytes/FD/base,
  Linux vet/unit/race3, Windows and15 ARM TCP cases3 pass on1326 frozen inputs.
  The optional `pending-peer-exit` guest now qualifies deliberate verified peer
  stop after the real binding: concrete adapter refusal/verified client group
  stop, containing review, refused client CLOSE/start/rebind/repeated release,
  original proc/namespaces/complete client inputs/server code/helper/local file
  retained until private subprocess disposal; unchanged bytes and parent FD
  equality. Actual fault and healthy ARM regressions, tagged host vet/unit/race3,
  Windows and strict controls pass on1329 unchanged inputs/base. Defaultten and
  existing deadlines are unchanged. Other live drift/uncertain teardown in the
  new composition remain unqualified; sequential observations are not atomic
  or continuous. This is not
  the opaque SMB handle/request witness: `smb_object_bound=false`/`pending_io=false`
  remain required. Next qualify remaining composed fault controls, then the original
  handle and request/extent/cache/journal
  before any WRITE or pending-write fault. Keep ID domains separate: pinned
  Samba's STATUS `share_file_id` is a file-handle
  generation, not either CREATE persistent/volatile FileId. An original client
  mapping and independent same-server-open bridge are still required; see the
  [source-backed handle prerequisite](support/QEMU-FAST-TESTS.md#remaining-original-handle-witness).
  A separate source-built reader now passes actual ARM mapping/IDR controls
  (36 refusals and fnum reuse), using real pinned private definitions and one
  exported symbol. The positive connection getters are mocked; loaded DSO
  early-refusal checks are real. Strict receipts, inserted bytes and base hashes
  pass. An optional close-only client build now observes its original context/
  file after OPEN/stat and before CLOSE, validates bounded IDs and fieldwise
  continuity, and refuses all writes. Sixteen observer/identity/auth refusal
  mocks, exact ordered notices, old-client regressions and ARMv5 compilation
  pass; a fixed reader SONAME excludes scratch dependency paths. The separate
  `pending-handle` guest now executes the actual client with complete retained
  module/loader inputs, a constructor-fixed adapter and bounded initial-tuple
  cache/parser. Its original session/tree match independent STATUS, with original
  process/namespace/TCP/server/local-object rechecks before CLOSE, unchanged data
  and verified both-group disposal before release. The old `pending` regression
  also passes; no default-campaign change. Independent closure rejection corrected
  RPATH to genuine RUNPATH; real `DLIST_ADD` RED/GREEN corrected singleton `prev`
  from NULL to self, with ten pinned sensitive source hashes.
  The remote persistent/volatile FileIds are still not independently bridged to
  the server's share-mode file generation. Next qualify that same-server-open
  bridge and composed negative controls, then request/extent/cache/journal before
  WRITE or any proof flag change. Initial metadata is cached, not a live lease;
  sequential checks are not atomic or continuous. Keep review
  and original references on uncertainty; no generic-profile/idle-observer
  widening, product startup, HTTP or physical NAS action.
  A separate server-side source reader now copies both remote IDs and share-mode
  generation from one pinned files_struct, including worker/session/tree and
  real-descriptor device/inode checks. Actual ARM source and loaded DSO run 66
  refusals with real upstream getters/list/fstat; open/tree records are synthetic.
  Sixteen sensitive source hashes, ABI/import/SONAME/RUNPATH guards and strict
  base/receipt controls pass. This is not the active-worker bridge. Next bind a
  dedicated retained producer/metadata channel and capture the actual original
  worker opening before comparing the client/server/local-object tuple; preserve
  all existing fences, refusal/review, fault and pre-WRITE requirements.
  Pinned lifecycle analysis requires `is_fsa` for a normal file, but neither that
  flag nor CREATE_FILE returning success proves the final SMB response. Capture
  must be admitted only after independent original-client OPEN success, while
  the original file remains open. Do not use VFS CLOSE for the second sample:
  SMB2 sets `closing` first. Do not inherit the old synthetic child's parent-PID
  check: a real worker is forked by smbd, not directly by the socket creator.
  See the [server reader prerequisite](support/QEMU-FAST-TESTS.md#server-side-original-open-reader-prerequisite).
  Its optional private wire lane now proves explicit C-to-Go ARM framing,
  bounded capture, sequence/refusal controls and separate all-field comparison
  to synthetic client/STATUS metadata. Host race3/10000 fuzz and standalone/ARM
  regressions pass; raw IDs do not enter receipts. This is not authenticated
  worker provenance or global replay/lifetime authority. Next implement a
  dedicated admitted VFS producer/channel, retain its full original code/root/
  transport authority, then capture and compare the actual same opening with
  existing process/namespace/TCP/local-object fences and fault controls. No
  generic launcher widening, Owner activation or WRITE in this prerequisite.
  [Wire contract and exact command](support/QEMU-FAST-TESTS.md#server-open-private-wire-prerequisite).
  A private sequenced-packet prerequisite now passes host and actual ARM tests:
  original endpoint/option/cookie checks, per-packet kernel credentials (not
  creator credentials), two ordered equal records, extra-output refusal, sticky
  review, exclusive calls and unchanged FD counts on ancillary refusal. A fixed
  synthetic C producer inherits only its fixture FD3 and settles before close.
  It is NOT an admitted VFS worker/producer/code lease or live-generation proof.
  Private release bookkeeping now closes endpoints sequentially, retains the
  first terminal result and never retries or touches replacement fields after
  that result. Real-file regression controls cover premature closure at this
  private boundary, healthy public closure and refusal before release; they do
  not inject kernel EIO or qualify live-worker close uncertainty or recovery.
  Actual ARM credential-domain controls distinguish automatic real IDs from
  explicitly supplied effective/saved IDs accepted by the kernel even with zero
  effective/permitted/inheritable capabilities. Neither proves Samba account
  authorization. Preserve independent retained producer and identity admission;
  qualify the producer's fixed credential context before interpreting packets.
  Next qualify dedicated server descriptor handoff and complete producer authority,
  then bind actual worker observations under all original lifecycle fences. Do
  not infer active-worker, global replay, pending-I/O or WRITE qualification.
  The private fixed-producer status observation is now consumed by a separate
  original-object composition in the explicit `file` guest. A fixed authorized
  client opens one existing synthetic file once, without create/truncate/reopen.
  The service retains the original O_PATH object through its original share
  root and matches device/inode plus complete session/tree/server/open identity.
  Exact configured producer name `Writable` is calibrated, not case-folded.
  Complete original storage/identity rechecks precede and follow admission and
  recur under the same exclusive serialized supervisor. Accepted cancellation
  verifies client/daemon group settlement while the object,15 inputs and both
  authorities remain held until full runtime Close. Repeated-close/closed
  refusal and FD/base equality pass in an actual cleaned-source ARMv5 guest.
  Root/non-root vet/race3, Windows preflight and ARM cross-compilation also pass.
  The fixture omits only a measured duplicate pre-supervision Observe, retaining
  Start's post-admission and supervisor's complete rechecks and all prior limits.
  The focused proof alone does not imply a current full image,
  hosted failure repair, in-flight work, durable reconnect or product safety.
  The separately qualified idle-open-file alias-loss proof below does not
  qualify in-flight faults or uncertain teardown.
  The private original-session-pair recheck prerequisite now passes root-isolated
  host race-count3 and a focused actual ARMv5 native campaign. It requires the
  same complete pair before target-only revocation, refuses the old pair afterward
  and distinguishes validated inventory change from command/parser/deadline
  failure. All old same-peer/access/stop/FD/base guards and session45/guest180
  remain; the two new proof fields are mandatory in the 66-test driver.
  This is NOT a composed-storage held-session fault, retained data handle,
  in-flight/durable reconnect, complete changed image or recovery qualification.

  The composed held-session source-loss packet now passes all seven fresh
  ARMv5 overlay guests plus root/non-root host checks. The SAME original
  service retains one fixed authorized client; the enabled ungranted account
  stays excluded. Complete original-session observations precede the alias
  cover. Client and daemon stop/reap; originals and all15 private daemon inputs
  remain retained. Old observers refuse the additional group and restoration/
  repeated Close cannot revive or release review. Parent FD equality and base
  hashes pass. All1,260 witnesses match; existing startup40/data20/supervision20/
  child90/guest180 and worker limits remain.

  **Normal held-client retirement qualified, host/QEMU only:** the SAME fixed
  authorized holder passes accepted idle cancellation and normal full runtime
  Close in a NEW separately enrolled `held` guest. Original session, identity/
  backend/complete mounted roster and RO/RW grants remain; the excluded account
  is not admitted. Both group absence/reap and unused two-client gen0 census
  precede retained-input release; all three older observers refuse the extra
  group. BOTH original authorities stay busy until full runtime Close. Repeated
  healthy Close, closed-observer refusal, final FD equality and base hashes pass.
  Root/non-root vet/tests/race3 and all EIGHT actual ARMv5 overlays pass on 1,263
  unchanged inputs (970 API inputs), with 67 verifier tests and all prior proofs/limits.
  No new privilege, image/volume, HTTP or physical-device action is introduced.

  **Original-open-file source-alias loss qualified, host/QEMU only:** the
  mandatory `file-source` guest reuses the original data opening, object/session
  witness and complete exclusive supervisor. Actual source cover leads to
  verified whole client/daemon stop, with the file, 15 inputs and BOTH original
  authorities retained in review. Removing the exact cover and repeating normal
  Close cannot revive/release authority. Parent FD/base proofs and all ten
  independently enrolled ARMv5 overlays pass on 1,270 frozen inputs (977 API
  inputs), with independent actual-log/every-source replay and 71 verifier tests.
  No timing/guard relaxation or physical disk action; changed full-image/archive/
  SBOM audit and own-head hosted qualification remain separate.

  **Next bounded host/QEMU packet:** complete read-only construction/lifetime
  and late/uncertain-close fault coverage under the existing retained Owners.
  Keep idle IPC$, actual-open-file, completed READ and pending-request proofs
  distinct. Do not repeat the basic client retention/launch work as though it
  were absent: complete client/bootstrap construction and the dedicated Owner
  already exist; optional ARM fixtures exercise OPEN/CLOSE, independent server
  snapshots, original process/namespace/TCP binding and a separate peer-exit
  fault. These are scoped observations, not complete lifetime qualification.

  Distinguish the executable variants before extending them. The generic
  `samba-pending-write-fixture.c` program opens O_RDWR, but its containing Owner
  exposes only OPEN/CLOSE; the WRITE branch remains host-mock/ARM-compile
  evidence, not an executed WRITE experiment. The handle-observer build compiles
  WRITE out but still opens O_RDWR: CLOSE-only behavior is not an O_RDONLY FD.
  The separate capture client opens O_RDONLY and has fixture-tested two one-byte
  READs, same-open VFS metadata matching and selected between-request faults.
  Its O_PATH object pin is not a duplicate worker open-file description or a
  pending-request lease. None of these variants authorizes product activation.

  The first constructor-backed pre-close packet passes host checks and actual
  ARM in the optional complete-input guest: a normally closed owned code file
  causes mismatch/review, preserves unattempted originals and refuses repeated
  operations with a stable reviewed FD count. The separate helper retains the
  reviewed Owner until process exit; init verifies exit/reaping and equal parent
  FD counts. All old proofs and the 60-second guest bound remain. No client/server
  runs; this is not kernel EIO, guaranteed FD reuse or launched teardown.
  A reproduced cause-loss defect is corrected in this private Owner: repeated
  review refusals retain the original cause and stop/release uncertainty without
  further adapter work. Host/race and actual ARM require cause preservation;
  this does not qualify late syscall failure or a product lifecycle.

  Remaining tests must reach the real containing lifecycle without a forged healthy
  Owner, per-operation backend replacement or new privileges. Preserve original
  errors and unattempted pins after uncertain close, verify owned-group absence
  before release, and refuse restoration/retry/restart in review. Qualify the
  original worker OFD/request and outstanding extent/cache/journal semantics
  before any separately reviewed pending-I/O/WRITE experiment. No such WRITE
  experiment is approved by this roadmap update. Do not widen the root helper
  or relax the idle observer. See the
  [bounded prerequisite check](support/QEMU-FAST-TESTS.md#dedicated-same-open-client-prerequisites-host-and-qemu).
  Require
  evidence that the actual original handle is open under the retained authorized
  session before fault injection; a successful earlier transfer or IPC$ echo is
  not sufficient. Never substitute a new login, backing object or backend.
  Verify whole-group settlement before any release; uncertain results preserve
  the first error, review and authority without retry/restart. Do not infer
  durable reconnect, data integrity or recovery from idle-session coverage.
  Hosted source-child data failures still need an exact-head local feedback
  loop and a causal fix before promotion; local green is not one.

  The fixed operation/worker-stage feedback seam now passes root/non-root
  host/race and all seven actual ARMv5 overlays on1,262 unchanged inputs.
  Private data-error wrappers preserve existing error/review semantics;
  only allowlisted operation/phase/reason rows survive diagnostic relay.
  Unknown labels, secrets and diagnostic-contaminated success proofs refuse;
  child-output1,024 and all existing deadlines remain unchanged. Guard/coordinator
  failures stay coarse. This improves the feedback loop only: no intermittent
  failure was reproduced or causally fixed. The normal held-retirement packet
  above adds a distinct qualification, not a hosted-failure fix.
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
  **M5.2a — plaintext listener admission (partial; locally tested):** require
  both the actual configured listener host and public-origin host to be loopback
  before permitting HTTP. A loopback origin previously admitted a concrete
  external listener without TLS; two RED reproductions precede the minimal
  guard fix. Sixteen IPv4/IPv6/name/wildcard/port controls preserve supported
  loopback HTTP and existing HTTPS tests. Windows API/UI/vet/ARM cross and pinned
  Linux whole API vet/unit/tagged-vet/proc checks pass. Actual single-boot ARMv5
  overlay executes four negative guards before the unchanged TLS fixture and
  preserves default smoke/base hashes. No external socket is opened by those
  checks. This is not product certificate provisioning, LAN deployment, complete
  image/SBOM, physical support or its own hosted qualification.
  The [management threat model](src/phantowd-api/THREAT-MODEL.md) maps current
  routes/trust boundaries, TM-01–TM-10 acceptance packets and remaining product
  gates. It is a source-based draft, not an independent security sign-off.
  **M5.2b — bounded supplied TLS material (partial):** read certificate/key PEM
  through checked open files, with inclusive256/64KiB input bounds and zero
  transport result on refusal. Both leaves must be regular and non-symlink;
  Linux no-follow/nonblocking opens and metadata rechecks preserve POSIX key
  permissions. The standard HTTPS fixture adds oversized valid-prefix refusals
  before its listener. Windows/pinned Linux whole checks, focused race-count3
  and one normal ARMv5 smoke pass. This is not retained parent authority, all-change/low-
  level I/O-fault coverage, an I/O deadline, whole-TLS memory qualification,
  certificate provisioning/renewal or product LAN admission.
  **M5.2c — kernel-checked supplied TLS paths (partial; host Linux):**
  use `openat2` whole-path no-symlink/no-magic-link resolution, with no weaker
  fallback on a missing/denied syscall. Preserve readonly/nonblocking/CLOEXEC
  and ARM32 large-file flags; require real regular-file paths rather than parent
  symlink aliases. Pinned native whole API/vet/race passes eight cert/key alias
  refusals, leaf-only comparison controls and ordinary relative/descriptor tests.
  This is not retained parent/mount authority, all replacement/close faults,
  certificate provisioning or ARM execution; qualify those before product use.
  The latest Windows full wrapper has an unexplained tagged HTTPS/iSCSI transport
  failure despite50isolated passes. Do not substitute those passes for repair.
- **M5.3 — Typed operation API.** Map privileges and state transitions to endpoints.
  Preserve strict decoding, origin/Host validation, CSRF, bounded requests,
  generic errors and per-operation concurrency limits. Long jobs return durable
  identity/status; cancellation must distinguish requested from actually stopped.
  **M5.3a — exact credential JSON (partial; local host/ARM verification):** setup/
  login reuse the existing bounded Unicode/duplicate/exact-key envelope instead
  of a parallel recursive scanner. A case-alias request previously enrolled an
  account and issued a cookie (two HTTP REDs); the decoder now refuses before
  credential operations. Fifty-two malformed HTTP cases retain account/session
  state; Unicode, paired escapes, literal U+FFFD, escaped canonical keys and
  inclusive 2 KiB controls preserve credential bytes. Unknown-length excess
  input is bounded without trusting Content-Length. Existing body/rate/KDF/
  origin/session limits and persistent formats remain unchanged. Windows and
  pinned Linux preflight and actual one-boot ARM overlay pass; the HTTPS fixture
  refuses two setup requests before canonical enrollment without altering login
  quota. Source/base/probe hashes agree and scratch is discarded. This is not
  current own-hosted/full/two-boot/SBOM, browser or product qualification.
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
  **M5.4b — desired-policy backup and reviewed restore (partial; locally tested):**
  explicitly load current state, download an initialized private SMB/NFS backup,
  or select one bounded versioned file. Validate original bytes server-side,
  require the observed expected revision and rebase every policy revision only
  after strict validation. Review the whole replacement with M5.4a and require
  the existing explicit CAS Save; preview never commits. Preserve auth/CSRF,
  shared request admission, deadline/session lifecycle, stale-writer refusal and
  uncertain-write reconciliation without automatic retry. Backups contain private
  names/networks/UUIDs but no credentials, native accounts, iSCSI or user data;
  restoring references does not provision users or qualify volumes. Windows/DOM,
  pinned Linux tagged/race-count3 and actual ARMv5 HTTP/HTTPS standard/two-boot
  overlay pass on frozen source. Complete terminal guest-log replay, real-browser
  qualification, production persistence/provisioning/service composition and
  recovery remain open. This is not the M5.6 sanitized support bundle, a complete
  appliance backup or an installer/legacy migration qualification.
  **M5.4c — snapshot load age (partial; host-tested):** show monotonic browser
  time since current complete/partial load, independently of backend/wall-clock
  timestamps. One local30s watcher, no API/disk polling/history; refresh/auth
  invalidation retires it and queued old callbacks cannot overwrite newer state.
  Invalid/regressing/missing clock means unknown age, without hiding valid data
  or automatic recovery before refresh. All-unavailable results have no watcher;
  hidden tabs skip periodic text writes and age is not a live region. This is
  not device observation age, health or an atomic snapshot. Complete DOM and
  Windows/pinned Linux preflight and one actual ARMv5 embedded-asset smoke pass;
  no JavaScript executes in QEMU. Browser/full/hosted/product gates stay separate.
  **M5.4d — explicit desired user references (partial development workflow):**
  create a reference without grants or remove one exact selected reference only
  after its last desired SMB grant is explicitly removed. Preserve all unrelated
  definitions/rules, show before/after review and require existing revisioned
  Save; no default-delete selection, cascading cleanup or automatic retry.
  These are policy references, not Unix/Samba accounts, credentials, live access
  revocation, rename or native identity reuse. Acceptance: name/duplicate/128
  bounds, selected-ID binding, referenced-removal refusal, immutable baseline,
  grant/NFS preservation, first/last reference, uncertain-save reconciliation,
  actual authenticated HTTP round trips and dangling-reference rejection. Verify
  updated embedded assets in ARM; real-browser/accessibility and native account
  management/recovery remain separate product gates.
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
  **M5.5b — authentication focus continuity (partial; host-tested):** a first
  skip link targets the main landmark; headings accept programmatic focus
  without adding tab stops. When an auth boundary hides the focused control,
  move focus to the visible destination heading without scrolling. Initial
  status, unchanged views, unrelated visible controls and retired responses
  do not move focus. Shared keyboard outlines include links, buttons, form
  controls, summaries and explicit tabindex targets; forced-color overrides
  use system colors. Actual-source DOM regression reproduces the missing
  login destination on the previous source and passes after correction,
  including logout, password-change uncertainty and stale-response cases.
  Complete Windows API/UI checks, ARMv5 test cross-compilation and pinned
  Linux embedded-asset tests pass. DOM focus/stylesheet contracts are not
  browser rendering, screen-reader, contrast or whole-image qualification.
  No new request, retry, endpoint, privilege, polling or activation.
- **M5.5c — Secondary text contrast (partial; host-tested).** The small-text
  `quiet` palette now meets the unrounded 4.5:1 numeric threshold against the
  three declared opaque surfaces and the two tested maximum highlight stops.
  The actual embedded CSS regression fails before the color-only correction;
  black/white and equal-color controls check the calculation. Complete DOM/
  Windows API checks, ARMv5 test cross-compilation and pinned Linux embedded
  asset tests pass. This is not computed-style, gradient-rendering, browser,
  screen-reader, all-text WCAG or complete-image qualification. No dependency,
  request, endpoint, service behavior or activation change.
- **M5.5d — Storage display envelope (partial; host/ARM asset-tested).** HTTP
  success with missing/malformed storage data no longer means zero devices.
  Require existing schema2/sysfs/read-only flags, exact count at most32 and
  typed row kind/read-only/removable/block-identity status labels before DOM
  mutation. Invalid storage clears only storage/GPT values, preserving freshly
  received other domains with partial freshness; no new/retried requests.
  DOM regressions cover27 malformed cases, valid empty/32-row boundaries,
  partial-DOM refusal and matching report unavailable/invalid classification.
  Whole pinned Linux tagged vet/units and actual single-boot ARM overlay pass;
  terminal raw guest capture is truncated and kept as such. QEMU serves/checks
  assets, not JavaScript execution. Complete metadata/response-byte validation,
  real-browser/accessibility, two-boot/full/hosted/product gates remain open.
- **M5.5e — Remaining snapshot display guards (partial; host/ARM asset-tested).**
  System memory/uptime/runtime flags, RAID status/health/counts and mount namespace/
  flags/counts now use existing schemas before rendering or declaring freshness.
  Bounds match producers: 16 arrays, 32 members, 128 mounts. Invalid sections
  cannot become empty inventories or clear freshly read independent domains.
  Valid partial/unsupported/unavailable RAID and zero available memory remain
  distinguishable. Rejected private display details yield a fixed invalid report
  marker, not an available aggregate. Four existing requests/session/deadline
  behavior remain unchanged. Actual-source RED/GREEN, 55 additional malformed
  cases, mixed-domain/report/maxima controls and whole pinned tagged Linux units/
  vet pass. Single-boot ARM overlay passes with complete raw HTTP/HTTPS asset
  markers; no browser JS execution, full metadata/byte/provenance, two-boot/full/
  hosted/hardware/product qualification is implied.
- **M5.5f — Diagnostic transport budgets (partial; host/ARM asset-tested).** Existing
  five read-only paths now bound decoded bytes before UTF-8/JSON parsing:
  auth/system16KiB, storage64KiB, arrays512KiB, mounts4MiB. Reject empty chunks,
  more than16384 fragments/depth16/1024 containers; geometric storage avoids
  per-chunk retained objects. No unbounded JSON fallback or Content-Length trust.
  Initial auth gets10s, shared snapshot deadline/session retirement unchanged.
  Failure requests cancellation/releases reader without waiting for uncertain
  cancellation; HTTP status preserved/no error-body consumption/no retry.
  Correct-seam RED/GREEN and native stream size/UTF8/cancel/lock/deadline/max-escape
  controls, whole pinned tagged Linux vet/units and single-boot ARM overlay pass
  with complete raw HTTP/HTTPS asset markers. This is not full JSON/schema/provenance, browser heap/CPU hard
  limits, live/compressed transport, all mutation/import response bounds or
  verified server/kernel stop. See the component contract before extending it.
- **M5.5g — File-service response lifetimes (partial; host-tested).** The combined
  desired-policy manager consumes six fixed method/path responses through the
  existing bounded stream reader. Session/save16KiB, configuration/backup525056
  bytes, preview/restore4MiB; preserve diagnostic defaults while allowing bounded
  large grant/client collections and document-plus-preview restore structure.
  HTTP errors retain status without body consumption; failure requests cancel
  and releases the lock without awaiting peer cleanup. Existing10s operation
  cancellation is rechecked at completed body handoff before publication.
  Overflow and handoff-cancellation RED regressions precede fixes. Whole final
  Windows/pinned Linux checks and actual-source DOM controls pass, including
  inclusive/excess bounds on every route, canceled/retired bodies, dense real Go
  producer samples and retained uncertain PUT reconciliation with no retry.
  The final standard single-boot ARMv5 overlay also passes embedded-asset and
  existing TLS/auth checks; it does not execute browser JavaScript or qualify
  the separate native timing campaign.
  Other panel flows, browser/load/heap, complete transport/teardown, hosted and
  product qualification remain separate. No activation or authority is added.
  **M5.5h — exact HTTP/HTTPS dashboard asset fixtures:** use one verifier for all
  fixed embedded assets (currently eight) over both existing loopback transports. Enforce64KiB
  response bounds, exact decoded-body match, source markers, single exact MIME/
  no-store/nosniff/CSP headers and body read/close success. Require both transports
  before/after API restart; missing/excess/lookalike receipts refuse readiness.
  Acceptance: real host HTTP/HTTPS, marker-preserving corruption and metadata/
  read/close/overflow/redirect/error refusals, tagged race tests, actual ARM smoke
  and runner-negative controls. This is packaging/transport parity within the
  running binary, not browser execution, signed release provenance or product
  certificate lifecycle; no timeout, privilege or normal startup change.
- **M5.5i — Actual-browser synthetic overview smoke (partial).** Reuse an
  installed Chromium-family browser, an isolated disposable profile and the
  host-only synthetic preview. Verify applied CSS and horizontal containment
  at 1365/390/320 px, actual Tab/Enter skip-link navigation, explicit refresh,
  no uncaught exceptions and only same-origin GET page requests. Record all
  current source hashes and bounded screenshots; fail on source drift or uncertain
  child/profile cleanup. The reproduced 320 px viewport/305 px client-width
  overflow is corrected by removing the fixed body minimum. Fast host checks
  separately enforce preview port admission, ephemeral loopback and route
  refusals; no browser download or automatic browser dependency is introduced.
  This does not qualify Go authentication, all management workflows, assistive
  technology/WCAG, heap/performance, network isolation or hardware. Embedded
  ARMv5 asset parity is a separate proof, not guest browser execution.
- **M5.5j — Browser-to-auth-handler smoke (partial; host fixture).** Reuse the
  installed-browser runner with an explicitly compiled test-only Go server,
  memory-only accounts and invented system input. Exercise setup, incorrect
  credentials, logout/login, password change and old/new password behavior,
  global logout; independently replay each original HttpOnly cookie before/
  after revocation. Preserve partial storage/RAID/mount unavailability without
  a real collector. Match embedded UI hashes before navigation; verify explicit
  fixture stop, zero exit and disposal receipt before success. The normal host
  suite must prove auth admission, synthetic-only values and opt-in server skip.
  No production code, persistence, privilege, HTTPS trust, second-browser/race,
  account recovery, service activation or physical device qualification follows.
  Keep exact pure-host paths in cheap CI without excluding other API sources.
- **M5.5k — Bounded setup/login submission (partial).** One ten-second browser
  deadline covers credential POST headers/body and its follow-up status read;
  cap the decoded JSON reply at16KiB and obtain session authority only from
  status. Diagnostic refresh retains its separate existing lifetime. Refuse
  duplicate active submissions and retire old continuations without touching
  replacement attempts. Known400/401/409/429 refusals use fixed messages;
  unknown/expired outcomes hide data/forms, clear input and release controls
  without retry. Explicit reconnect reads status only, including completed setup.
  Keep each asset within64KiB by deferring authentication in a separate module;
  verify the complete seven-file roster over both transports across API restart.
  Acceptance: actual-source RED/GREEN for setup/login header/body/status stalls,
  inclusive/excess replies, fixed/redacted failures, duplicate/retired events
  and late/status-only reconciliation; real-browser controlled pre-header login
  stall; whole host/Linux and actual ARM asset smoke. Browser scheduling is not
  a hard wall-clock guarantee; abort is not server rollback/cancel proof.
  Concurrent tabs, production auth/recovery,
  certificate and full accessibility qualification remain separate.
- **M5.5l — Bounded authenticated mutations (partial).** Password replacement,
  local logout and global panel logout share one exclusive lifetime and original
  ten-second controller through session/CSRF GET, mutation POST and final status.
  Bound each decoded JSON response at16KiB; no unbounded JSON fallback or renewed
  status timer. Require existing endpoint confirmation flags plus explicit
  `authenticated:false`; HTTP200 alone is insufficient. Fixed password refusal
  notices require the matching401/422/429 code. Unknown/expired outcomes hide
  data/form and require explicit status-only reconnect, with no mutation retry.
  Retirement cancels old work/releases controls/clears fields; old finalizers
  cannot unlock replacements. Block snapshot/report work during the mutation.
  Acceptance: actual-source RED/GREEN;18 session/POST/status header/body stalls,
  inclusive/excess/malformed replies, invalid CSRF sessions, network/HTTP errors,
  confirmation/refusal cases, duplicates and retired/replacement ownership;
  actual-browser controlled password/global-logout stalls with original-cookie
  validity and no false revocation/retry; whole host/Linux and ARM asset smoke.
  Browser scheduling/abort is not hard wall clock or server cancellation/rollback.
  Durable account recovery, concurrent tabs, other workflows, full security and
  accessibility/product/hardware qualification remain separate.
- **M5.5m — Reconcile the two administrative-response candidates (partial).**
  Join PR133's exact source/history with the later guard candidate, preserving
  both test sets. Retain M5.5g's stricter six method/path consumer limits and
  M5.5k/l's separate single-flight authentication module byte-for-byte. Add the
  earlier bounded consumers for GPT64KiB, saved share-only policy512KiB,
  standalone preview4MiB and their session16KiB reads. The generic eight-profile
  reader retains tested1MiB combined/backup ceilings, but the active combined
  manager still enforces525056bytes; these are not interchangeable contracts.
  Keep diagnostic defaults and higher-cardinality policy structure bounds,
  no JSON fallback, generation/CSRF/revision/uncertain-save guards and all tests.
  Prevent resurrection of old duplicate authentication handlers during merging.
  Acceptance: both complete DOM suites, Windows/pinned Linux and current browser
  smoke, then exact seven-asset ARM parity; no history loss or implicit develop
  merge. Previous isolated source proofs do not qualify the new combined head.
  Full/own-hosted/native timing, browser coverage of all workflows, physical
  recovery, product service activation and installation remain separate gates.
- **M5.5n — File-service operation and401 ownership (partial).** The combined
  development manager settles its original ten-second operation even when a
  headers promise ignores abort. Late headers are disposed without waiting for
  body cancellation; they cannot send another preview/PUT, publish policy or
  unlock a replacement operation. A401 clears private policy data without
  releasing the current operation before its auth-status recheck; that read
  shares the original signal/deadline and generation. Retirement prevents old
  status success/error from changing a later login. Preserve all response byte/
  structure bounds, revisions/CSRF, single-flight and uncertain-save/no-retry rules.
  Acceptance: twice-reproduced actual-source RED seams;12 header timeout/auth-loss
  cases,2 post401 original-budget cases, replacement-view and replacement-gate
  controls, whole Windows/pinned Linux, actual Edge auth-memory lifecycle with
  controlled policy401/stale-status delivery and original cookie revocation,
  and exact seven-asset HTTP/HTTPS ARM delivery. Reuse the existing wrong/correct
  login leg so the original five-attempt/minute server quota is unchanged.
  Browser actions are DOM-triggered; visible pointer/keyboard/assistive coverage,
  real policy-store browser transactions, concurrent tabs, product enrollment/
  recovery, full/hosted and physical qualification remain separate. This does
  not change or qualify every other administrative reader.
- **M5.5o — Visible authentication controls (partial).** Separate the actual
  memory-auth test profile from the GET-only synthetic preview: invented system
  data stays explicit, authenticated controls stay visible only in the former.
  Exercise setup/login/password input with actual pointer focus, Tab and native
  Enter submission; sign-out/reconnect use visible hit-tested pointer controls.
  Preserve auth handlers, five-login quota, original-cookie revocation,401
  retirement and controlled10s uncertainty proofs. Retain every bounded resource
  observation; accept only same-origin HTTP plus one exact reviewed inline SVG,
  rejecting unknown local schemes, external requests and non-auth mutations.
  Acceptance: profile RED/GREEN controls, resource refusals, whole Windows/pinned
  Linux, both installed-browser modes and exact embedded-asset ARM delivery.
  Auth setup is exercised at1365px, overview at1365/390/320px and subsequent auth
  flows at320px. Refresh/policy load remain DOM-triggered. Other forms/viewports,
  multi-tab/password-manager/assistive testing, native policy-store browser
  writes, product enrollment/recovery and HTTPS browser trust remain open.
  This is not service activation, full firmware/hosted or physical qualification.
- **M5.5p — Browser desired-policy round trip (partial; host only).** A separately
  selected test-only memory backend exercises actual Go handlers with visible
  pointer/keyboard form actions. Load uninitialized state, create independent
  NFS without SMB/users and reread revision1, add combined SMB/NFS and reread
  revision2 without duplicating its volume reference, update an existing SMB
  grant and reread revision3 while retaining both NFS exports, then remove only
  the second export and reread revision4 while retaining the complete SMB policy
  and original independent export. Require exactly four explicit PUTs, fixed same-origin
  fixture routes, independent bounded snapshots, stale-revision refusal and
  verified owned-process/profile disposal. Preserve the default fixture's
  absent policy backend and the separate auth/network/iSCSI campaign claims.
  Windows units, pinned Linux vet/scoped units/race3, existing DOM/resource/
  workflow controls and installed Edge execution pass in the initial campaign.
  Its original forms ran at1365px, with overview layout at390/320px. The
  responsive extension below now changes CSS and expands browser coverage;
  only exact pure-host files bypass firmware
  rebuild triggers. Appliance persistence, real-store browser transactions,
  activation, accounts, all forms/accessibility, clean/hosted and physical
  qualification remain open. This mode is not a substitute for those gates.
- **M5.5q — Responsive bounded desired-policy review (partial; host browser).**
  Preserve the complete M5.5p workflow and all original caps;
  run visible policy actions at320px with80-character share names,32-character
  user references and512-character relative paths, verifying exact saved bytes.
  Inspect draft and the three original combined-add/edit/remove reviews at
  1365/390/320px, with no horizontal page or
  control overflow and associated input labels. Two real browser REDs reproduce
  non-wrapping summary text (3491px on1350px) and a1225px long review region in
  a900px viewport. Summary wrapping and viewport-bounded scroll regions preserve
  complete content without lowering valid input limits or hiding overflow.
  Both table regions require Tab reachability, visible focus and horizontal
  arrow scrolling; the long pair table also needs vertical arrow scrolling with
  unchanged page position and verified keyboard exit. Twelve layout observations,
  two fixed screenshots and original process/profile disposal are required.
  Current Windows host and installed Edge checks pass; current pinned Linux,
  ARM embedded-asset execution, full/hosted, broad accessibility, touch/mobile
  hardware and product persistence/activation qualification remain separate.
- **M5.6 — Audit and diagnostics.** Record actor, operation ID, revisions and
  redacted outcome; bound retention. Export a sanitized support bundle that
  excludes credentials, private keys, passdb hashes and user file contents.
  **M5.6a — sanitized snapshot report (partial development workflow):** explicitly
  download a versioned browser-created report from the already loaded four-domain
  snapshot. Allowlist runtime/memory values and aggregate sysfs, MD-health and
  mount counts; omit names, paths, identifiers, addresses, configuration and raw
  errors/logs. Preserve per-domain unavailable/invalid/partial states and report
  browser receipt/export times with unknown age after clock regression. Cap
  output at4 KiB; never retain original inputs in the report factory, poll,
  authenticate again or perform device operations. Refresh/session retirement
  immediately clears report authority; late replies cannot restore it. Blob
  URLs and temporary anchors are disposed. This is not trusted attestation,
  an atomic inventory, SMART history, appliance backup or operation audit.
  Real-browser/accessibility qualification and the remaining audit/diagnostics
  workflow remain separate from DOM/HTTP and guest asset checks.

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
  **M6.1g — Manual desired-policy preview (host/browser/ARM prototype):** the
  authenticated POST `/api/v1/network/preview` reuses the existing strict 16 KiB
  model, with Origin/CSRF, one active body, revocation/cancellation fences and a
  32 KiB response. Exact decimal revision, hostname, two logical slots, IPv4/IPv6,
  routes and DNS describe only submitted settings. All saved/applied/binding/
  live-state/conflict/reachability/activation flags remain explicitly false.
  The panel sends original text without JSON re-encoding, bounds response bytes
  and structure, shares one 10 s deadline across session and preview, retires
  edited/logged-out work and clears private input without retry/browser storage.
  Host/DOM/race controls, real memory-auth browser keyboard entry/refusal/clear
  and three widths, plus actual ARM HTTP/HTTPS checks twice across API restart
  pass. All nine UI assets are byte-exact on both transports; old checks and
  budgets remain. Pure UI test modules select cheap host checks, not firmware
  builds; runtime/API changes still select their original checks. No kernel
  inventory, resolver or store is wired here. This closes neither physical-slot
  binding nor M6.2 trial/recovery, production networking or product state gates.
  **M6.1h — Guided complete proposals (host development workflow):** use explicit
  hostname/revision, both logical slots and IPv4/IPv6 modes/aliases/defaults,
  DNS/search fields and up to16 additional routes. No enabled-family or /24
  default, existing-JSON import or second address parser. Emit canonical uint64
  revisions exactly. Existing nonempty text requires one-shot whole-replacement
  consent, cleared by input edits; publish new text only after the existing
  server validates it and every projected setting matches. Refusal, timeout,
  drifted reply and retired work preserve original text. Reuse the single-flight
  ten-second operation,16/32KiB limits, auth/CSRF and clear/logout privacy.
  Acceptance includes pure mode/list/route/revision guards, server refusals,
  manual/guided concurrency, edited/cleared/logged-out/timed-out work and real
  browser dual-stack /16 plus IPv6/gateway/route fields at1365/390/320px.
  This is a whole-proposal builder, not current-state editing, persistence,
  qualified physical-slot mapping or application. ARM embedded-asset execution
  and full product networking remain separate from host/browser evidence.
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

**State:** partial offline research/software prerequisites; hardware unqualified.
**Hardware entry:** a separately approved plan with stop conditions and suitable
equipment/media; not ordinary software work.

- **M7.1 — Evidence inventory.** Map supported board revisions, SoC/RAM, UARTs,
  GPIO/pinmux, interrupts, controllers and boot handoff. Keep model-specific
  evidence and source attribution next to board definitions.
- **M7.2 — Controller protocol.** Passive internal-UART captures first; qualify
  framing/checksum, selectors, timing, replies, asynchronous alarms and failure
  behavior. Console UART is not the management-controller UART. Validate parser
  fixtures before considering any transmitted control command.
  **M7.2a — passive receive restart (host-only):** static byte-identical final/
  older daemon and direct RS232-read evidence establish immediate0xfa restart.
  Decoder refuses interrupted standalone frames and recovers following frames
  without inventing button events, independent of capture chunk boundaries.
  Keep15-byte buffering and unknown checksum status. Generic ACK flag evidence
  does not establish command correlation. No serial opener/transmitter, safe fan
  setting, active hardware or complete wire-protocol qualification is provided.
  **M7.2c — selected transmit/retry boundary (static evidence only):** original
  CLI/daemon/library bytes distinguish11 blocking-capable queue attempts from10
  general wire attempts, ignored write/setup results, count-versus-message-size
  mismatch and a special status bypass. The generic XML ACK has no command/
  freshness binding, no pre-send clear and unchecked deletion; normal exhaustion
  skips the later failure diagnostic. Read−1 becomes0, not an uninitialized-byte
  parser read. Three selected builders/forwarders calculate no integrity field;
  zero table bytes keep unknown semantics. Independent static scopes and root
  PT_LOAD/instruction/import checks are not a runtime/hardware qualification.
  See the [exact scoped finding](board/wd/ex4/FRONT-PANEL-RESEARCH.md#selected-transport-errors-retry-and-ack-association).
  Next: qualify retained transport ownership, full bounded write/settlement and
  command/reply association against passive original traffic; model source loss,
  short/failed I/O and delayed/duplicate/asynchronous events before any separately
  authorized TX trial. Never replace unknown integrity with “checksum valid”,
  infer physical application from queue/ACK/exit, or carry over blind retries.
  **M7.2b — length-specific passive dispatch (host-only):** classify7-byte
  thermistor replies by fixed03/08 prefix plus supported sensor1/2 and status
  families40/41/42 by byte1; only MCUVer is eligible at15bytes. Leave13-byte
  envelopes unclassified because the legacy RTC path bypasses selector checks.
  Preserve raw dispatch bytes, bounded diagnostics, unknown integrity and no
  temperature conversion. Acceptance: actual regression failures before fixes,
  all38templates across3lengths, sensor/status byte boundaries, capture splits,
  CLI behavior and complete Windows/pinned Linux vet/race/fixed-count fuzz.
  This does not establish checksum/payload validity or authorize hardware I/O.
- **M7.3 — Cooling safety.** Independently measure temperature and fan/tach
  behavior. Define startup-safe fan state, unavailable/stale sensor handling,
  controller/daemon failure, overtemperature and safe shutdown. Do not disable
  watchdogs or alarms to prolong an unstable experiment.
  **M7.3a — offline legacy path reconstruction (partial):** hash-bound final
  ARM analysis maps level-request IPC, initial LOW/conditional HIGH boot,
  GPIO boolean-state selection and zero-result last-good temperature fallback.
  Requested speed is not confirmed speed; generic ACK and cached nonzero XML
  do not prove command application or fresh temperature. No active controller
  or safe thresholds are supplied. See the [evidence and contributor handoff](board/wd/ex4/THERMAL-RESEARCH.md).
  Remaining offline work: exact tach/register/error interface, conversion and
  freshness, HDD normalization/hysteresis/overheat-to-shutdown path, hibernation
  ownership. Replacement contract/tests must distinguish requested/observed
  state and invalid/stale samples before separately qualified hardware controls.
  **M7.3b — tach/register static reconstruction (partial):** exact `libshare`
  paths map raw input versus latched cause, the wall-clock/iteration-bounded
  transition estimator, fixed15x conversion and conditional nominal publication
  substitutions. `/dev/mem` open/map failures collapse to zero, write receipts
  are unconditional and failed-map paths retain an opened descriptor. Selected
  GPL source supports bank1 bit7/GPIO39 under its mapping, not physical wiring
  or permission to request a line. Acceptance before a real provider: calibrated
  edge/count/elapsed provenance, monotonic overflow-safe sampling, explicit
  read/clock errors, no nominal RPM substitution and no broad MMIO authority.
  Host-only analysis does not qualify that provider or release the hardware gate.
  **M7.3c — thermal input/shutdown static linkage (partial):** receiver lookup
  precedes selector validation without a visible index guard; visible initialized
  data is not a proven declared-array bound or calibrated Celsius. Map differing
  model predicates, HDD display-versus-control transformations, skipped sleeping
  slots, composite score and counter-based thermal request. Selected consumer
  clears the request before a double activity gate and asynchronous shutdown;
  remaining marker/reassertion paths are not a verified shutdown transaction.
  Replacement acceptance: per-sensor/per-disk quality, no brand exclusion or
  nominal health, bounded monotonic deadlines, retained intent/verified deferral
  and cooling ownership through shutdown. No safe numerical thresholds or
  physical shutdown qualification follow from the legacy constants.
  **M7.3d — deferral/hibernation static linkage (partial):** boot attempts a
  persistent-to-temporary marker move, then the consumer attempts unlink before
  its activity gate, without checked results. USB/SATA guards are not global
  admission. The selected `set_pwm` manages disk activity/sleep bitmaps, not an
  observed direct cooling command; its dependencies/MCU effects remain open.
  Acceptance: retained deferral/replay intent, per-disk generation/freshness,
  helper crash invalidation, index equivalence with slot holes, bounded wake/
  shutdown settlement and thermal-safe workload admission. Do not infer physical
  sleep, cooling handoff or power-off from a command, bitmap or readiness marker.
  **M7.3e — private observation evaluation (host/QEMU prerequisite):** a bounded
  pure evaluator distinguishes missing/generation mismatch, invalid clock/stale,
  unavailable/read failure/disk sleep, unqualified/raw and out-of-range samples.
  Only a current point-in-time observation exposes its number, including genuine
  zero; no last-good or nominal substitution. Roster, generation, monotonic
  origin, units/calibration, TTL and measurement interval remain trusted-caller
  obligations, not properties proven by input flags. No safe thermal policy,
  I/O, HTTP, history, controller or activation. Acceptance: exact time/range
  boundaries and overflow, whole-roster refusal, private immutable output,
  fixed-count fuzz and invented-source fixture in the existing standard ARM boot.
  See the [component contract](src/phantowd-api/internal/thermalreport/README.md).
  **M7.3f — exact tach arithmetic (host/QEMU prerequisite):** normalize a supplied
  transition count by its actual window and explicit transitions/revolution,
  not WD's fixed multiplier. Preserve all inputs and fractional-result evidence;
  exact128-bit products/checked division must reject unrepresentable RPM without
  clipping. No physical calibration, trustworthy counting/window, source
  qualification, safe-speed threshold or actuator follows from arithmetic.
  Acceptance: independent big-integer oracle including wide products, signed
  output bounds, zero/fractional cases, fixed-count fuzz, allocation benchmark
  with exact scope and synthetic execution in the existing ARM self-test.
  **M7.3g — Kernel temperature diagnostic adapter (host/browser workflow):**
  attach an optional thermal envelope to the existing authenticated system reply,
  not a new polling request. Observe at most8 canonical kernel zone labels with
  two128-entry-capped directory censuses and128-byte attribute acceptance.
  Validate type before measuring; canonical signed32-bit millidegrees preserve
  zero/negative reports. Failed samples have no number, partial states are explicit,
  changed/excessive/unavailable inventories have no retained values. Isolate
  malformed optional thermal data from valid runtime/memory display and omit
  labels/values from sanitized reports. Hardware-qualified/control flags stay
  false; no trusted sensor identity, calibration, sample age, complete coverage,
  actuator, thresholds, alerts or thermal-safe workload admission follows.
  Synchronous driver reads have no promised total I/O deadline. Acceptance:
  type/value/roster/byte bounds, actual read/close/error/no-retry controls,
  no cooling-device access, unchanged response budget, HTTP synthetic boundary,
  independently bounded display/no-last-good and all real-browser regressions.
  Native CI must print actual status/count; empty inventory does not qualify a
  sensor. Actual ARM/physical board and safe cooling qualification remain open.
- **M7.4 — Peripheral support.** Qualify SATA bays, USB, RTC, LEDs, LCD, buttons,
  watchdog and power control. Hardware alarms override cosmetic display choices.
  Record LED/button semantics and shutdown completion, not just driver presence.
  **M7.4a — internal text preparation (software prerequisite):** distinguish
  raw `FanSpeed`/`SysName` display publication from `FanControl` actuation. The
  selected legacy string builders do not enforce their payload bounds or an
  encoding contract; table value20 is not an enforced LCD width. Prepare only
  nonempty printable ASCII within an explicit caller byte limit, with zero
  result/fixed error on refusal, no truncation and no default hardware profile.
  The one-byte representation ceiling255 is not qualified MCU capacity. Keep
  output private/requested, not observed or a measurement. Acceptance: all256
  byte values, inclusive1..255 limit boundaries, Unicode/control/framing refusal,
  preserved spaces, independent predicate fuzz, private JSON and synthetic
  execution in the existing standard ARM self-test with both restart receipts.
  No extra guest, frame encoder, transport, provider, HTTP or product startup.
  Remaining product gates: independently qualified board/profile/repertoire,
  complete integrity/reply semantics, bounded ownership/settlement, alarm
  priority and physical behavior. See [exact static anchors and handoff](board/wd/ex4/FRONT-PANEL-RESEARCH.md).
  **M7.4b — split LED ownership and alarm arbitration (partial static evidence):**
  selected EX4 `led` alarm outputs use SoC-register wrappers, not solely MCU
  requests. Exact cached class 2/1 flags override the cosmetic LED-enable setting
  only in a final branch after preliminary output calls; direct update/download
  paths bypass it. Class 0 does not prove valid/current/complete health. Separate
  `ErrStatus` event codes map to compact selector bytes, not bit positions; its
  unchecked numeric/byte and optional-text paths are not a product contract.
  Before implementation: bind exact board/controller revisions and exclusive
  backend ownership; qualify a narrow GPIO/kernel LED interface; define typed
  events/boolean operations and bounded event-specific text; distinguish desired,
  submitted and observed state; preserve alarm authority through stale sources,
  uncertain clear, crash and boot/update/shutdown transitions. Acceptance must
  cover cosmetic-off versus active alarms across **all** output paths, source
  loss without false healthy/clear, concurrent source changes, malformed/overflow
  inputs, delayed/duplicate application receipts and verified controller/driver
  settlement. Host/QEMU first, then separately reviewed physical behavior; no
  broad MMIO port, MCU encoder, hardware profile or product control is added by
  this static checkpoint. Selected masks/selectors are not qualified wiring.
- **M7.5 — Non-persistent boot.** Keep research targets and product configuration
  separate. Audit enabled write-capable subsystems, readiness/stop markers and
  state effects before a RAM trial. Never turn a narrow B3 success into a blanket
  authorization for longer boots or attached data disks.
- **M7.6 — Recovery foundation.** Determine exact NAND geometry, ECC/OOB,
  bad-block policy, vendor headers/checksums, boot validation, environment and
  device identity dependencies. Verify backups and an independent rescue path.
  A raw image copy or recognizable SquashFS magic is insufficient.
  **M7.6a — stock source/configuration cross-check (partial, offline):**
  hash-bound GPL configuration/Orion/core ECC evidence selects software Hamming,
  not the compiled-out RS override or its `nandEcc=` parser. For observed
  2048/64 geometry the source path implies 256-byte steps, three ECC bytes per
  step and OOB positions 40–63; this is not a measured page decode, exact build
  reproduction or U-Boot parity. Final `chk_image` separately selects an mtd4
  fallback from a register bit and seeks 5 MiB + 4 KiB in a requested 10 MiB packed
  dump; unchecked command/seek/write results prevent a restore guarantee.
  Acceptance still requires reconciling both rescue readers/producers and the
  register writer, a reviewed raw-versus-logical capture specification with
  identity/ECC/bad-block preservation, and independent bootloader-readable
  restore/interruption drills on sacrificial EX4 hardware before any writer.
  See the [source anchors and remaining gates](board/wd/ex4/NAND-RECOVERY-RESEARCH.md).
  **M7.6b — rescue identity and legacy mutation boundary (partial, offline):**
  final updater merger rewrites only its 2 KiB binary header plus an
  identity-bearing config text file, with unchecked I/O and pathname reopen;
  its serial-derived field labelled "key" does not establish cryptography or
  explain the inner rescue body. Synthetic host inspector tests retain this
  field's opacity through success/refusal/errors without mutating input.
  Host rescue read errors now discard private reader text/unwrap chains; shared
  checksum guards require full declared consumption and refuse mixed EOF/error
  outcomes. Actual REDs cover privacy and XOR-preserving truncation; Windows/
  pinned Linux toolkit, focused race3 and the existing10,000-case fuzz campaign
  pass, including a real temporary file truncated after stat. This does not
  establish source immutability or qualify physical rescue/installation.
  Static `mtd_check` main can select destructive UBIFS config reinitialization
  and return zero without verified remount; its stock init invocation is
  conditional on USB detection/retry state. Never execute it as a diagnostic.
  Acceptance still needs an independently evidenced rescue body producer/
  payload, register writer, exact-unit capture design and recovery drill;
  no new payload parser, legacy-helper execution or installer is authorized.
  A further final-updater trace now anchors the standalone rescue-input consumer:
  type2 classifier, separate file validation and same-path writer/header merger;
  712 instruction/literal words match the original ELF. This is not the body
  producer, register writer or bootloader handoff, which remain explicit gates.

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
    Its operation budget now starts before admission and includes post-capture hashes:
    cooperative hash-read/final cancellation fences preserve zero results,
    while observed drift remains review rather than a cancellation shortcut.
    Constructor hashing and blocking filesystem/fixture calls are not given
    a hard interruption guarantee. This is a primitive reliability correction,
    not trusted device/runtime collection or a hosted timing fix.
    Host lifecycle tests and a test-only adapter in the existing ARM926 producer
    boot pass seven genuine generic-producer projections and fake-source-change
    refusal. This closes neither authenticated/isolated runtime nor device
    provenance, ioctl, standby or physical qualification; no product startup
    uses the primitive. Debug-free guest tests fit the existing copied image;
    injected bytes are verified before boot even if debugfs reports success.
    An optional constructor-fixed private ATA serial/NAA-5 WWN comparison now
    runs in that coordinator without changing its original profile or sample
    shape. Report refusal latches review, never retries or publishes partial
    evidence. Whole host/vet, scoped race3 and the existing ARM926 replay boot
    pass six matched projections plus missing/foreign identity and changed fake
    source (ten compared cases), with the original proofs and budgets retained.
    Matching report text is not provenance, stable identity or command authority;
    qualify expected-field origin, retained runtime/device and standby before
    attributed collection, history or UI. No product startup calls this profile.
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
    A private fixed-opener composition now derives every name/generation from
    the initial complete census, reuses the existing read-only `/dev` opener,
    keeps that pre-open baseline and retains independent witnesses. Constructor-
    owned original FDs close before success; borrowed inputs remain borrowed.
    Uncertain construction cleanup returns a non-usable review handle plus error,
    never a partial usable set or automatic retry. Native unit/race tests and
    actual seven-leaf ARMv5 metadata opening, retained-review and failed post-open
    census rollback pass in the standard smoke overlay. Its new exact marker
    refuses missing/duplicate/suffixed receipts. Two-boot, complete rebuilt-image/
    SBOM, clean/hosted, physical/non-root/standby and SMART command qualification
    remain open. Product startup, broker operations and HTTP are unchanged.
    Do not add history/UI by treating this transient tuple as stable media identity.
    A separate offline report-comparison prerequisite now requires exact caller-
    supplied serial plus NAA-5 WWN, integer4/24/36-bit fields and the original
    bounded report/exit semantics, with no missing-ID fallback or normalization.
    Windows unit/vet/fuzz and pinned Go 1.26.8 Linux unit/vet/race3 scopes pass. It is
    not connected to the coordinator or a provider, and matching JSON does not
    authenticate its source. Next qualify retained device/command composition;
    do not infer ATA/sysfs equivalence or disk support from report consistency.
    The existing seven-case corpus now supplies independent invented serial/WWN
    words and original parser comparison/refusal checks, without changing cases,
    commands or deadlines. Six host input/runner/routing controls and selected
    Windows tagged tests pass. On 2026-10-16 actual native 7.4/7.5 reports pass
    comparisons plus eight existing checksum/power cases each; actual ARM7.5
    producer/parser/capture passes, base unchanged. Linux shell/path/lint controls
    pass, all fifteen selected source/archive/base witnesses match and formatting
    preserves all seven trace hashes. Complete current-image/own-head hosted and
    physical/provider qualification remain open. Fake replies are guard tests
    only; they do not qualify producer execution or authenticate a report.
    A separate offline temperature prerequisite now validates optional ATA
    `temperature.current` without changing the original health parser or granting
    collection authority. Its signed-byte bound is not an operating limit, and
    missing remains distinct from zero. Actual generic-only native7.4/7.5 and
    static7.5 ARM926 fixtures pass invented attribute194 values37/0/127/255:
    only37/127 are reported. Original health/boundary/capture proofs remain.
    Signed device-statistics/SCT emitters have static-source/parser coverage,
    not replay qualification; source/freshness/transport/thermal gates remain.
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
- **M9.2c.1 — Coherent protocol-view editing (internal model).**
  Build a base+1 whole NAS document from either the file-service or iSCSI view;
  preserve every other-protocol definition and advance all seven revision
  bindings. Refuse invalid/stale/skipped/overflowing state and any removal or
  redefinition of a volume referenced by a retained iSCSI backing. Return
  independently owned nested values, never an authority or partial failure.
  **Local acceptance:** units/vet, race-count3, 19 refusal cases, exact
  maximum revision, empty collections, concurrent detached results and the
  unchanged dense-sample allocation ceiling pass. The existing guest self-test
  exercises seven cases before/after API restart with an exact-pair log guard.
  Actual ARMv5 standard overlay smoke passes that pair and its existing checks;
  this is not two-boot, full image/SBOM, physical or installable qualification.
  **Next:** compose these helpers with the single product state Owner and the
  M1 publication/recovery protocol before exposing a persistent edit workflow;
  retain expected-revision comparison under that Owner. No second authoritative
  store, automatic migration, backing/credential access or service activation.
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
- **M9.2f — Desired iSCSI management projection (internal prerequisite).**
  Reuse the whole coherent policy validator; never add an independent dialect
  or choose/migrate authoritative old/new stores through display code. Project
  complete target/LUN/initiator/grant relationships and proposed backing fields,
  omitting credential usernames, SecretRefs and raw filesystem UUIDs. Preserve
  exact uint64 revision/capacity as decimal strings and bounded numeric counts/
  LUN numbers. Desired enabled is not running; storage, credentials, runtime and
  activation remain explicitly unqualified. Return no partial output on invalid
  or mixed revisions, never truncate accepted rows, cap encoded output at256KiB,
  and keep input/output ownership separate. No file/secret/device/process I/O.
  Acceptance: exact large integers, nil/empty distinctions, seven revision
  refusals, foreign refs/RO escalation, privacy/copy controls, dense1024grants,
  bounded arbitrary-JSON fuzz through the existing decoder, whole Windows/Linux
  and actual standard ARMv5 synthetic projection/stale-refusal assertions.
  The approved manual HTTP/panel adapter follows in M9.2g; this pure prerequisite
  grants no persistence, activation or NAS authority. Never run a second writer.
- **M9.2g — Authenticated manual iSCSI preview (local prototype).** Accept one
  complete coherent SMB/NFS/iSCSI document at an explicit POST; reuse existing
  decode/projection, never the old development store or an independent dialect.
  Require current session, exact Origin, single CSRF header, strict JSON envelope,
  query/encoding refusal and a non-queuing one-preview gate; recheck the session
  before publication. Bound complete streamed input at656128bytes and exact
  encoded response at262144bytes. No state save/load, backing/secret open,
  runtime observation, create/enable action or second authoritative store.
  Text-only UI displays every accepted target/LUN/initiator/grant and backing;
  preserve exact decimal revision/capacity, explicit empty policy and desired
  versus running distinction. One10s deadline includes session/POST headers and
  response bodies; edit/clear/logout retire old work, late401/results cannot
  change a replacement view, and session loss clears private input. No browser
  storage, automatic retry or memory-zeroization claim. Warn against actual
  passwords/keys and do not imply that CHAP encrypts traffic.
  Local acceptance passes: whole Windows/pinned Linux vet/units, ARMv5 compile,
  focused race3, strict HTTP/body/concurrency/revocation controls, independent
  display validation, inclusive byte bounds and four non-cooperative deadline
  seams. Installed Edge tests visible text/pointer submission against actual
  memory-auth Go handlers, explicit clear and1365/390/320px result layouts.
  Standard single-boot ARMv5 smoke requires two exact HTTP and two HTTPS preview
  receipts across API restart, including privacy/precision and negative requests;
  all eight embedded assets remain byte-exact on both transports. This is not
  full/two-boot/hosted, production security, target activation or physical EX4
  qualification. Next: authorized source-of-truth migration and guarded product
  credential/storage/session composition before any saved target workflow.
- **M9.2h — Configured backing exposure advisory (local prototype).** Extend the
  existing authenticated preview to schema2 with explicit per-backing SMB/NFS
  path-overlap counts bounded by the submitted complete definition rosters.
  Compare only validated canonical paths on the same logical volume: root,
  equal and ancestor/descendant components, case-sensitive without normalization.
  Include read-only shares and disabled targets; no lexical match is not safety.
  Display positive exposure warnings and explicit negative limitations using
  text only. Refuse old/missing/malformed/contradictory counts; retain all original
  authentication, byte/deadline/retirement/privacy and no-save/open/activation
  boundaries. No overlapping share names, clients, UUIDs or secrets are added.
  Acceptance: full128-definition counts, whole model/HTTP/DOM checks, real browser
  POST/clear/narrow layouts and actual HTTP+HTTPS ARM fixtures with both overlaps.
  Filesystem aliases, real use and product activation remain separate gates.
- **M9.2i — Guided disabled-target draft (host/browser prototype).** Add one
  target/LUN0/backing/initiator to a supplied complete coherent NAS policy, not
  the older SMB/NFS-only store. Preserve prior definitions and advance all nested
  revisions together; generate collision-free draft IDs, not runtime authority.
  Select CHAP/mutual-CHAP symbolic references, access, block size/allocation and
  capacity; do not request passwords or provision credentials here. Target starts
  desired-disabled; no backing allocation or service action. Validate exact
  original input through the existing authenticated preview before validating
  the normalized candidate: duplicate/unknown/invalid originals must not be
  silently repaired. Replace local text only after verified candidate projection;
  invalid/refused/expired/retired work leaves the original unchanged (session loss
  clears it). Both POSTs share the original10s deadline and bounded readers,
  session/Origin/CSRF, single-flight/no-retry and privacy guards; no new endpoint
  or authoritative store. Refuse unsafe browser numbers rather than rounding;
  full-range manual JSON preview remains usable. Local acceptance: strict invalid
  fields/precision, nonempty three-protocol preservation, ID collisions, mutual
  CHAP, base/candidate/projection refusal, six second-request header/body retirement
  cases and explicit private-field clear. Real browser/Go API verifies CHAP draft
  success/duplicate-base refusal/clear and1365/390/320px layouts under unchanged
  resource/action budgets; ARM verifies exact embedded HTTP/HTTPS assets, not JS
  execution. Still needed: qualified source-of-truth load/save/recovery, broader
  target/multi-LUN/initiator editing and guarded credential/storage/session/runtime
  composition before any product create/enable operation.
- **M9.2j — Existing-target LUN draft extension (host/browser prototype).**
  Extend M9.2i's same bounded two-preview operation, not a new store/backend.
  Require exact target ID and IQN and desired-disabled state; this is not proof
  of runtime inactivity or permission for a live change. Preserve target identity,
  previous LUNs/backings and all old credentials/grants. Add one backing and
  collision-free LUN ID with lowest unused number. If the named initiator exists,
  require identical CHAP/mutual-CHAP mode/users/SecretRefs and append only its new
  LUN grant. Otherwise propose one new initiator granted only that LUN; never
  grant all existing peers automatically. Respect16target/64backing/16LUN/
  32initiator/16grant limits, coherent revisions, safe browser integers and the
  original strict server base/candidate validation. Refused or ambiguous original
  evidence must not be normalized into accepted state. Bind candidate display to
  target/LUN/backing/initiator/access as well as revision/counts. Do not replace
  source text on refusal or retire old results into a newer operation. Acceptance:
  correct-seam RED/GREEN, old/new peer and mutual-CHAP preservation, mismatch/
  enabled/unknown/name refusal, self-consistent substituted projection refusal,
  actual browser/Go API create→extend with one peer/two LUNs, six preview POSTs,
  unchanged deadlines/action caps and three viewport checks. ARM qualifies exact
  embedded HTTP/HTTPS bytes, not JS execution. No save/allocation/secret resolution/
  target activation; product creation/enable/grow/remove still requires M9.3's
  real session/storage/credential authority and M1 recovery/source of truth.
- **M9.2k — Scoped desired target/LUN/grant edits (host/browser workflow).**
  Edit one target state, one LUN's access or one existing initiator grant in the
  supplied complete coherent policy. Exact target ID+IQN and selected LUN/peer;
  refuse ambiguous/no-op/unsafe-number input. Access changes require desired-
  disabled state, never inferred runtime inactivity. A read-only LUN refuses
  while any grant is read/write; no cascade or credential/backing/file-service
  mutation. Advance every coherent revision together. Reuse the same strict
  original/candidate POSTs, auth/CSRF,16-target/64-backing and original byte/time/
  single-flight/retirement limits. Match the complete public projection before
  publishing local text, including unrelated targets/LUNs/grants/backings and
  file-service counts. Acceptance: multiple targets/LUNs/peers with immutable
  credentials and unselected policy; base/candidate and valid-but-substituted
  reply refusals; shared manual/add/edit exclusion and private clear/retirement;
  actual browser/Go API five edits, no-cascade refusal, duplicate-original
  refusal, keyboard controls and1365/390/320px layouts. No new endpoint/store,
  delete/resize/allocation/credential provisioning or product activation. Native
  host evidence does not replace ARM asset or full/physical qualification;
  desired enabled/disabled is never a target start/stop/session-revocation result.
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
  **M10.2c — unsigned metadata production (partial; host-tested):** prepare
  deterministic schema1 JSON from explicit names/roles, caller declarations
  and a raw public key; measure fingerprint/sizes/SHA-256, sort copied lists,
  reuse existing validators/read bounds and refuse incomplete results.
  Whole-set size and encoded-manifest admission precede payload hash reads.
  New host CLI has no private-key/signing/staging/install/publish action.
  CLI missing-command regression, exact-byte fixture signing/verifier roundtrip,
  invalid declarations/no-output, payload substitutions, Linux FIFO/symlink and
  kernel-observed before-open size refusal pass. Complete Windows/pinned Linux
  host vet/tests and producer/CLI race3 pass. Declarations remain unproven
  source/model/version input, not build provenance or qualified compatibility;
  observed files are not retained immutable staging. Next qualify provenance,
  signing-key authorization/rotation and authenticated runtime roster delivery
  with the release/installer owner; no product trust or target transaction.
  **M10.2d — unambiguous GitHub API metadata (partial; host-tested):** before
  any asset request, require exact decoded consumed-field names, unique release/
  asset fields, required non-null scalar types and the bounded asset list.
  Missing publication flags are not false observations. Additional GitHub
  fields remain supported; their nested contents are not application metadata.
  Actual local HTTP regression reproduces duplicate `immutable` and missing/null
  `draft` acceptance before correction. Request counters prove refusal before
  all assets; positive escaped-name/extension controls preserve full signature/
  hash verification. Complete Windows toolkit vet/tests, pinned Linux whole
  toolkit vet/tests/race3 and 10,000 structural fuzz executions pass. No CLI,
  signature/trust-root/schema change, target installer, firmware build or device
  operation; release and recovery qualification remain separate.
  **M10.2e — host body-read diagnostic redaction (partial; locally tested):**
  response headers do not end the transport-error boundary. Manifest/signature
  reads and payload streaming now redact reader errors using the existing
  request wrapper, preserving programmatic cause/cancellation without exposing
  signed URLs in public messages. Real local HTTP/TLS plus an external-reader
  one-byte fault reproduces manifest and payload disclosure twice each before
  their separate fixes. All three asset stages refuse without later downloads,
  retry or positive verification, close once and clean temporary staging.
  Whole Windows toolkit vet/tests and pinned Go1.26.8 Linux whole toolkit
  vet/tests/race plus reader race-count3 pass. This is synthetic error-injection
  evidence, not an observed public GitHub credential leak. No API/schema/CLI,
  trust root, redirect, byte/timeout limit, firmware build or device change.
  **M10.2f — opt-in host strict-upgrade prerequisite (partial; host-tested):**
  `--require-upgrade` requires valid caller-supplied `--current-version` and
  refuses equal/older authenticated releases before payload I/O/staging.
  Existing advisory-only mode and exit status remain unchanged. Keep separate
  metadata-only `upgrade_prerequisite` evidence, never weaken the full-payload
  `update_policy` contract. Preserve signature/schema/model/revision/channel,
  signed GitHub tag and minimum-installer gates; a newer version still requires
  complete size/hash verification. Acceptance: CLI failure before implementation,
  immutable/nil/zero metadata boundaries, version/pre-release limits, missing/
  invalid input before HTTP/files, local unavailable-payload refusal, HTTP request
  counts, staging failure sentinel with positive control, preceding-gate and
  corrupt-payload refusals, legacy advisory behavior and whole host vet/race/fuzz.
  This is not installed-state attestation, durable anti-rollback, owner-approved
  downgrade recovery, signing/trust provisioning or target installation.
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
  **Partial Samba July packet:** six upstream advisories are reconciled with
  selected4.22.11 and190 archive-identical source files. Distinguish declared
  AD DC exclusion from actual compiled/installed CTDB; an absent CTDB init
  entry is not proof against all activation paths. The QEMU preview-parser
  fixture explicitly disables clustering and queries actual target `testparm`;
  this does not change the share-only renderer or qualify a product global
  profile, remove a build feature, settle lifecycle or close all advisories.
  Keep source-page inconsistencies and upstream's remaining CTDB packet-size
  protection requirement visible. [Review packet](support/DEPENDENCY-REVIEW.md#samba-july-advisorysource-cross-check-2026-10-15).
  **Build-only hardening increment:** existing QEMU and EX4 B2/B3 resolved-config
  auditors refuse unused `CONFIG_CRYPTO_USER_API*` builtin/module interfaces.
  Internal kernel crypto remains available; no AF_ALG hash backend or kernel
  change is introduced. Windows/Linux mutation tests, lint, actual QEMU6.18.55
  config audit and workflow contracts pass. B3 config6.18.54 is historical
  audit evidence only, not a current build. Current upstream
  [AF_ALG guidance](https://www.kernel.org/doc/html/latest/crypto/userspace-if.html)
  supports avoiding this interface; no specific-CVE or complete-security
  disposition, performance improvement or hosted-timeout fix is established.
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

The [M4.5 server-open integration packet](support/SMB-SERVER-OBSERVATION-PLAN.md)
now specifies fixed build closure, a separate server descriptor handoff, live
capture, containing authority, fault/lifetime controls and regression ordering.
The dedicated VFS/bootstrap boundary is now approved for host/disposable QEMU
only, with retained original references, no added privileges or generic-launcher
widening. A partial S1 loader prerequisite uses Samba's actual canonical loader
and registry; the module refuses CONNECT until trusted handoff/capture exists.
An optional partial S2 context probe now verifies a separate fixed bootstrap,
original endpoint handoff, root/FD/capability boundary and original-reference
checks after verified child/group settlement. Actual endpoint-loss and leaked-FD
mutations refuse. It does not launch smbd or supply containing execution authority.
A separate optional daemon fixture now qualifies actual pinned smbd startup,
the original executable/sender FD3, fixed guest-loopback SMB3.02 NEGOTIATE,
twelve constructor refusals, single-use startup review and verified stop before
descriptor release. No authentication/file OPEN or active VFS sample occurs.
Complete SDK/runtime closure and containing Owner composition, active producer,
lifetime binding and faults remain open: neither S1/S2 nor the server bridge is
complete. Next bind the retained code/channel authority, then qualify a bounded
still-open worker capture; no WRITE experiment is admitted by these prerequisites.
The same dedicated adapter now has a qualified discrete original-endpoint drift
check and actual smbd stop/retention/restoration-refusal case (partial S5 only).
Continuous supervision and complete module/configuration/worker/closure faults
remain required, alongside the containing authority work above.
A separate code-input prerequisite now retains the complete declared tree and
original fixed-path/unique-mount binding. Actual ARM rejects an identical copy
covering that path even while the original census still passes; caller-close,
foreign-root refusal and sticky review after restoration are checked. This
pre-startup probe is not yet joined to daemon containment and does not complete
SDK/module/bootstrap retention or S2/S4. Next compose those original authorities;
do not interpret the probe as live service activation or a pending-WRITE lease.
Client-launcher approval alone is not server approval. This does not waive the
failed full-integration/hosted gates or authorize product/NAS startup.

Dedicated observer composition now connects the declared immutable code and
independently built static bootstrap, fixed rendered configuration, original
state/share roots, both channel endpoints and fixed daemon adapter under one
private single-use lifecycle. Actual ARM receiver-option drift and live code
cover stop real smbd and retain originals/review; restoration cannot restart.
Parent FD equality, canceled cleanup, host close-uncertainty/copy refusals and
strict2+61 pass within original bounds. This advances partial S2/S5, not the
active worker bridge: complete module/SDK/producer closure, construction races,
continuous supervision, all worker/frame bindings and S3–S6 remain required.
No product startup, NAS or pending-WRITE admission follows from this experiment.

M4.5 TCP wire prerequisite (2026-10-11): a private QEMU-only decoder and
[focused check](support/test-pending-tcp-wire.ps1) now qualify fixed IPv4
ESTABLISHED framing/identity/bounds, interrupted/foreign/duplicate refusal and
copied completion-only rows. The kernel query exists only in tests: real
reciprocal loopback identities independently match descriptor Fstat/SO_COOKIE/
address/unbound-device observations and vanish after closure. Same-UID
connections to the same server endpoint remain distinct across 32 concurrent
queries; closing one pair preserves the other. Success/refusal preserve FD
counts, including cancellation immediately after the real request. Tagged
Linux vet/unit/race3, 10,000 fuzz executions and eleven
actual ARM926 cases repeated three times pass, source/base unchanged. No
default pipeline/campaign, launcher, Owner or product wiring is altered.
The later focused `pending` guest now composes original client/worker proc,
namespace and TCP binding with healthy closure (details in M4.5 above). Composed
adversarial fault controls and opaque SMB handle/request/extent/cache/journal
proofs remain required before WRITE/fault admission. Wire completion is not atomicity or
process/socket authority; the hosted timing gate remains unwaived.

The subsequent copied-pair comparison adds four cases to that same optional
runner (fifteen total, each repeated three times). It admits only two distinct
observed inode/cookie identities with reciprocal fixed loopback1445 endpoints,
refusing missing/cross-pair/reversed/duplicate/foreign/malformed/over-bound input
and canceled publication. Full copied UID/cookie/endpoint identities expose
continuity changes. Actual host/ARM two-connection descriptor oracles and
closure/peer preservation pass, along with tagged vet/race3/Windows preflight;
1323 source inputs/base unchanged. It is not connected to the Owner and does
not qualify the supplied inode census, principals, namespaces or actual SMB
handle/request. The original-process binding and all later gates remain open;
the default ten-campaign lane and deadlines are unchanged.

Local efficiency increment (2026-10-07): code inspection/preparation reuses
one 32 KiB scratch buffer per pass, with every original hash/metadata/identity
fence retained. Host digest allocation/chunk/cancellation/reuse regressions,
tagged race-count3/module vet and Windows/ARMv5 cross-compilation pass. The
114-digest host microbenchmark reduces allocated bytes from 3,739,200 to 36,416;
this is not appliance RAM, EX4 throughput or a demonstrated lifecycle-timeout
fix. Static Owner/service/native pass locally; the unchanged lifecycle guest
times out at180 seconds. A Go-source-identical shell timing diagnostic completes
preliminary work in about16 seconds, so that prefix alone does not explain the
failure. Resolve and requalify the original all-three union before a full image
or integration; earlier926-source proof does not cover the changed inspector.

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
   evidence. Initial native fixture status/revocation budgets were fixed4/10;
   the phase-accounted M0.3 fixture profile supersedes them with status4,
   control4 and aggregate20 seconds; ordinary commands remain status2/total5.
   Separate startup20/idle20/session45 phases
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

   The QEMU native runtime's own terminal teardown now preserves first errors
   from Owner/auth/helper release, stops later resources and retains observable
   review across repeated Close. Current real-file bookkeeping RED/GREEN and
   tagged module vet/three-count planner/runtime/coordinator race tests pass;
   normal-repeat control stays idempotent. This imports only the previously
   isolated wrapper contract, not its older ARM/image qualification. Requalify
   original all-campaign normal lifecycle and the combined image, then fault
   live worker/session teardown and durable recovery separately. No new
   constructor, callback, HTTP surface or device privilege is added.

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
   or automatic retry is introduced. Frozen `42d77be` also passes complete
   cached local integration: all 894 tracked API files match the compiled
   package/source archive, configured target stripping reproduces the installed/
   embedded/exported API, and seven artifact hashes verify. Hosted/clean
   qualification and broader faults remain separate.

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
     A complete immutable isolated candidate now binds NSS/grants/root requests
     and the six-field Plan freshness tuple. Host/race tests qualify immutability,
     refusals and matching; a focused ARMv5 service campaign qualifies exact
     declaration checks against actual mounted pins, seven mismatch refusals and
     sticky source-loss review. This is a prerequisite, not full composition:
     a positive candidate derived with `BuildFromOwners` against the SAME actual
     native identity Owner/backend and mounted handoff now passes complete
     cached local integration. Bounded Plan-derived configuration rendering also
     passes host/Linux and focused ARMv5 lifecycle tests, including granted-only
     lookup and byte-identical output after complete evidence recompilation.
     Next stage that exact configuration and descriptor grant set for the SAME
     identity/backend/native service Owner, retaining complete management lookup
     separately from granted-only daemon lookup without copying passdb or changing
     the backend. Rendering and candidate admission are not daemon consumption.
     A subsequent fixed two-share input-preparation prerequisite now passes
     Linux tagged/race tests and the complete three-campaign ARMv5 union. Both
     full configuration expectations are independently matched; credential
     workers retain management lookup while the data tuple duplicates the five
     service-config/seven state/two original RO/RW inputs. Actual fresh Plan/
     caller-close/busy-authority/runtime-close-before-release checks pass. No
     planned daemon starts and the inert-role startup refusal remains. Native
     owns the independent libc/config/handoff probes once; lifecycle still
     performs its OWN real bootstrap/enrollment and every original union proof
     and deadline remains required. Next qualify actual paired-role daemon
     consumption, complete same-service supervision and uncertain constructor/
     teardown paths; do not treat tuple preparation as a service Owner.
     Recompile
     complete storage/identity evidence at admission and supervision; a declaration
     match or candidate fingerprint is not a retained service lease. Preserve
     explicit stop/copy-close-before-pin-release and uncertain-close quarantine.
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
