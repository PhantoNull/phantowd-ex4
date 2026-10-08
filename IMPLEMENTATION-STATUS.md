<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation status

## Current complete cached integration — seven Samba scenarios and exact959 audit

Frozen `217d978c8861d1384a77e28b287505cbca77e38d`, API tree
`bfbfa25ab57e4457cd33709ded2dc080b085ec56`, passes the complete cached
Buildroot/host/ARMv5 lane and an independent post-terminal read-only audit on
2026-10-08. Original ordinary/race/fixed-fuzz/toolkit, standard smoke, MD/state,
launcher/runtime/loader/atomic, all **seven** independently enrolled Samba
scenarios and both synthetic SMART lanes pass with unchanged limits.

The complete original proof union includes same-authority startup/data access,
exclusive supervision, verified cancellation/stop, idle source-alias loss and
the original-owned idle exit described below. The latter requires retained,
unconsumed and settled worker inputs; review does not authorize release,
restart or recovery. Mid-transfer/held-session loss and uncertain construction/
teardown remain open.

All **959** API inputs match source, compiled package and legal source archive
without stale extras. Configured strip, installed/rootfs/exported API, all
seven ordered artifact hashes, actual Go 1.26.8 recipe/source/SDK/host licensing/
SBOM and Linux AND headers 6.18.55 agree. All **11,510** installed SDK files
match; **25,252** regular audit inputs and all **1,242** tracked build witnesses
recheck unchanged. See [measured artifact identities](support/DEPENDENCY-REVIEW.md).

Only the existing image/two project volumes are reused; no consumer remains.
This is cached local qualification, not independent clean reproduction,
exact-head hosted qualification, complete advisory review, EX4 operation,
migration, recovery, product activation or an installable release. PR #128/#129
retain their own failed QEMU checks; local success is not their timeout fix.
Older sections below retain their dated, narrower source scopes.

Build-only hardening now fences builtin/module `CONFIG_CRYPTO_USER_API*`
interfaces in the existing QEMU and EX4 B2/B3 kernel-config auditors. Public
CLI mutation regressions first reproduce acceptance, then pass after the guard;
all ten kernel-input tests, both-stage namespace refusals/internal-crypto
controls, lint and workflow contracts pass. The resolved QEMU6.18.55 config
already has these interfaces disabled and passes the new auditor. Historical
B3 config6.18.54 also passes, but is not a new build. No kernel selections,
fragments, crypto provider, image, API, privilege or timeout changes. This is
build-policy validation, not a new whole-image, security or performance result.

## Current release component — unsigned metadata producer, host-only proof

M10.2c adds the host `build-release-manifest` command and typed producer for
existing schema1. Explicit declarations/names/roles and a raw public key yield
sorted deterministic JSON with measured fingerprint/sizes/SHA-256; no private
key, signer, writer, publisher, VerifiedManifest or install authority. Existing
validators and bounded regular-file hashing are reused; whole-set size and
encoded JSON admission precede payload hash reads. Observed set/root drift and
missing/nonregular/empty payloads refuse with no metadata output.

The real CLI first fails as unknown, then the existing verifier accepts exact
output with test-only in-memory signatures and still refuses installation/
hardware authority. Whole Windows Go1.27 toolkit vet/tests and pinned Go1.26.8
Linux whole toolkit vet/tests plus producer/CLI race3 pass. Linux inotify
observes zero payload opens/accesses on a sparse over-budget set and verifies a
positive read control; FIFO/symlink refusal also passes. No GiB of test data is
allocated and no new Docker image/volume remains.

This prepares metadata, not a qualified firmware release. Source/model/version
declarations are caller input, files remain point-in-time observations, and
trusted provenance/immutable staging, key authorization/rotation, authenticated
runtime roster delivery, signed publication, target install/recovery and EX4
qualification remain open. No guest, image build, product API or NAS operation;
the existing QEMU lifecycle failures are unchanged.

## Current runtime component — final digest cancellation, host-only proof

The bounded regular-file digest helper now checks its context after EOF and
SHA-256 finalization, before emitting a digest/count. A deterministic test
cancels immediately after the last successful pre-read check and reproduces
the old completed result for 1, 32768 and 32769 bytes; all three return the
typed cancellation with zero result after the fix. Complete byte hashing,
size+1 and metadata/census/identity checks remain unchanged. No cache, skipped
scan, provider, privilege, retry or deadline change.

Pinned Go 1.26.8 non-root Linux tagged vet/tests and race-count3 for runtimebundle
and smbexec pass, including the existing digest/scratch regressions; ARMv5
runtimebundle tests cross-compile, not execute. Root-required fixtures may skip
under this profile. `Inspect` already had its own final context check: this is
an internal calculation-boundary correction, not a demonstrated admission
bypass, new whole-image qualification or the lifecycle timeout fix. No guest,
hardware or persistent resource creation; the timing-contract choice remains
open and the integration PRs retain their failed QEMU gates.

## Current UI component — authentication focus continuity, host-only proof

M5.5b adds a main-content skip link, non-tabbable focus destinations and shared
keyboard/system-color focus styles. Before an authentication transition hides
the active control, focus moves to the newly visible heading without scrolling.
Initial status, unchanged views, unrelated controls and retired replies do not
steal focus. No request, retry, endpoint, privilege, poll or activation changes.

The actual-source DOM regression fails against prior `fa97910` JavaScript for
the missing login destination, then the complete suite passes with three new
focus groups including setup, expiration, both logout scopes, unavailable auth,
password-change uncertainty and stale replies. Windows Go 1.27.0 API/UI/vet,
tagged contracts and ARMv5 test cross-compilation pass. Pinned Go 1.26.8 Linux
host vet and embedded dashboard/self-test asset checks also pass in one bounded,
auto-removed non-root container with the existing read-only workspace.

No new image/volume or guest/hardware run. DOM/source assertions do not qualify
real-browser focus/rendering, assistive technology, contrast, WCAG, a complete
changed image or hosted integration. The `217d978` complete-image checkpoint
above remains historical and does not cover these changed assets. Existing
QEMU coordinator failures and integration gates remain open.

## Current component — original-owned exit, focused host/QEMU proof

On 2026-10-08, a new independently enrolled ARMv5 `exit` guest passes the fixed
original-owned daemon exit scenario. It completes real startup/data access and
an exclusive supervision scan before a single-use signal through the original
owned `os.Process`. No caller supplies a PID, group, executable or signal.
Canceled and duplicate requests refuse. The actual supervisor retains review,
verifies whole-group stop/reap and preserves all 15 private inputs, original
runtime references and both busy identity/share authorities. Normal-stop
classification, restart, recovery and authority release remain refused.

Unexpected exit can refuse a credential worker after its inputs were prepared
but before execution. The separate reviewed-stop witness now explicitly checks
that retained capture is **unconsumed and settled**, without closing/retrying it.
Executed, closed or uncertain captures refuse. This corrects the new witness's
initial blanket rejection of pending handles; it does not alter the runtime's
safe retention or the original normal/held-client observers. The real failing
guest preceded the fix; no healthy runtime or positive stop is fabricated in
host tests. Temporary diagnostic instrumentation was removed.

Pinned Go 1.26.8 Linux vet, seven-package tests/race-count3, ARM5 cross-build,
65 Linux verifier tests and the focused actual guest pass. Parent descriptor
equality, private child disposal, complete runtime census and unchanged base
remain mandatory. All 959 API inputs and six harness files match before/after.
One compilation now passes all seven fresh campaigns, their complete ordered
proof union, equal full runtime censuses and unchanged base. Complete image
qualification is recorded above, separately from this component proof.
Original guest/worker/readiness/stop
limits are unchanged. This qualifies a completed-transfer/idle exit fixture,
not mid-transfer/held-session loss, constructor/uncertain-stop coverage,
product activation, physical EX4 operation, migration or installation.

## Earlier component — reviewed-stop observations, host-only refusal proof

Separate QEMU-only `ObserveNativeDataReviewStopQEMU` and
`ObservePlannedReviewStopQEMU` are implemented as read-only observations.
The normal planned-stop and older held-client observers are unchanged.
Reviewed-stop success requires the exact launched generation, sticky review,
verified owned-command/group teardown, all 15 private process inputs retained,
absence of the runtime's original group, dormant prepared clients and retained
runtime code/configuration/state. Missing, incomplete, canceled, competing or
closed lifetimes refuse; the observation does not signal a process, retry
Stop/Close, release authority, re-admit inputs or clear review.

Pinned Go 1.26.6 Linux vet, seven-package tests/race-count3, ARMv5 cross-build,
64 Linux verifier tests and no-Docker Windows API/UI/lab preflight pass on
2026-10-08. Host tests fabricate no healthy or successfully stopped runtime.
These are **negative host proofs and a cross-build**, not actual ARMv5 reviewed
teardown qualification. A genuine composed unexpected-exit trace and fixed
original-process-handle trigger remain separate work; neither exists in this
increment. No HTTP/product activation or NAS operation is added. The complete
950-input image below retains its original source scope. The newer 954-input
image includes these four files and passes the original campaigns, but does
not supply a positive composed unexpected-exit/reviewed-stop trace.

## Earlier complete cached integration — Go 1.26.8 and exact954 audit

Frozen `970483e095c54186de9f53e4a164bc44c2b3cfd0`, API tree
`7b612fe28e5a0304d40664cf72816ece027af0dc`, passes one complete cached
Buildroot/host/ARMv5 integration run and a separate independent post-terminal
read-only audit on 2026-10-08. Ordinary/race/fixed fuzz, standard smoke,
MD/state reboot, launcher/runtime/loader/atomic, all six independently enrolled
Samba guests and both synthetic SMART lanes pass with their original limits.
The complete proof union includes normal exclusive composed supervision and
the completed-transfer/idle source-alias-loss fault, not the pending composed
unexpected-exit or positive reviewed-stop scenarios.

All **954** API files match source, compiled package and legal source archive,
without stale extras or generated-marker exemptions. The selected recipe,
official SDK/source hashes, all **11,510** installed Go SDK files, actual linked
Go 1.26.8/CGO0/Linux ARM5, host licensing/SBOM, configured strip and installed/
rootfs/exported API agree. All seven ordered artifact hashes, Linux AND headers
6.18.55 source/license/SBOM/legal/release bindings agree. All 1,237 tracked
source witnesses remain unchanged; 24,959 regular audit inputs are rechecked.
Only the existing image/two project volumes are reused; no workspace consumer
remains. See [exact artifact identities](support/DEPENDENCY-REVIEW.md).

This is cached local qualification, not independent clean reproduction,
exact-head hosted qualification, a hosted-timeout fix, complete advisory review,
physical EX4 support, migration, recovery, product activation or installation.
Require the publication head's own hosted checks before integration.

## Earlier complete cached integration — six Samba scenarios and exact950 audit

Frozen `5355a5cb033ecd1106294c4fcd4bb256fe2e3e2a`, API tree
`82955d54b74934ae4fcf1351339a39483a5fa40f`, passes one complete cached
Buildroot/host/ARMv5 integration run and a separate independent post-terminal
read-only audit on 2026-10-08. Ordinary/race/fixed fuzz, standard smoke,
MD/state reboot, launcher/runtime/loader/atomic, all six independently enrolled
Samba guests and both synthetic SMART lanes pass. Every original proof,
complete runtime census and unchanged-base check remains required.

The complete image includes normal composed supervision, separate planned-stop
observation and the completed-transfer/idle source-alias-loss fault below.
All **950** API inputs match the compiled package AND collected source archive,
with no stale extras or generated-marker exemptions. Configured stripping,
installed/rootfs/exported API, seven ordered artifact hashes, Linux AND headers
6.18.55 source/license/SBOM/legal/release bindings and linked Go 1.26.6/CGO0/
Linux ARM5 agree. All 950 pre-build source witnesses remain unchanged;
1,923 regular audit inputs are rechecked. Only the existing image/two project
volumes are reused; no workspace consumer remains after verification.
See [exact artifact identities](support/DEPENDENCY-REVIEW.md).

This is cached local qualification, not an independent clean build, hosted
timeout fix, physical EX4 support, legacy migration, recovery, product service
activation or installation. Composed unexpected exit, held sessions/mid-transfer,
worker cancellation and uncertain construction/teardown remain separate gates.
The prior integration head `2c2c04c` failed its own hosted coordinator continuity
test at the fixed 45-second budget; cause remains unproven. Require the updated
publication head's own hosted checks before integration.

## Current component — composed source-loss supervision, focused host/QEMU proof

On 2026-10-08, pinned Linux seven-package checks, race-count3, ARMv5 cross-build,
64 Linux verifier tests and the actual focused fault guest pass. After genuine
enrollment, the SAME planned identity/backend, complete mounted roster, share
pins and daemon survive startup, real access and a complete exclusive scan.
Covering ONLY the synthetic volume alias triggers review and verified owned
daemon stop/reap. All 15 private inputs and runtime code/configuration/state
references remain retained; BOTH original authorities refuse premature Close.
Removing the identity-checked cover restores the original mount, but start,
observation, data access and supervision remain refused in sticky review.

The child has a separate private mount namespace. It exits only after the stop,
retention and non-revival witnesses, without normal-path cleanup or a forced
release of reviewed authorities. Parent descriptor equality and the prior
identity-fault proof pass before the new mandatory marker is accepted. This is
fixture disposal, not product recovery. Original mounts/grants are not detached;
no real disk, TDB mutation or device write is used to trigger loss.

The first actual guest exposed missing empty child share destinations in the
new fixture. Shared create-only preparation now serves both fixed callers;
all C type/mode/ownership checks remain intact. Temporary diagnostic probes are
removed before the clean regression passes. No original timeout is expanded:
the new child has preparation10/startup40/access20/supervision20 and parent90;
the original identity-fault40, guest180 and runtime guards remain unchanged.

This qualifies completed-transfer/idle source-alias replacement, not physical
disk failure, active sessions, mid-transfer/worker cancellation, unexpected exit
or uncertain teardown. The updated complete six-guest union and whole 950-input
image/audit now pass separately, as recorded above.
This is not a fix for the hosted coordinator timeout, product activation, HTTP
surface, migration, recovery or EX4 qualification.

## Current component — planned-stop observation, focused host/QEMU proof

On 2026-10-08, the separate QEMU-only `ObservePlannedStopQEMU` passes pinned
Linux seven-package checks, race-count3, ARMv5 cross-build, 63 Linux verifier
tests and all six independently enrolled ARMv5 guests using one compilation.
The complete ordered proof union and unchanged census/base pass. The same service's daemon is observed
live before supervision and stopped/reaped afterward, with all 15 private
daemon inputs plus the original code, management/service configuration and
state references retained. Repeated observation does not release authority;
closed runtime observation refuses. The final descriptor census and unchanged
base checks pass before the new mandatory proof is accepted.

The runtime constructor prepares two held-client handles even in the data
profile. This observer requires them to remain dormant: exact members, zero
generations/PIDs and no launch attempt. The legacy two-client observer is
unchanged and is checked against the real unstarted, live and stopped runtime.
An initial actual-guest refusal exposed and corrected a mistaken nil-client
assumption; host-only tests did not qualify a healthy runtime.

This is retention/stop evidence, not fresh input validity, recovery authority,
composed source-loss/uncertain-teardown coverage or a hosted timeout fix. The
earlier 948-input component union passed independently. This observer is now
included in the separately qualified complete 950-input image above; that
later proof does not expand this observer's retention-only contract.
No deadline expansion, product activation, HTTP surface or NAS access is added.

## Current component — composed Samba supervision, normal host/QEMU proof

On 2026-10-08, `NativePlannedServiceQEMU.Supervise` passes pinned Go 1.26.6
tagged Linux checks, seven-package race-count3, ARMv5 cross-build, 62 Linux
verifier tests and all six actual disposable ARMv5 guests using one compilation.
Complete 114-file/27,384,058-byte censuses agree; every original campaign proof,
new mandatory supervision proof, FD equality and unchanged base check pass.
Windows API/UI/lab preflight also passes. The corrected component is included
in the complete 946-input cached image and independent audit below.

The SAME original identity Owner/backend, mounted roster and share pins survive
startup, actual access and supervision. One exclusive loop serializes complete
storage-first/identity checks, refuses competing lifecycle operations, stops on
accepted idle cancellation and retains both originals until separate successful
full runtime closure. No retry, restart or replacement authority is admitted.
The new supervised fixture action is independently bounded to 20 seconds;
prior phase, worker/readiness/stop and guest180 guards remain unchanged.

Only the normal path is qualified here. The separate idle source-alias fault
is qualified above; composed unexpected exit,
mid-worker cancellation and uncertain stop/close need coordinator-specific
proofs; earlier identity-only faults cannot substitute. Product authorization,
storage/identity lifetimes, durable recovery, hosted/clean/EX4 and install gates
remain open. No HTTP surface or NAS operation is added. See the
[component contract](src/phantowd-api/internal/smbexec/README.md#planned-service-and-fixed-data-access-qemu-only).

Post-run review found and corrected a telemetry regression in the factored stop
path: pre-existing close uncertainty must publish `review-required` even when
cleanup is not retried. A pinned Linux negative-only Close/Status test reproduces
the missing snapshot, then passes after restoring publication. It uses an invalid
runtime that cannot execute or own processes, not fabricated healthy evidence.
This host refusal proof does not qualify a live daemon's uncertain teardown.

## Earlier complete cached integration — six Samba scenarios and exact946 audit

Frozen `1e68966f91d27c6d449a7624212720cf3d7da86b`, API tree
`0280c9719f3ac808b5a5d25c077492a81e6bc954`, passes one complete cached
Buildroot/host/ARMv5 integration run and an independent post-terminal read-only
audit on 2026-10-08. Standard smoke, MD/state reboot, launcher/runtime/loader/
atomic, all six independently enrolled Samba guests and both synthetic SMART
lanes pass. Every original proof and each complete runtime census remain required.

All **946** API source files match both the compiled package and collected
source archive, with no stale extras or generated-marker exemptions. Configured
stripping, installed/rootfs/exported API, seven ordered hashes, actual images,
kernel AND headers 6.18.55 source/license/SBOM/legal/release bindings and linked
Go 1.26.6/CGO0/Linux ARM5 agree. All 946 before/after source hashes match;
1,915 regular audit inputs are rechecked. Only the existing pinned image and
two project volumes are reused. See [exact artifact identities](support/DEPENDENCY-REVIEW.md).

This qualifies the current cached local image, not independent clean builds,
the new publication's own hosted checks, a causal fix of the hosted
failure, physical EX4, migration, product service activation or installation.
Normal retained startup/access and composed supervision are tested; complete
grants/ACLs, constructor/late-close and composed supervision faults remain open.

The earlier integration checkpoint `2c2c04c` has a passing host check but its
[own hosted QEMU run](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37753497490)
fails during identity-coordinator disable/peer continuity at the fixed
45-second fixture deadline. Its first worker classification is pre-admission/
other, not proof of lost peer connectivity. Cause and a regression fix remain
unqualified; do not merge that checkpoint on the strength of this local pass.

## Earlier QEMU component — independently enrolled bounded scenarios

On 2026-10-08, the updated Samba lane passes pinned Go 1.26.6 tagged vet,
seven-package tests and seven-package race-count3, ARMv5 cross-build, all 61
Linux verifier tests and all six actual ARMv5 guests. One overlay compilation
runs service, native, candidate, lifecycle, fault and data with matching complete
114-file/27,384,058-byte censuses, all original proofs and an unchanged base.
Windows API/UI/lab preflight and mock-only wrapper guards also pass.

The previous compound lifecycle exceeded guest180 after healthy candidate and
startup. Each scenario now has its own genuine disabled-first enrollment;
no passdb, lease or pins cross boots. SAME within-trace authorities, FD counts,
worker/readiness/stop/guest limits and failure retention remain required.
Candidate's distinct declaration/prepared-input workloads now receive separate
30-second contexts rather than sharing30. Five deterministic fake-clock tests
cover ten refusal/cancellation/budget cases, including late nil and no retry;
the aggregate change is QEMU-only, not a product deadline extension.

The updated complete cached image/source audit now passes as recorded above.
This is not a repair of the earlier hosted run. Exact-head hosted checks and
independent clean/physical/product gates remain open. The older 943-input
image below retains its exact historical source scope.

## Earlier complete cached integration — same-authority startup/data and exact943 audit

Frozen `2ce88f03ee2211f03e1efb73426aab0bccf0efe3`, API tree
`aa88877c1336c4d20f9eeb0def51ea8daf8de84a`, passes the complete cached
host/ARMv5 driver on 2026-10-08. Standard smoke, MD/state reboot, native
launcher/runtime Owner/loader/atomic, all four Samba guests and both synthetic
SMART lanes pass, preserving every original assertion and deadline.

The independent post-terminal read-only audit matches all **943** source
inputs against the compiled package and legal source archive, with no stale
extras or generated-marker exemptions. License copies, configured strip,
installed/exported/rootfs API, seven ordered hashes, actual images, kernel AND
headers 6.18.55 archives/licenses, selected metadata/SBOM/legal/release and
linked Go 1.26.6/CGO0/Linux ARM5 agree. All 943 before-build source hashes remain
unchanged; 1,909 regular audit inputs are rechecked. Existing image and two
project volumes are reused; no new image/volume or broad prune is required.

This includes the normal same-authority planned startup/data tracer below,
not complete grant/ACL, constructor/late-close fault or supervision proof.
Cached local success does not qualify independent clean reproducibility,
complete advisory/licensing compliance, physical EX4, migration, installation
or product activation. The earlier prepared941 checkpoint's own hosted QEMU
run [37734668729](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37734668729)
fails during planned candidate construction with post-admission/deadline;
this newer local success does not repair that failed run or establish its cause.
Exact-head hosted qualification remains open.

## Same-authority SMB access — local host/QEMU component qualification

Code checkpoint `e3e1d5b845b72558688ec37aedfec23307853c9f` adds a single-use,
fixed `VerifyDataAccess` probe through the already-running planned service.
The SAME identity Owner, startup-fixed backend, complete mounted roster and
original share pins remain retained. Fresh complete observations bracket the
probe outside the runtime gate; full code/configuration/state/child checks
bracket each of its six bounded SMB clients.

On 2026-10-08, Windows API/UI preflight, pinned Linux tagged vet/package tests,
six-package race-count3, ARMv5 cross-build, all 59 POSIX verifier tests and all
four actual Samba guests pass locally. The data guest verifies transfer bytes,
effective Unix ownership, kernel read-only enforcement, write/symlink denials,
enabled-but-ungranted authentication denial, canceled/repeated probe refusal
and runtime-close-before-authority-release, with final descriptor equality.
`DataVerified` records completion of that probe, not ongoing health or authority.

The former expanded native guest exceeded its 180-second cumulative limit.
A reduced diagnostic completed the new work in about 37 seconds; its incomplete
proof was correctly refused. After removing all temporary probes, one compiled
overlay runs four fresh snapshots: service, native, lifecycle and data. Each
guest creates its own state and hashes its complete runtime. Every prior proof
remains mandatory, with matching censuses, original deadlines/privileges and
no retries or new Docker images/volumes. This does not establish a causal fix
for intermittent hosted enrollment or other CI timeouts.

This is fixed normal access qualification, not a complete ungranted UNC/mixed
ACL matrix, constructor/late-close fault proof, continuous drift supervision,
product activation, HTTP route or EX4 qualification. The changed 943-input
cached image/source audit now passes as recorded above; exact-head hosted
checks and independent clean reproduction remain separate. The earlier
prepared941 audit below is not borrowed as proof for this successor.

## Earlier same-authority planned startup — local component qualification

Code checkpoint `8dcd541d29acb253c03320e0d712d511bbe51dbb` adds single-use
`NativePlannedServiceQEMU.Start`. The coordinator retains its original identity
Owner, startup-fixed backend, complete mounted roster and declared share pins.
Fresh complete planning brackets startup outside the runtime gate. The daemon
uses the separately retained service configuration; credential workers retain
management lookup. Live verification compares both original data objects and
their exact protected RO/RW child views. No backend is selected per operation.

On 2026-10-08, Windows API/UI preflight, pinned Linux tagged vet/package tests,
six-package race-count3, ARMv5 cross-build and all three original Samba guests
pass locally. The new mandatory startup proof verifies canceled/duplicate
refusal, busy original authorities while live, fresh complete observation and
runtime-close-before-release. All 56 POSIX driver tests pass, all prior proofs
remain mandatory, and guest/worker bounds and privileges are unchanged.

This normal startup tracer explicitly claims **no data transfers by this
coordinator**, no product activation or HTTP route. The older isolated data
probe remains independent and does not gain complete storage/identity scope.
Constructor/late-close faults, live data/grant/ACL checks and complete drift/
supervision qualification remained open at this earlier checkpoint. The newer
943-input cached image/source audit now passes above; the prepared941 record
below remains historical. No hosted timeout fix, independent clean-build,
EX4, installation or release qualification follows from these local tests.

## Prepared same-authority coordinator — complete cached local qualification

`NativePlannedServiceQEMU` now privately copies policy, compiles its SAME
identity/storage authorities, binds share pins to the original roster, retains
the Owner's startup-fixed backend and closes runtime copies before original
identity/share authorities. Its pure plan derivation uses ONE freshly verified
retained identity observation under storage-first lock ordering, not cached
evidence or a replacement backend. Normal construction/observation/closure,
caller-policy isolation and original-roster refusal pass pinned Linux tagged
tests/race-count3, Windows preflight and the complete three-guest ARMv5 union.

The union retains every original independent proof; inspector refusal/retention
experiments run once in service, while native/lifecycle still hash their OWN
complete runtime. Bounds, privileges and per-worker admission fences remain.
Earlier timeout evidence is preserved: this pass does not establish a hosted
timeout fix, independent clean reproduction or physical performance.

That frozen prepared checkpoint had NO Start, HTTP/product activation or product policy lease.
Constructor/late-close uncertainty and live same-authority data access/
supervision remain open. The complete 941-input build and independent
source/image audit now pass as recorded below. Hosted exact-head, independent
clean reproduction, physical EX4 and all product/release gates remain separate.

## Earlier cached integration — prepared coordinator and exact941 audit

Frozen `19d189178d155bb6a721d775495b45136809c96f`, API tree
`e8ba603a77553d715564e155789d2525ce4a1e59`, passes one complete cached
Buildroot/host/ARMv5 driver on 2026-10-08. Ordinary/race/fixed-count fuzz,
standard smoke, MD/state, launcher/runtime/loader/atomic, all three original
Samba campaigns and both synthetic SMART lanes pass. The four-job ceiling,
assertions, privileges and guest/operation deadlines are unchanged.

The independent post-terminal read-only audit matches all **941** API inputs
against BOTH compiled package and collected source archive, rejecting stale
extras with zero generated-marker exemptions. Declared licenses, configured
stripping, installed/image/exported API, ordered seven hashes, actual Linux
AND headers 6.18.55, SBOM/release/legal-source/license and linked Go
1.26.6/CGO0/Linux ARMv5 agree. Twenty-one regular inputs recheck unchanged;
all thirteen component-tested code hashes match before and after the audit.

The API is 10,708,180 bytes, SHA-256
`a8ef0ccd990c37eb4fccaf2df0f3ff57194c856e811cc4c51ca13d88e45713de`.
Exact archive/rootfs/manifest hashes are recorded in the
[dependency qualification record](support/DEPENDENCY-REVIEW.md).
This is not independent clean reproduction, a hosted timeout fix, complete
advisory/release licensing review, planned daemon consumption, complete
service supervision, physical EX4 qualification or installation.

## Planned native inputs — host and ARMv5 prerequisite

The QEMU-only runtime now prepares one fixed two-share process tuple from
independently derived complete management/service expectations. Credential
workers keep management lookup; the prepared data tuple duplicates the five
service-configuration inputs, seven original state directories and two declared
RO/RW O_PATH roots. The trusted caller freshly compiles the same Owner/storage
evidence and retains original share pins and identity authority outside the
runtime gate until verified runtime closure. Input preparation starts no daemon;
all existing start APIs still refuse the inert service role.

Actual local Linux tagged vet/tests, focused race-count3, ARMv5 cross-build,
Windows API/UI preflight and all three disposable ARMv5 Samba campaigns pass.
The complete original union verifier independently passes with equal 114-file/
27,384,058-byte runtime censuses. New mandatory evidence covers original input
preparation, separate configuration roles, caller closure, busy authorities and
runtime-close-before-release, alongside existing startup/fault/FD checks.

An earlier lifecycle attempt times out and remains failure evidence. Independent
libc/configuration/handoff scenarios now run once in the native campaign;
lifecycle still bootstraps and enrolls its own real accounts. Every original
proof remains mandatory in the three-guest union, with unchanged guest/operation
deadlines and privileges. This local pass does not establish a hosted timeout
fix, physical efficiency, planned daemon consumption or complete service Owner.
Constructor-close/late-uncertainty faults, fresh identity/storage supervision,
and product/hardware gates remain open. The new complete image/source audit
now passes as recorded below.

## Earlier cached integration — original planned inputs and exact939 audit

Frozen `0d12dca66bcaa41f80666aeebcac0145f64e92c2`, API tree
`599446ec8424e9622683cea9a156d4a347759c8f`, passes the complete cached
Buildroot/host/ARMv5 driver on 2026-10-08. Ordinary/race/fixed-count fuzz,
standard smoke, MD/state, launcher/runtime/loader/atomic, all three original
Samba campaigns and both synthetic SMART lanes pass. The original four-job
ceiling, assertions, privileges and guest/operation deadlines are unchanged.

The independent post-terminal read-only audit matches all **939** API source
files against BOTH compiled package and collected source archive, rejecting
stale extras with zero generated-marker exemptions. Declared licenses,
configured stripping, installed/image/exported API, ordered seven hashes,
actual Linux AND headers 6.18.55, SBOM/release/legal-source/license and linked
Go 1.26.6/CGO0/Linux ARMv5 agree. Twenty-one regular-file witnesses recheck
unchanged. No previous image or 937-input census is adopted as this proof.

The normal API is 10,708,180 bytes, SHA-256
`e383bca363eb5c5204c3d3f4cfae262f62afdbc57e655839749a5f82a4e85be5`.
Exact source archive, rootfs and manifest hashes are recorded in the
[dependency qualification record](support/DEPENDENCY-REVIEW.md).
This is cached local integration, not clean reproduction, a hosted timeout fix,
complete advisory/release licensing review, paired-role daemon consumption,
complete service supervision, physical EX4 qualification or installation.
Exact-head hosted and all remaining product/storage/recovery gates remain.

### Earlier cached parent — bounded build jobs and native phase visibility

Frozen `4ca65d557c746eec08d36dadf72a97bdcbce9757`, API tree
`677a3f8f76122ab310c5763d6cd0ee631ace4543`, passes the complete cached
Buildroot/host/ARMv5 driver on 2026-10-08. All original campaigns, assertions
and guest deadlines remain, including three Samba campaigns and synthetic
SMART producer/capture. The actual driver selects four compile jobs from
its visible CPU quota rather than the host's 24-CPU count.

The independent post-terminal read-only audit matches all **937** API inputs
against BOTH compiled package and collected source archive, with zero stale
extras or generated-marker exemptions. All original license, strip, installed/
image/export, seven-hash, kernel/header, SBOM/release/legal-source and linked-Go
predicates pass; 21 regular-file witnesses recheck unchanged. Two added sources
are QEMU-tagged timing/tests; the normal product API and seven final artifacts
retain the earlier Linux 6.18.55 hashes. The new source archive is recorded in
the [dependency qualification record](support/DEPENDENCY-REVIEW.md).

Fixed QEMU-only phase observations are explicitly nonqualifying and cannot
replace any mandatory acceptance marker. Native/race/refusal and original
focused ARMv5 controls pass. This is not a demonstrated speedup, hosted Samba
timeout fix, clean reproduction, service activation or deployable image.
Exact-head hosted and all EX4/storage/recovery/installation gates remain open.

## Linux 6.18.55 — complete local ARMv5 integration and exact artifact audit

The complete Buildroot driver terminates successfully on frozen
`fb2f68c6cded66db1a118c21fa99ca8fad2bfc6d`, API tree
`5d819e6b9ad72b849f2fb3c3c27c1b2c47a114ff`, in the new configuration-derived
output namespace. It rebuilds the toolchain, Linux/headers and userspace;
the previous output is not relabelled as the new version. Ordinary/race/fixed-count
fuzz, standard smoke, MD comparisons, state reboot, launcher/runtime/loader,
atomic dispatch, all three Samba campaigns and synthetic SMART lanes pass with
their original assertions and guest deadlines.

An independent post-terminal read-only audit matches all **935** tracked API
inputs against both the exact compiled package and source archive, with zero
generated-marker exemptions. It reproduces configured stripping and proves
installed/image/exported API equality and all seven ordered artifact hashes.
The actual kernel AND headers, package namespaces/downloads, SBOM project and
components, installed/source/image release, output/export images, legal manifest,
both authenticated kernel source archives, kernel license copies and linked
Go 1.26.6/CGO0/Linux ARMv5 settings match. Twenty-one file witnesses recheck
unchanged; nonregular inputs and generation/alias drift refuse.

The API remains 10,708,180 bytes, SHA-256
`aaf55b14c1c9ffe9f44144086ccdb01e9ca4af5726fec7e34cf5c84d9d28e2c0`.
The new complete rootfs is
`8f37bfa289f7e260853c20705bdcf6341beffded9c50986676501cb74899fb5d`.
This supersedes the included update's pending local full-image statements,
not historical hosted failures, clean reproducibility, complete component/CVE
or release licensing review, EX4 profile/hardware or installation gates.
No NAS or production disk is touched.

### Earlier focused source and kernel controls

The authenticated Linux 6.18.55 source compiles with the existing ARMv5
toolchain and an exactly unchanged configuration-symbol set. The original
standard QEMU smoke passes with all assertions and its 240-second budget,
using the previous userspace and only an aligned expected-kernel field in a
disposable rootfs copy. API/readiness-script bytes and all seven original
artifact hashes remain unchanged. EX4 Stage B3 DTS bytes also match the
6.18.54 control, but this is not an EX4 kernel build or hardware proof.

Five configurations/release metadata files, both kernel/header archive hashes
and the version-qualified GPL hash patch/driver now select 6.18.55 together.
Local version/workflow, kernel-input, shell, dashboard DOM and actual upstream
GPL-patch preflights pass. The complete local rebuilt image/campaigns and audit
now pass above; exact-head hosted checks remain required. Existing public CI
failures are not fixed or waived.
The [dependency record](support/DEPENDENCY-REVIEW.md) distinguishes the focused
proof from the unchanged prior image and the remaining qualification gates.

## Dependency review — partial advisory coverage, other updates pending

The [2026-10-07 dependency review](support/DEPENDENCY-REVIEW.md) checks the
actual local package inventory and embedded API compiler metadata against
selected official advisories. Linux 6.18.55 now has the complete local proof
above; host OpenSSL 3.5.9 and Go 1.26.8 remain update candidates. This is not
a renewed full advisory review of the changed kernel. OpenSSL is host-only
in this inventory, whereas the Go SDK also supplies the target executable's
runtime. Exact backports and complete component/exposure dispositions remain
release gates. This is not an all-package security audit, QEMU timeout fix,
public-head qualification or installable firmware.

## Buildroot archive cleanup — complete cached integration qualified

The pinned archive helper's documented successful cleanup now removes its
empty `mktemp` marker alongside its three work files. The real unmodified
function fails the new disposable-file regression; the patched function
passes content, exclusion, unrelated-file preservation and repeatability checks.
An original-versus-patched differential produces identical compressed bytes.

The QEMU build applies the one-line patch only after source authentication and
before package downloads/builds. Exact original/patched helper and patch hashes
gate idempotent application; unknown, missing or symlinked inputs refuse.
Focused tests use read-only existing sources and small disposable tmpfs only.
The frozen `d2320541dd67c56ad17c7a6bcaae38fe686be03f` source passes the
complete cached host/ARMv5 build after the normal build hook applies this patch.
All three original Samba campaigns, actual mounted share-close quarantine and
synthetic SMART lanes pass with unchanged assertions and deadlines. An independent
post-terminal read-only audit matches all 935 API inputs against BOTH compiled
package and source archive, with **zero generated-marker exemptions**, declared
license bytes, configured stripping, installed/image/export equality and seven
ordered artifact hashes. No unexpected input is deleted to obtain success.

The API is 10,708,180 bytes, SHA-256
`aaf55b14c1c9ffe9f44144086ccdb01e9ca4af5726fec7e34cf5c84d9d28e2c0`.
The independently measured source archive and artifact hashes are unchanged;
the cleanup corrects producer bookkeeping without changing archived contents.
This does not clean historical markers in unrelated packages, qualify failure/
interruption cleanup, resolve Samba's intermittent hosted timeout, qualify clean
reproducibility/release compliance or authorize deployment. No NAS operations.

## Previous combined checkpoint — before the archive cleanup correction

Frozen `b25dea169c3048fc867abb4ea46f2f0584536349` passes the complete cached
host/ARMv5 build, including all three original Samba campaigns, the new actual
mounted share-close case and synthetic SMART producer/capture. A post-terminal
read-only audit verifies all 935 tracked API inputs against the compiled package
and exact source archive, declared license copies, configured stripping,
installed/image/exported API equality and all seven artifact hashes.

The package census separately accounts for one exact zero-byte archive marker
created after API compilation. The upstream Buildroot archive helper's omitted
marker cleanup reproduces three times in disposable RAM; no generic `tmp.*`
exception, source deletion or runtime modification is used. At that frozen
checkpoint the cleanup defect was unfixed; the newer focused correction above
was still only focused-qualified at that earlier checkpoint. The newer complete
post-patch qualification above supersedes that limitation. API SHA-256 is
`aaf55b14c1c9ffe9f44144086ccdb01e9ca4af5726fec7e34cf5c84d9d28e2c0`.

This is cached local qualification, not clean reproducibility, complete release
licensing, deployment or timeout resolution. PR #123's own `00d9445` QEMU run
fails in the native campaign at the original 180-second bound after descriptor
handoff with no final enrollment marker; that marker is emitted after the whole
campaign, so its absence does not locate a pre-enrollment failure. A separate
intentional shell-only SIGQUIT90 diagnostic samples fresh data-runtime hashing
after prior authority closure, not the original hosted timeout. All temporary
instrumentation is removed. Service passes; later hosted lanes remain unqualified.
Both public integrations remain held. No NAS or persistent device action.

## Declared-share close quarantine — actual mounted ARMv5 fixture

The focused disposable launcher lane now qualifies healthy original mount,
roster and two-share admission before a controlled premature original-FD close.
Repeated public operations retain review, the later original, both original
grant mounts and complete roster; replacement admission and new descriptor
copies refuse. Independent never-launched fixture disposal verifies exact clone
identities, closes remaining known inputs once and never resets review or the
handoff reservation. All earlier launcher controls, final FD equality, the
original 90-second guest bound and seven unchanged base hashes pass.

This extends existing correct behavior's qualification, not product runtime
behavior. The first guest failed because the new test expected `review` instead
of the existing `unavailable` refusal from an already-reviewed handoff; the
assertion was corrected, without changing its public error contract. No actual
Samba daemon consumes these roots. Kernel EIO, live-child uncertain stop/close,
durable recovery, production composition and physical EX4 gates remain open.
The older complete 934-input image/audit does not qualify this changed fixture.

## Declared-share input close tests — host bookkeeping only

Actual temporary `O_PATH` descriptors now characterize the existing reviewed
release contract. A preclosed original prevents handoff teardown and preserves
later inputs; repeated and concurrent calls cannot revive the lifetime, retry
cleanup or touch a test-only replacement. A known-close control is idempotent,
revokes further descriptor use and does not grant absent mount authority.

Pinned Linux tagged vet and full mountowner package race-count3 pass; Windows
API/UI/vet and ARMv5 cross-compilation also pass. This is added coverage of
existing behavior, not a reproduced bug/fix or actual mounted-roster admission.
No healthy mount lease is fabricated or verified by these host tests. The
separate actual guest case above covers controlled premature-close authority;
kernel EIO and product recovery remain separate requirements.
The earlier combined cached proof below keeps its exact 934-input source scope;
it does not cover the newly added test/archive input or component documentation.

## Current combined checkpoint — complete cached local qualification

Frozen `8aaedd716a370b4f1180475da0465b67565bf151` passes the complete cached
Buildroot/ARMv5 lane: host ordinary/race/fixed-count fuzz, source/configuration
preflights, package/source collection, default/metadata/two-boot smoke,
launcher/retained Code Owner/loader/libatomic, all three original Samba
campaigns and synthetic SMART interpretation/producer/capture. Assertions,
privileges and guest deadlines remain unchanged. Paired configuration remains
inert: no daemon consumes that candidate and product activation is absent.

After the writer terminates, an independent read-only audit matches all **934
tracked API files** to compiled-package and regular source-archive contents,
reproduces configured stripping, and verifies installed/image/exported API
equality plus all seven ordered artifact hashes. The API is 10,708,180 bytes,
SHA-256 `abfa6bb2ee5a96bc78a8288d14f45b53da8b7ba32d0215852c4da5eceeb65e9a`.
This supersedes pending combined-image statements for the included changes;
earlier sections retain their historical source and fault-test scope.

No failure diagnostic fires in these successful guests. This is not an
intermittent-timeout fix, injected live teardown fault proof, independent clean
reproducibility, complete release licensing, product construction or EX4
qualification. Own exact-head hosted checks are required before integration;
the failed older PR heads do not become qualified by this local result.
No NAS, physical disk, NAND, product listener or installation operation occurs.

## Native backend inner-close quarantine — focused host qualification

A deterministic host regression reproduces the native adapter forgetting an
inner-configuration close failure: repeated public Close returns nil after
discarding its inner backend. The fixed post-runtime step now retains the
original bookkeeping and first review/error. All native operations are fenced
before the first Close attempt; runtime-close uncertainty cannot release the
inner configuration or permit retries. Normal repeated closure stays idempotent.
Closed adapters cannot construct a new retained identity service.

Real-file regressions pass with race detection and three repetitions, including
concurrent Close/empty observation and test-only replacement noninterference.
Pinned root Linux module tagged vet and five-package race-count3 also pass,
along with Windows API/UI/vet and ARMv5 cross-compilation. The regression seam
is exactly the private inner-close step after independently
verified runtime closure; tests do not fabricate or invoke a healthy runtime,
inject arbitrary closers or qualify runtime retirement/kernel EIO. Frozen
`fdef51d` now passes the original complete service/native/lifecycle ARMv5 union,
including all former guards and unchanged base hashes/budgets. This qualifies
normal-path compatibility of the changed source, not injected runtime-close
faults or the intermittent-timeout cause. The newer combined checkpoint above
separately qualifies the complete cached image and source audit. The
previous `a257104` proof retains its separate source scope. No NAS, product
endpoint or activation.

## Native worker failure classification — host-only diagnostic prerequisite

The latest diagnostic correction fixes a separate cause-loss guard in live
daemon verification: retained-tuple/bootstrap/process-observation errors now
keep their typed cause behind generic review-only text. A public negative
observation reproduces unavailable-cause loss before the fix and passes after
it; deadline/cancellation/private-text classification tests also pass. Pinned
Go1.26.8 non-root Linux vet/two-package tests/race3 and ARMv5 cross-compilation
pass. The unchanged focused lifecycle guest completes enrollment but fails
peer-continuity at45.125302s under its original CPU2/45/180 limits. This is
host-verified diagnostic work, NOT positive QEMU, timeout resolution or a new
complete image qualification. No product interface, admission or budget changes.

The private QEMU credential runtime now preserves the first failing phase and
fixed reason label across ordinary backend redaction. Complete admission,
worker execution, verified settlement and post-execution admission failures
remain review-required; the private cause stays inspectable with `errors.Is`
but is never included in error text or diagnostic output. A gated read-only
observer refuses canceled/busy calls, survives closure and neither runs workers
nor clears review. The guest emits fixed diagnostic-only labels on failure,
including from the distinct retained-startup runtime. No product endpoint,
constructor, privilege, normal command, admission guard or budget changes.

Host tests reproduce loss of the original cause before the implementation and
verify fixed-label redaction, first-fault retention and canceled/busy observation.
Pinned Linux tagged vet/race-count3 and Windows API/UI/vet/ARMv5 cross-compilation
pass. The unchanged ordinary Samba adapter's command-diagnostic redaction also
passes three root-fixture executions. These are host bookkeeping proofs, not
an actual native worker-failure or complete image qualification. Frozen
`a257104` now passes both an original focused lifecycle and the complete
service/native/lifecycle ARMv5 union, with unchanged base hashes, guards and
deadlines. No failure diagnostic fires in those positive paths. Earlier clean
timeouts and hosted failures remain unresolved: this normal-path proof does
not identify their cause, qualify failure telemetry end-to-end or establish
complete changed-image/independent clean-build qualification.

## Native runtime terminal-close quarantine — host qualification

The QEMU-only native runtime now retains its first terminal release error after
Owner cleanup, authentication-file removal or helper-descriptor closure. It stops
before later resources, fences subsequent service operations and keeps observable
review state; repeated `Close` neither retries cleanup nor reports false success.
The normal verified repeated-close path remains idempotent.

On the current branch, real temporary-file bookkeeping tests reproduce all three
former failures before the fix and pass afterward. Tests also preserve untouched
later resources and refuse removal/closure of test-only replacement objects.
Pinned Linux tagged module vet and three-count planner/runtime/coordinator race
tests pass, along with Windows API/UI/vet/ARMv5 cross-compilation. These tests
exercise teardown bookkeeping without bundle admission, never launch a child and
do not qualify actual kernel EIO, live-worker fault handling or durable recovery.
The original all-campaign replay on frozen `3ffb811` passes service and native,
but lifecycle reaches its unchanged 180-second outer timeout after handoff.
Full current-image/source qualification is therefore deferred. A temporary
timestamped lifecycle replay passes, measuring enrollment at about 35 seconds
and candidate/closure at about 11.5 seconds; this is diagnostic evidence, not
an original replay or a timeout fix. All temporary timestamps are removed.
This does not fix or bypass PR #123's hosted native outer timeout.
No constructor, privilege profile, device operation or HTTP surface is added.

The local Samba wrapper now has opt-in `-DiagnosticLogs`: after each guest
exits, it emits the bounded fixture log in an escaped single-line JSON record
marked `qualifying=false`, including success and timeout exit status. Default
invocation, original acceptance, guest commands and deadlines are unchanged;
no persistent log directory, image, volume or retry is added. Mock Windows
wrapper tests, 54 Linux driver tests, flake8 and shellcheck pass. This closes a
diagnostic-observability gap, not the intermittent campaign-timeout gate.
The unchanged API guest on `32644ec` subsequently reproduces the focused
lifecycle timeout with QEMU exit 124; diagnostic output is retained and the
wrapper correctly fails. Neither clean all-three nor full changed-image
qualification is claimed, and no hosted rerun has been dispatched.

## Paired management retention — host and original ARMv5 union qualification

The QEMU-only inert retainer now accepts the complete same-Plan role candidate,
not a separately supplied service candidate. Before acquiring new service pins,
it compares the existing retained management expectation's complete seven-file
roster, names, modes, sizes and SHA-256 values to independently rendered
management output. The original late complete code/configuration/state scan
remains mandatory; expectation equality alone grants no freshness or authority.
Mismatch returns without replacing management or acquiring a new role.

The credential renderer previously appended four resolver directives already
present in its opaque files-only lookup. A real temporary empty identity Owner
regression reproduces that duplication and passes after reusing the bounded
renderer shared by both roles. Globals, state paths and files-only resolution
remain unchanged. Windows API/UI/vet/cross-compilation, pinned Linux tagged vet
and three-count planner/runtime/coordinator race tests pass. Matching tests
reject every file's changed digest/mode/size/name and incomplete or service-only
expectations. These are not retained-descriptor fault tests. Original all-three
ARMv5 campaigns pass on frozen `79b5229`, including mandatory management binding
against the actual native Owner and mounted roster, all former guards, exact
base hashes and unchanged guest deadlines. The source-changing full image/audit
remains pending. Inert startup stays blocked, with no product
listener, service activation or physical-device operations.

Hosted PR #123's exact `1e77768` QEMU run `37592585439` separately failed the native
campaign's original 180-second outer timeout after the native configuration
handoff. Host and B3 succeeded. Neither this NSS correction nor earlier cached
passes establish a timeout fix; develop integration and main promotion remain
held, without rerun or bypass.

## Same-Plan Samba lookup roles — local cached integration qualification

The internal `Plan.SambaRoleCandidate` binds complete live management lookup
and the existing granted-only isolated service candidate to one immutable Plan
and freshness tuple. Desired-disabled and ungranted live users appear only in
management lookup; retired rows are omitted without removing permanent identity
reservations. Missing management UID/GID evidence refuses the pair, not an
otherwise valid existing share-only Plan. Rendering is bounded, non-serializable
and independent of caller mutation. The QEMU-only paired renderer returns two
separate seven-file trees with the exact existing globals/passdb/state paths and
no management shares; it neither stages them nor provides startup authority.

Windows API/UI/vet and ARMv5 cross-compilation pass. Final pinned Linux tagged
module vet and three-count race tests pass for the planner/runtime/guest command,
including the maximum-capacity regression. The
existing lifecycle fixture now passes on `7614c3e`: it checks both views against
its SAME actual native Owner and mounted roster, recompile and staleness, without
removing the inert startup guard. The original focused ARMv5 lifecycle campaign
and unchanged-base checks pass, with no added limits or instrumentation.
The complete cached Buildroot/QEMU lane then passes on frozen `f40fd82`, including
all three original Samba campaigns, default/two-boot and synthetic SMART gates.
An independent read-only audit matches all 930 tracked API inputs to the rebuilt
package and source archive, reproduces the configured strip operation, and
matches the installed/image/exported API plus all seven artifact hashes. Its
API SHA-256 is `e02d803b891bcf0bd2f8e4cde8f776a949f45d62cb59cef528ef28c26bd024a8`.
Later CI-filter/status edits do not change those API/build/guest inputs. Cached
qualification is not independent clean-build reproducibility, full licensing
compliance, hosted qualification or EX4 hardware/product qualification.
Same-object two-role runtime admission, native parser/access
checks, supervision/recovery and product activation remain open. No physical
NAS, disk, listener or persistence operation is introduced.

## Base Samba adapter close uncertainty — local cached integration qualification

The base `smbexec.Backend` now fences operations before releasing its pinned
configuration and preserves the first close error. Later closes do not retry,
close a test-only replacement or turn uncertainty into success; empty passdb
observations also refuse a closed lifetime. Production configuration admission,
fixed commands, privileges and deadlines are unchanged.

A real regular-file regression reproduces the prior false success. Targeted
non-root Linux race-count3 passes; ordinary and QEMU-tagged Linux adapter
race-count3 plus tagged module vet pass with temporary root-owned configuration
fixtures and fake command runners. Windows API/UI/vet and ARMv5 cross-compilation
pass. The combined checkpoint `0e36a08` also passes the complete cached
Buildroot/ARMv5 integration: ordinary/race/fuzz, default API boot, two-boot state,
metadata, launcher/Code Owner/loader/atomic, all three Samba campaigns and
synthetic SMART lanes. Original limits, assertions and base hashes are unchanged.
Independent comparison matches all 928 tracked API files to compiled-package
and distributed-archive contents, reproduces configured stripping, and confirms
installed/image/export API bytes and all seven artifact hashes. These normal
guest paths do not exercise injected close faults. No actual kernel EIO,
separate native-wrapper recovery, independent clean build, physical-device or
product activation is qualified. This is
not a fix for the independent native campaign timeout blocking main promotion.

## Local Samba test-wrapper default — host regression only

Windows PowerShell `-File` failed while evaluating the artifact-directory
parameter default, before any Docker command. The default is now resolved in
the script body from the repository root, matching the Code Owner wrapper.
A Windows native-command mock reproduces the old failure and confirms the fix
without contacting Docker. Command-boundary tests cover default/explicit paths,
all four selections, unchanged resource/read-only isolation, and six refusal
cases. The regression is also included in host CI; hosted qualification remains
pending. This does not address the ARMv5 lifecycle timeout or change guest limits.

## Per-scan hash scratch — local allocation and cached integration qualification

Code inspection and retained-code preparation now own one 32 KiB scratch buffer
per complete pass, instead of allocating it once per file. There is no global
pool, shared mutable Plan state, hash cache or skipped verification. Every file
is still hashed; read chunks, size+1 fence, cancellation boundaries, census,
ACL/capability/mode/mount checks and trailing original-object checks remain.

The real digest-loop allocation regression fails before this change and passes
afterward. Chunk-boundary, short/overlength, cancellation/read-failure and
different-file scratch-reuse tests pass. A Linux amd64/Go 1.26.6 microbenchmark
of 114 regular-file digest repetitions measures 3,739,200 -> 36,416 allocated
bytes per batch and 228 -> 115 allocations. This is not complete inspection,
physical EX4 throughput, total appliance RAM or proof of a lifecycle-timeout
fix. Tagged module vet/full runtimebundle and processowner race-count3 pass;
Windows API/UI/vet and ARMv5 cross-compilation pass, not guest execution.

The earlier isolated scratch checkpoint passed static Code Owner and service/
native campaigns, but its lifecycle guest reached the unchanged 180-second
outer timeout. A shell-only
timing diagnostic, with unchanged Go source, also times out; its preliminary
boot/staging/inspection/lookup work finished in about 16 seconds. The subsequent
combined checkpoint `0e36a08`, including the independently regressed base Samba
close fix, passes the original three-campaign union and complete cached image;
its own 928-source/package/archive/strip/image audit passes as described above.
Those positives do not explain the earlier timeouts or prove that scratch reuse
fixed them. Do not substitute the older 926-source audit for this new proof. The
separate native-wrapper cleanup draft remains excluded; no product service,
new privilege, physical-device or migration qualification is added.

## Retained descriptor release uncertainty — local full qualification

Linux retained code/configuration/state and pinned-process cleanup now preserve
the first close error permanently and stop releasing later inputs. The runtime
Owner records review; repeated Close never retries cleanup or reports success.
Earlier confirmed closures remain released. An errored close is not evidence
that its descriptor remains open, and restoring a test-only object does not
clear quarantine or permit closing its replacement.

Real-file fault regressions reproduce the old false-success behavior before
the fix and pass afterward, including remaining-root/later-role/executable
retention. Non-root Linux race-count3 and tagged regressions/vet pass. A separate
actual ARMv5 normal-path campaign passes the original static Code Owner and
all three service/native/lifecycle Samba campaigns, all driver/loader guards
and unchanged base hashes. Those guest positives do not execute the injected
close fault. Complete cached Buildroot/ARMv5 integration now also passes all
ordinary/race/fuzz/default/two-boot, metadata, launcher/code-owner/loader/atomic,
all three Samba and synthetic SMART lanes. Independent comparison matches all
926 API sources with the compiled package and source archive, reproduces the
configured strip step and matches installed/image/export API bytes and all
seven artifact hashes. This is not independent clean-build qualification;
the earlier 924-source proof below does not cover this increment.
Actual kernel I/O close failures, durable quarantine/recovery and product
activation remain unqualified. No HTTP, NAS operation or new privilege is added.

The earlier qualified 926-source image excludes the native-runtime wrapper's
terminal cleanup follow-up. That image can continue auth/helper cleanup after an
Owner error and forget terminal errors on repeated Close. The current host-tested
follow-up is described above; it is not retroactively included in that image.
Normal guest positives do not establish injected-close-fault qualification.

## Native session-worker phase budgets — local full qualification

A measured slow ARMv5 diagnostic and a host regression reproduce the former
ten-second aggregate deadline truncating the last inventory, despite every
worker individually fitting its four-second limit. The private native QEMU
adapter now selects a fixed phase profile: four seconds for status and control,
twenty seconds for the aggregate verification loop. The latter covers one
initial inventory, one control and two complete absence inventories, with one
worker-sized margin for bounded parsing/polling. The ordinary command adapter
retains its exact two-second status/five-second total profile. Unknown profiles
refuse before commands; no durations come from requests or configuration.

The control is independently capped, never repeated, and uncertain outcomes
still require review. Complete code/configuration/state admission around every
native worker is unchanged. No product deadline, privilege, guest limit or
recovery policy is widened. New host timing/control/profile regressions pass;
the explicitly incomplete slow ARMv5 diagnostic also passes. All temporary
instrumentation, narrowed validators and alternate virtual-clock settings are
removed. Windows API/UI/vet/cross-compilation and root Linux tagged race-count3
also pass. The timing regressions execute and pass in ordinary non-root Linux
tests, with and without the QEMU tag. The clean phase-profile checkpoint passes
the original service/native/lifecycle ARMv5 union, including live revocation,
same-peer preservation, all earlier guards and unchanged base hashes.

A subsequent negative host regression reproduces a separate expired-inventory
acceptance bug: a runner's successful result after its own status deadline could
count toward absence while the parent remained live. The executor now checks
that child context before canceling it, clears late output and refuses without
another poll or control. The test fails before the fix and passes afterward;
the combined source passes Windows preflight and root tagged Linux race-count3,
plus ordinary non-root Linux race tests. The exact combined source now passes
complete cached Buildroot/ARMv5 integration: all three Samba campaigns, default
and two-boot checks, launcher/code-owner/loader/atomic and synthetic SMART lanes.
Independent comparison matches all 924 tracked API files with compiled package
and source archive, configured stripping, installed/image/export API bytes and
all seven artifact hashes. This is local cached qualification, not independent
clean-build reproducibility; own hosted qualification remains required before
integration/promotion.
Historical four/ten-second qualification below retains its earlier source scope.

### Retained-descriptor gap discovered after this qualification

A separate Linux fault regression demonstrated forgotten close errors and false
success on repeated cleanup in the source qualified above. The later increment
at the top of this document fixes that bookkeeping; it is not included in this
924-source qualification. Already-closed-object fixtures do not qualify kernel
I/O close failures, product recovery or physical-device behavior. These remain
product-runtime prerequisites; no installable runtime is offered.

## Inert retained Plan configuration role — QEMU only

The same native runtime can retain a second, independently Plan-derived
configuration root without replacing its management lookup or mutable passdb.
Construction requires exact protected documents; empty candidates and malformed
modes refuse. Caller descriptors close independently, management observations
remain unchanged, and normal runtime closure precedes exact-mount cleanup.
The role blocks daemon startup and cannot be replaced. It is not a grant lease,
freshness token, service activation path or product configuration.

Linux tagged race-count3/module vet, host preflight/ARMv5 cross-compilation,
50 driver/seven loader tests and the focused ARMv5 lifecycle campaign pass.
The default service/native/lifecycle union also passes every previous contract
and unchanged base hashes with the same guest/operation limits. Complete cached
Buildroot/ARMv5 integration also passes, including the default/two-boot and
synthetic SMART lanes. Independent comparison matches all 921 tracked API files
with the compiled package/source archive, reproduces configured stripping and
matches installed/image/exported API bytes plus all seven artifact hashes.
Post-admission fault tests, original storage/identity/state composition and
actual Plan-configured daemon consumption remain required. This is not an
independent clean build or physical EX4 qualification. No HTTP or physical NAS
operation is added.

## Bounded Plan-derived Samba documents — QEMU only

One pure renderer emits seven configuration documents from the immutable
isolated Plan candidate: exact granted-only Unix lookup and RO/RW share sections,
with byte-identical existing native loopback/SMB3 globals and passdb/state paths.
The unchanged aggregate 64 KiB budget accepts its exact boundary and refuses
overflow or absent inputs without partial output. Returned-map mutation cannot
change the candidate or a later render.

Windows API/UI/vet and actual-command ARMv5 cross-compilation, Linux tagged
runtime/planner race-count3 and module vet, 50 driver/seven loader tests and a
focused ARMv5 lifecycle campaign pass. That campaign uses the SAME actual native
identity Owner/backend and mounted roster, omits the ungranted native account,
and freshly recompiles complete evidence to byte-identical documents. It is
explicitly `complete_image=false`; no daemon consumes these documents yet.
Protected staging, distinct retained management/service roles, complete native
data/service lifetime and fault tests remain required. No HTTP, product startup
or NAS operation is introduced.

The renderer checkpoint also passes complete cached local Buildroot/ARMv5
integration, including all three Samba campaigns, two-boot checks and synthetic
SMART lanes. Independent comparison matches all 917 tracked API files with
the compiled package and source archive, reproduces the configured strip step,
and matches installed/image/exported API bytes and all seven artifact hashes.
This is not independent clean-build reproducibility or EX4 qualification. A
separate hosted develop run failed live-session revocation; a focused local
replay of that exact develop commit passes, so the failure remains unresolved.

## Actual Owner-to-mounted-candidate admission — QEMU only

A positive disposable ARMv5 fixture now builds a locked Plan from the SAME
real identity Owner/native Samba backend and an actual mounted-volume roster.
Its immutable candidate matches both declared RO/RW roots; retained identity
and original share descriptors block premature teardown. Caller copies close
independently, fresh Owner/storage evidence recompiles to the same candidate,
and normal release restores the volatile mount namespace. A desired-state
round trip leaves Unix/Samba journals and passdb identities unchanged; stale
evidence and restored disabled grants refuse.

The clean local service/native/lifecycle union passes all previous guards,
50 driver/seven loader tests and unchanged base hashes. Windows API/UI/vet/ARMv5
cross-compilation and Linux tagged planner/mount-owner race-count3/module vet
also pass. The fixed 16 MiB synthetic ext4 device is read only for UUID probing;
mount anchors use a protected temporary overlay, never a writable base image.
No deadline or privilege profile is widened. A prior local timeout remains
recorded; one successful regression does not establish absence of runner jitter.

This proves candidate/handoff admission, **not** Samba consuming that Plan's
configuration or data. The existing fixed native-data experiment remains a
separate prerequisite. Complete planned daemon composition, grant/ACL and
source-loss/uncertain-stop proofs, full image/hosted qualification and product
activation are still required. No HTTP, NAS or installation authority is added.

The preceding admission-only source checkpoint separately passes the complete
cached local Buildroot/ARMv5 integration, including all three Samba campaigns
and synthetic SMART lanes. Independent comparison matches all 914 API sources
with the compiled package and source archive, configured-stripped package bytes
with installed/image/exported API bytes, and all seven artifact hashes. This
does not establish independent clean-build reproducibility, a physical SMART
provider or EX4 hardware/migration/recovery. The later renderer's separate
complete cached qualification is recorded above.

## Complete isolated Samba candidate — storage composition prerequisite

One immutable candidate now packages Plan-derived NSS, isolated share grants,
exact ID/VolumeID/subdirectory/RO requests and the complete freshness tuple.
Caller mutations cannot mix/rewrite its parts; zero, unsupported and NFS-only
plans refuse with no partial usable SMB candidate. JSON is refused in both
directions. The private QEMU adapter compares these requests with a live
trusted mounted-handoff declaration; it supplies no mount or launch operation.

Windows API/UI/vet and ARMv5 cross-compilation, Linux tagged race-count3 for
planner/mount-owner plus tagged module vet pass. A focused actual ARMv5 service
campaign also passes exact declaration matching, seven mismatch refusals,
healthy-pin preservation and source-loss/restoration review, all prior service
guards and unchanged base hashes. Focused proof is explicitly
`complete_image=false`; it does not replace native/lifecycle/full-build CI.

The full positive Owner → Plan → candidate → mounted pins → SAME native service
composition remains unqualified. Current fixed two-root native data proof does
not become complete merely because this candidate/check exists. No product
startup, web activation, persistent-device operation or firmware release is added.

## M0: Bounded Samba feedback and nonduplicated lifecycle preparation

The default local ARMv5 runner still compiles once and requires three fresh
service/native/lifecycle guests, exact ordered proofs, equal runtime censuses
and unchanged base hashes; each retains its180-second limit. Lifecycle creates
real disabled-first accounts and explicitly enables them before its new retained
startup coordinator, without repeating native's first daemon/idle-disable cycle.
Authentication, idle/live revocation and backend binding remain mandatory in
native. Every original contract remains required in the complete proof union.
The final native passdb assertions use the already-collected Owner-locked
snapshot; no worker fence or deadline is relaxed.

The clean local three-campaign regression and a separately scoped focused
lifecycle probe pass. Driver tests cover complete contract coverage, missing/
wrong-phase proofs, exact campaign selection and rejection of partial evidence
as full qualification. Temporary diagnostic logs are removed. An explicit
`-Campaign` local probe reports `complete_image=false`; full-build callers are
unchanged. See [fast-test scope](support/QEMU-FAST-TESTS.md).

These are cached local fixture results, not an independently clean build,
exact-parent hosted qualification, product startup or hardware/release proof.
Intermittent runner behavior is not claimed eliminated by one successful run.
All product identity/storage/runtime composition and recovery gates remain open.

## Native individual-share data handoff — fixed QEMU prerequisite

A separate guarded native data profile now receives two original, individually
attached ext-family mount roots (RO/RW) alongside the retained code/configuration
and seven mutable-state directories. Its factory duplicates existing `O_PATH`
descriptors, verifies independent mount identities/protected flags and rejects
host execution. The bootstrap makes nonrecursive clones before changing mount
namespace, attaches only the two fixed shares, closes all inherited inputs and
executes Samba in the existing restricted read-only root with capabilities
`0xdb`. Credential workers retain their twelve-input, no-data profile; the
generic static/non-root launcher is unchanged.

The official local three-campaign ARMv5 lane passes with 43 driver tests, seven
loader tests and unchanged base hashes. Real SMB write/read, RO read, RO-write
denial, kernel `EROFS`, 22-byte file contents and Unix ownership `2001:2001`
pass. A symlink escape returns `NT_STATUS_STOPPED_ON_SYMLINK`; no destination
file or forbidden RO file exists. Verified whole client/daemon settlement
precedes original-root release, and parent descriptor counts match. Linux
process/runtime race-count3 and tagged module vet plus Windows API/UI preflight
and ARMv5 cross-compilation also pass locally.

This uses fixed qualification documents and synthetic mounts after the prior
identity/runtime experiment has closed. It does **not** consume the complete
mounted-roster share pin or retain the SAME identity Owner throughout data
service startup. The marker explicitly says `complete_storage_identity=false`.
Complete Plan-bound bootstrap, grant/ACL matrix, storage-loss and uncertain-close
composition, full cached/clean/hosted integration and product activation remain
required. No new guest, widened timeout, production listener or device operation
is introduced. See the [native profile](support/SAMBA-RUNTIME-PROFILE.md#native-individual-share-data-profile-qemu-only).

## Declared share descriptor pins — QEMU storage prerequisite

The guarded `qemu && linux` storage fixture now retains original `O_PATH`
descriptors for each declared attached share, after complete roster and source
verification. Only copies of those originals are returned; no complete volume
root or recursively cloned tree is supplied. One exclusive pin prevents direct
handoff teardown until explicit release. Source loss puts the pin in sticky
review; restoring the source path cannot issue replacement descriptors.
These parent-namespace handles are not a service isolation boundary.

The actual ARMv5 service-launcher guest passes two declared roots (RW and RO),
repeated copied-descriptor closure with original pins still usable, non-root
UID/GID-correct writes, kernel `EROFS` and unchanged descriptor count after
settled release. Legitimate data changes do not trip immutable-code checks.
Normal release and source-loss review are exercised, with all earlier launcher
and static-child isolation guards unchanged. Host refusal/race tests and tagged
module vet pass; the pins and descriptors refuse JSON serialization.

The trusted consumer must first stop/reap every descendant and close all copied
inputs; this pin's `Close` cannot independently prove that external settlement.
Its uncertain-close path conservatively keeps the handoff reservation, but an
actual close-uncertainty fault has not yet been qualified for this new type.
This fixture does not pass data to Samba, transfer SMB files, qualify descendant
settlement for a Samba consumer, activate HTTP/product services or touch real
disks. Next, compose the Plan and complete roster/identity/runtime authorities
with an individual-share native descriptor profile and real SMB RW/RO access.
Full cached/clean/hosted integration of this increment remains separate.

## Isolated Samba share candidates — preparation only

The existing file-service Plan now privately retains a bounded immutable copy
of its validated SMB policy. `SambaShareCandidates` derives fixed
`/shares/<share-id>` sections and exact logical-volume/subdirectory requests
from that same Plan, alongside its identity/storage freshness and NSS context.
Ordinary previews are unchanged. Mixed RO/RW grants are preserved; roots with
no writer request read-only clones. A writer on one share does not broaden
another. Zero/refused candidates return no partial output; whole-volume `.`
is unsupported by this isolated path, and NFS-only policy invents no SMB root.

Windows API/UI/vet and ARMv5 cross-compilation pass locally, as do Linux
race-count3 for the renderer/planner, tagged module vet, ShellCheck and a
10,000-execution renderer fuzz campaign. The complete one-boot ARMv5 overlay
smoke passes against the hash-verified cached base. Its mounted-roster fixture
checks the exact isolated root request and invokes target `testparm` for path,
users, RO/RW lists, read-only default, denied guests and symlink/wide-link
refusal; the smoke requires the new isolated-candidate assertion alongside all
earlier guards. Identity in this particular parser fixture is synthetic.

This does not attach share descriptors, retain storage for native Samba,
transfer files through this candidate or authorize activation. The next
step is the complete roster/identity/native-runtime composition with real RW/RO
access, source-loss quarantine and verified descendant stop before releasing
data pins. Candidate/parser results do not qualify that file-access behavior,
product startup, migration or physical EX4 hardware.
This overlay does not rebuild base packages/SBOM/legal-info or run the separate
two-boot and three restricted Samba campaigns; complete cached/clean/hosted
qualification of this increment remains separate.

## Coordinator-owned native Disable — focused QEMU prerequisite

The retained startup coordinator now routes explicit revision-checked Disable
through the SAME identity Owner/backend and atomically retains its verified
successor. No caller can supply a replacement token, fingerprint or runtime.
A qualified pre-intent revision conflict leaves the journal/consumer unchanged;
other uncertainty stops the service and retains review, without retry.

The actual ARMv5 fixture holds two distinct sessions before this transition:
the target disappears, new target login is denied and the original peer session
and server generation remain unchanged. Owner Close stays busy through the
transition and verified stop; full runtime closure precedes identity release.
Canceled/stale requests, pre-start/stopped mutation and mutation competing with
the exclusive supervisor refuse. The fixed client helpers share the coordinator
gate and supply no caller-selected credentials, command or executable.

All 42 Linux driver/seven loader tests, lint/ShellCheck, three actual ARMv5
campaigns, base hashes and final descriptor equality pass locally. Root Linux
race-count3/tagged vet and Windows API/UI/cross-compilation pass. The added live
phase has its own 45-second bound, followed by a 20-second observation/stop
phase; startup40, worker4/revocation10 and each guest180 remain unchanged.
The later state-fault subprocess explicitly re-enables the synthetic target
before NEW admission; it does not refresh an invalidated consumer or fabricate
state. No additional campaign, image, volume or privilege profile is added.

Complete cached local integration also passes on frozen `42d77be` (tree
`9440318`): API/UI/vet/race/fixed-count fuzz, package/source/license/SBOM
collection, ordinary ARMv5 smoke, MD component/partition comparisons, two-boot
state, launcher/runtime/loader/libatomic, all three Samba campaigns and synthetic
SMART report/producer/capture. An independent read-only audit matches all 894
tracked API files to the compiled package and source archive, without extra or
duplicate regular archive members. All seven artifact hashes verify.

Buildroot's configured target stripping is reproduced on a temporary copy of
the raw package binary: its result equals the installed, image-contained and
exported API (10,577,108 bytes, SHA256
`80478e9bfdb3a08aa58e431f03822360ef551755e2d1a4f9c83af08661163ac1`).
The pre-strip binary is not expected to have the same bytes. This is cached
local qualification, not independent clean-build reproduction or complete
release licensing.

This does not qualify production queued commands/supervision, continuous
bootstrap/storage authority, additional fault variants, durable recovery,
HTTP activation, clean/hosted integration or physical EX4.

## Retained native state-alias fault — focused QEMU prerequisite

The actual ARMv5 trace replaces one fixed guest-tmpfs state directory alias
while retaining the original object and its contents. Complete admission
refuses before the pending capture executes. The coordinator stops the owned
daemon/client set, keeps the unconsumed capture, original code/config/state
descriptors and busy identity authority, and refuses restart or repeated close
after restoration. A separate read-only observation proves owned-group stop
and distinguishes an unconsumed capture from an executed, settled one.
Intentional retained references are disposed only by the test subprocess's exit
after that proof; this is not product recovery. FD equality applies to its parent.
Clients are not active in this fault trace; their fault settlement remains open.

The final local lane passes 42 driver/seven loader tests and three complete
ARMv5 campaigns. One probe compilation/base image supplies separate fresh
service, native-revocation and lifecycle snapshots, each still limited to 180
seconds. Complete phase markers, matching runtime censuses, entropy, all earlier
access/authentication/revocation guards and unchanged base hashes are mandatory.
Root Linux race-count3 for the five affected packages, tagged module vet and
Windows API/UI/vet/ARMv5 cross-compilation pass. Temporary diagnostics are removed.

The original mode-drift test selected the wrong seam: invalid directory modes
refuse capture construction before a pending capture exists. Alias replacement
exercises the intended later refusal. A combined campaign passed with timing
instrumentation but its final uninstrumented rerun timed out; separate campaigns
avoid charging unrelated scenarios to one deadline without dropping their tests.
This does not prove deterministic performance or diagnose every older timeout.
The newer complete cached `42d77be` proof above includes this fault trace;
hosted/clean-build qualification is still separate. Identity/code
drift, unexpected exits, in-worker cancellation, other uncertain teardown,
further command lifecycle, storage, bootstrap continuity, product UI/startup, durable
recovery and physical EX4 qualification remain open.

## Identity-bound native startup/supervision — normal QEMU prerequisite

The private QEMU coordinator obtains only the exact Owner-fixed backend's
runtime and retains a backend-bound consumer **before** daemon startup.
Fresh identity verification brackets startup; complete observations use the
same retained code/config/state/daemon through the fixed backend. One exclusive
fixed-idle supervision loop serializes scans, refuses competing operations and
stops on accepted cancellation without restart. Readable atomic status is
redacted telemetry, not authority. Identity release follows verified complete
runtime closure; uncertain startup/stop/close retains review without replay.

The focused local ARMv5 lane passes all 40 driver/seven loader tests and BOTH
campaigns. The additional positive trace proves Owner close refusal before/
during startup, canceled/duplicate refusal, complete timed scans, serialized
observation, accepted cancellation, retention until full closure and no FD leak.
Existing authentication/revocation/privilege markers and base hashes remain.
Root Linux race-count3/tagged vet and Windows API/UI/cross-compilation pass.

The complete cached local Buildroot lane also passes on frozen `e445f1c`
(tree `b10ac7a`): API/UI/vet/race/fixed-count fuzz, source/license/SBOM
collection, standard ARMv5 smoke, MD component comparisons, two-boot state,
launcher/retained runtime/loader/libatomic, both Samba campaigns and synthetic
SMART producer/capture lanes. Independent read-only audit matches all 887
tracked API files to compiled package and archive members, with no additional
regular archive entries; installed, image-contained and exported API bytes
match, and all seven artifact hashes verify. Existing fixed caches are reused;
the temporary builder is removed. This is not independent clean-build,
complete release licensing, hosted or physical EX4 qualification.

This qualifies the **normal** startup/supervision path only. Coordinator-specific
drift/exit/mid-worker cancellation/uncertain-stop/close fault proofs,
storage/grants, bootstrap continuity, product startup/UI and
durable recovery remain open. The cached image proof above does not qualify
hosted/clean builds, deployment, NAS or hardware behavior.

## Identity Owner teardown quarantine — host prerequisite

An Owner with no live file-service consumers must close its fixed backend
before releasing identity journals/ledger. Backend teardown errors now retain
all authority references, reject new work and return redacted unavailability/
review without automatic retry. Later inner-store closure errors retain the
outer root fence; final descriptor-close uncertainty is sticky, not proof that
the descriptor remained open. Successful closure remains idempotent.

A root-isolated failing test reproduced the former competing-Owner admission
after an external backend error. Real Owner/store/lock tests now verify all
native/Samba/registry leases, new-work refusal, no retry and positive teardown
ordering. No product recovery, failed-Open or low-level syscall fault claim is
made. Root Linux race-count3 and tagged module vet pass. The focused local
ARMv5 lane preserves both complete Samba campaigns, all 39 driver/seven loader
checks, normal native closure, old/new markers, FD equality and unchanged base
hashes. The modeled teardown fault itself is tested on Linux host, not ARMv5.
This is separate from the earlier complete cached image below.

## Explicit SMB disable successor — cached integration prerequisite

`identityowner.SMB(id).DisableForFileService` retains the startup-bound backend
and performs existing journaled revocation under the Owner lock. Only complete,
non-recovering before/after evidence with the exact single-account delta can
transfer the bounded consumer slot. A new token verifies; the old token never
revives. Foreign/unbound/stale inputs refuse; uncertainty keeps review/retention
without retry. No generic lease refresh or enable/password successor is added.

Root-run Linux tests exercise seven scenarios plus eight refusal subcases,
including capacity 16, concurrent Close and cancellation after journal intent.
The actual local ARMv5 lane passes 39 driver/seven loader tests, both Samba
campaigns, SAME peer-session continuity and mandatory old/new markers, verified
whole stop/reap/FD equality and unchanged base hashes. Windows API/UI/vet and
tagged ARMv5 cross-compilation pass. An earlier combined live-phase attempt
expired at 45 seconds; an instrumentation-only control also passed. Preparation
is now separately bounded 20 seconds before held clients; live 45/enrollment 60/
guest 180 limits and every admission remain intact. No deterministic timing fix
or older hosted census diagnosis is claimed.

Retention here starts after daemon startup. Constructor-bound continuous
identity/storage authority, supervisor drift/failure handling, close-uncertainty
retention, product HTTP/startup, durable recovery and EX4 qualification remain
open. The complete cached local build of source `cd9b2a5` also passes API/UI,
vet/race/fixed-count fuzz, package/source/license collection, ARMv5 smoke, MD,
two-boot state, launcher/runtime/loader/libatomic, both Samba campaigns and
synthetic SMART lanes. Independent read-only comparison matches all 883 tracked
API files against the compiled package and regular archive members; installed,
image-contained and exported API bytes agree, and all seven artifact hashes
verify. This is cached integration, not independent clean-build, complete
release licensing, hosted or hardware qualification.
See the [identity contract](src/phantowd-api/identityowner/README.md#file-service-consumer-retention).

## Exact-backend identity retention — focused host/QEMU qualification

The internal identity Owner now offers `RetainSMBFileServiceSnapshot` for the
exact non-nil, non-zero-sized pointer backend fixed at startup. The candidate
is an identity assertion only, never a replacement executor. Different Owner
backends are refused before observation even when their complete fingerprints
match. Generic consumer behavior remains unchanged; both methods share the
same 16-consumer bound, close fence, copy/release and sticky-review rules.

Root-run Linux tests and race-count3 qualify foreign/equal-evidence refusal,
invalid/noncomparable/typed-nil/zero-sized identities, revocation/stale evidence,
serialization refusal, mixed capacity and exact backend lifetime. Windows
API/UI/vet and tagged ARMv5 cross-compilation pass. The official local ARMv5
wrapper passes all 38 driver/seven loader tests and BOTH complete Samba
campaigns, including an actual native-backend read-only retention/close-fence
probe that releases before daemon startup without changing identity evidence.
All earlier live-revocation/privilege/base/teardown/FD guards remain mandatory.

This is not a new complete Buildroot image, hosted/clean qualification or
continuous daemon authority. A constructor must still bind its own runtime,
coordinate outside Owner/runtime gates, and qualify a successor/fence for
confirmed account mutations. The probe neither supervises a daemon nor
authorizes refresh, activation, new HTTP, persistent recovery or NAS operations.
The complete cached result below retains its exact historical source scope.

## Complete cached native-revocation integration — local qualification

Frozen `57ee527` passes the complete cached local lane: API/vet/race/fixed-count
fuzz, source/configuration preflights, package/source/legal-info collection,
actual ARMv5 smoke/MD/two-boot, launcher/retained Owner/loader/libatomic,
both restricted-root Samba campaigns and synthetic SMART producer/capture.
Live-session revocation and every earlier Samba guard pass within the declared
fixed profiles; all previous base-image/teardown checks remain mandatory.

An independent post-terminal audit compares all 880 tracked API files against
the compiled package and regular, nonduplicated source archive members. All
match; unexpected archived code is refused. Installed, image-contained and
exported API bytes agree at SHA256
`5867a9149bd506811ddfcf15bde6d605e08057ef415a01b8524a8b91410ee662`.
All seven ordered payload hashes verify. No tracked source changes or restarted
build occur during qualification.

This is cached local evidence, not the new PR's own hosted checks, independent
clean-build reproducibility, complete release-source/licensing qualification,
product identity/storage composition, recovery, migration or EX4 qualification.
There is still no installable firmware release.

## M4.4 Owner-bound native live-session revocation — disposable QEMU

The official local ARMv5 wrapper now passes all 37 driver/seven loader tests
and both campaigns, including two fixed interactive clients against the same
Owner-enrolled daemon. Complete qualified session inventories must establish
both accounts before dispatch. One Owner-bound target-only logoff then requires
two complete target-absence inventories, the SAME peer session ID and server
generation, a denied fresh target login and an allowed peer login. A replacement
session or empty/partial inventory cannot substitute for continuity.

The private witness is backend-bound and cannot be serialized. Host/race tests
at count3 refuse incomplete/ambiguous inventories, zero/foreign witnesses,
changed peer IDs/generations and weakened parent deadlines. Client groups,
daemon groups and original pins remain owned through verified stop/reap/close;
final FD equality, all earlier markers and unchanged base are mandatory.

The initial native tagged fixture used fixed 4-second status / 10-second
revocation budgets; the phase-accounted profile above supersedes those limits.
The ordinary adapter
retains 2/5 seconds. Startup and idle-disable each have a separate 20-second
phase; the complete active-session phase has 45 seconds. Enrollment remains
60 seconds and each fresh guest remains bounded to 180 seconds. Earlier
shared/tight phase envelopes failed closed during slower emulated scans;
no admission, inventory, generation guard or no-retry rule is removed.

The complete cached result above additionally qualifies this source's image.
Neither result establishes hosted/independent clean-build qualification,
continuous identity/storage authority, data-share/handle semantics, product
startup/UI or EX4 qualification. The firmware remains non-installable.
Historical results below retain their source scope.

## M4.4 Owner-bound native idle disable — disposable QEMU

The fixed native daemon now has a single-use serialized start/check/stop
lifecycle. The same Owner-bound backend can run credential and status workers
while that daemon remains owned; no per-operation replacement backend,
arbitrary command, product listener or new privilege is introduced.

The official local ARMv5 wrapper passes all 36 driver/seven loader tests and
both complete campaigns. It explicitly disables one Owner-enrolled account,
confirms the same SID and disabled journal, requires the unchanged backend's
two complete stable-absence inventories, denies that account's new login and
authenticates the other account against the same daemon. Canceled/duplicate
start and restart after stop are refused; verified teardown, final FD equality
and unchanged base are mandatory. Focused Linux-native tagged vet/race tests
pass at count3, including absent/canceled/busy authority refusal.

The initial new composition failed closed when redundant complete code scans
exhausted the existing 2-second status deadline. Removing the duplicate scans
restores exactly one complete code/config/state plus live-daemon admission on
each side of a worker; the 2-second status, 5-second revocation, 60-second
enrollment, 20-second daemon and 180-second guest budgets remain unchanged.
Temporary diagnostics were removed before final qualification.

No session is deliberately held open in this tracer. It does **not** qualify
revocation of an established session, active-session generation coverage,
sustained supervision, continuous identity/storage authority, product startup,
new complete-image/clean/hosted qualification or physical EX4 operation.
Those gates remain open; the earlier complete-image result below retains its
exact source scope. The firmware remains non-installable.

## M4.4 native Owner-enrolled daemon authentication — disposable QEMU

The native runtime now retains the same original code, protected configuration
and mutable state through Owner-bound enrollment and actual `smbd` execution.
A separate fixed daemon adapter independently duplicates twelve input objects,
clones their mounts before namespace isolation, masks source paths and attaches
the originals. Generic static/non-root launcher restrictions remain unchanged.

The daemon has a private read-only root/mount namespace, capabilities `0xdb`,
no-new-privileges, no `/proc`, `/dev` or `/run`, and an empty read-only `/tmp`
required for IPC. It shares only the disposable guest's loopback network;
QEMU has no NIC or host forwarding. Fixed test clients use root-only temporary
authentication files via an inherited descriptor, never password argv/env.
Readiness requires real authentication, not merely an open TCP port.

The official local wrapper passes all 35 Linux driver tests, seven loader tests,
lint/ShellCheck and both complete actual ARMv5 campaigns. Both Owner-enrolled
accounts authenticate; a wrong password is denied. Live checks verify all 114
original code objects, protected configuration/state views, capabilities and
root isolation. Whole-group stop/reap and explicit close precede release;
the final FD count matches the baseline and the base image is unchanged.
Enrollment retains its 60-second budget; authentication has a separate fixed
20-second phase inside the unchanged 180-second native guest limit.

The same frozen runtime also passes complete cached local integration on
`8cb0b86`: API/vet/race/fixed-count fuzz, package/source collection, actual ARMv5
smoke/MD/two-boot, launcher/code/loader/atomic, both restricted-root Samba
campaigns and synthetic SMART producer/capture. All 877 tracked API files match
the compiled package and regular source-archive members independently.
Installed, image-embedded and exported API bytes agree at SHA256
`bbcfcff3f63976b1a8ca731f25c8e78eba8dea2500b270d6774f1b9ab4fc79d9`;
all seven exported artifact hashes verify. No source mutation or restarted build
occurs during qualification. This is cached local evidence, not independent
clean-build reproducibility or complete release licensing.

This is test-only authentication qualification, not a clean/hosted build,
sustained service supervision, live revocation, continuous
identity/storage authority, product construction/UI or physical EX4 proof.
The existing revocation fixture does not qualify this new restricted profile.
This increment's own hosted checks remain required; the firmware is not
installable.

## M0 bounded Samba campaign qualification

The Samba integration lane now compiles its probes once, then boots two fresh
disposable snapshots: service isolation/lifetimes and native lookup/enrollment.
Each guest retains the 180-second limit; the credential operation retains its
60-second budget. No state/passdb is transferred between campaigns.

Each log must independently prove the exact ordered markers for its phase,
including fresh entropy, staging, complete code admission and teardown. The
joint verifier rejects missing/duplicate/swapped campaigns and different code
censuses. Every earlier guard remains required; the manifest-verified base is
unchanged. Failure diagnostics identify the failed campaign.

The official local wrapper passes all 34 Linux driver tests, seven loader
tests, lint/ShellCheck and both actual ARMv5 campaigns. This fixes the observed
single-guest outer timeout after native handoff without removing checks or
extending per-guest deadlines. This is focused cached local qualification;
the new hosted head must pass its own checks. No new daemon/product/EX4
qualification is claimed by reorganizing these tests.

## M2.4 Owner-bound native credential workers — disposable QEMU

The actual two Unix identities from the native lookup now enroll through a
backend fixed at `identityowner.OpenWithSMBBackend`, not a per-operation adapter.
Its private runtime retains the complete code roster, independently expected
Owner-derived configuration and one original writable state directory tuple.
The exact roster now also includes `smbstatus` and `smbcontrol` and their closure.

A fixed worker receives twelve original objects: configuration root plus
passwd/group/nsswitch/smb.conf, followed by state root and six private role
directories. It clones them before unsharing, masks the source paths, verifies
same-object attachment, closes escape FDs and executes a fixed Samba command
with bounded privileges. The protected config is read-only/noexec; mutable
state is writable/noexec. Password input is a bounded, sealed read-only memfd,
never argv or environment. Raw command output remains private parser input.

Actual ARMv5 tests require absent → disabled/no-password → password still
disabled → separately enabled for both real identities, with unchanged per-user
SID and distinct final SIDs. Every worker settles and closes before release;
the final descriptor count matches the baseline. The official campaign passes
all 33 driver tests, seven loader tests, lint/ShellCheck and every older gate,
with unchanged base image and the existing 180-second guest budget.

The same frozen runtime subsequently passes complete cached local integration
on `8b1f9ec`: host/race/fuzz, package compilation and source collection, ARMv5
smoke/MD/two-boot, launcher/code/loader/atomic, restricted-root Samba and
synthetic SMART producer/capture. All 874 tracked API files independently match
the compiled package and source archive. Installed, image-embedded and exported
API bytes agree at SHA256
`c74339a186c8faed0610d3c242689724cb54d74e1a47cda9316899ccd7e05717`;
all seven exported artifact hashes verify. This is cached local qualification,
not an independent clean build, complete release licensing or EX4 qualification.

The first composition reproduced a 60-second fixture deadline caused by four
complete code scans per command. Configuration binding now checks configuration
only; full code/config/state checks immediately bracket each worker. Both
identities finish within the original 60-second budget; checks were not removed
from the effect boundary or replaced by cached success.

The earlier `8b1f9ec` qualification is **credential-only fixture composition**.
The newer same-state daemon authentication is qualified separately above;
live-session revocation in this composition, storage grants, continuous identity
authority, descriptor-bound product code/root construction, durable quarantine,
startup recovery, HTTP and physical EX4 qualification remain open. The bootstrap
Owner closes
before a fresh backend-bound admission; this is not continuous retention. The
legacy fixture's session-revocation proof is not borrowed for this new profile.
No product service, installer or independent clean-build qualification is
established.

## M2.4 Owner-derived native configuration and descriptor handoff — QEMU

The native enrollment candidate now supplies the independently expected hashes,
modes and sizes for exactly `passwd`, `group` and `nsswitch.conf`. A private
adapter reuses protected configuration admission; it does not infer expected
contents from the directory being inspected or grant execution authority.

The fixed QEMU tracer admits those real Owner-derived documents on a separate
read-only/nosuid/nodev/noexec mount and retains their original descriptors
across actual libc lookup. Temporary caller references close before execution;
fresh complete rechecks bracket the worker. Verified group absence and explicit
capture close precede configuration release. A controlled metadata change is
refused; restored permissions still differ from the originally admitted object
generation. Successful teardown restores the initial descriptor count and the
native Owner's evidence remains unchanged.

A separate fixed QEMU capture now duplicates the original configuration root
and three original files, with role/parent correspondence and late metadata,
mount, attribute and byte rechecks. Its bootstrap clones these objects before
changing mount namespace, masks the source pathname in the child and attaches
only the detached original-object clones. The actual post-exec libc probe
checks that inherited descriptors are closed. All four temporary config callers
close before capture; no generic extra-FD/action/secret interface is added.

Seven real admission refusals cover missing, closed, duplicate, wrong-kind,
swapped-role and non-empty-stdin inputs with caller preservation and partial
cleanup. A metadata change after capture construction refuses before launch;
restoration does not clear capture review. This is fixed lookup-worker review,
not product service recovery or an identity lease.

Windows API/UI preflight, Linux tagged vet and focused race-count3 pass. The
official focused wrapper passes all 31 Linux driver tests, seven loader tests,
lint/ShellCheck, fresh ARMv5 compilation and all existing/new Samba gates with
the base unchanged and the existing 180-second guest budget.

This qualifies original configuration handoff during one fixed lookup worker,
not a retained identity lease, descriptor-bound product root construction, sticky
service review, daemon installation or SAME-state credential backend. The
QEMU controller retains a writable original only for its metadata fault;
product code must not inherit that fixture shortcut. Uncertain worker teardown
does not release configuration pins. No product service, HTTP, credentials,
physical device or new full image/source-bundle qualification is introduced.

## M2.4 native lookup consumed by libc — disposable QEMU only

The existing restricted-root Samba campaign now finishes with a separate
lookup-only experiment, after all earlier daemon/controller groups stop. An
actual native Owner creates two disabled Unix accounts through the typed
BusyBox executor and derives the pre-enrollment documents without a Samba
backend. Incomplete private-group-only identity is refused. The documents are
staged only in fresh guest tmpfs, outside the daemon root and code-only tree.

A fixed bootstrap creates private mount/network namespaces, binds read-only
code and read-only/nosuid/nodev/noexec lookup files, closes escape descriptors,
chroots, switches to nobody and drops every capability. The dynamically linked
ARMv5 glibc probe verifies name/ID lookup, exact private primary groups,
`getgrouplist`, bounded enumeration, absence of foreign users/groups and lack
of shadow, devices, original paths, Samba state or data grants. An owned,
single-use capture validates exact output, ordinary exit and complete group
absence before release. Owner evidence remains unchanged across execution.

Actual ARMv5 execution passes all prior Samba gates and this new positive
control. Three controlled child-document faults — changed UID, an extra
supplementary group and a foreign user — must reach the real libc probe and
return its exact refusal, not merely fail bootstrap. Restored lookup passes in
a fresh capture; no stale capture or service authority is revived. Host marker
tests reject missing, duplicate, reordered or weakened evidence. All 29 Linux
driver tests, tagged vet and the focused ARMv5 campaign pass locally.

This proves libc consumption in an independent disposable root, **not**
installation in the daemon, retained identity/configuration authority, a
same-state credential backend, product startup, a new full image/source bundle,
hosted qualification or physical EX4 support. The complete cached result on
`fa4f25a` below predates this test-only increment. Password assignment, explicit
enable/revoke, storage leases and durable service recovery remain to compose.

## M2.4 native enrollment lookup — internal prerequisite

The Owner now has a separate non-recovering read-only native lookup for confirmed
private Unix identities, including disabled accounts before Samba enrollment.
It freshly observes the complete Unix census under the mutation lock and needs
no passdb backend. Its independently domain-separated fingerprint includes
registry/native/stable Samba journals and census; uncertain journals, incomplete
or changed identities and cancelled/busy/closed admission refuse evidence.
JSON is blocked. The stronger service reader retains its passdb requirements
and original fingerprint format, sharing the same native-validation helper.

The separate internal enrollment builder derives immutable locked files-only
NSS documents under the Owner lock, reusing the active planner's grammar and
32 KiB/128-account bound. It is not a Plan, credential observation, share grant,
lease or service activation. No files are installed or daemon changed. The
new ARMv5 smoke runs it after actual typed Unix creation and before the existing
fixture's first enrollment; it also requires refusal of an actual incomplete
identity. Host/root tests, tagged vet and focused race-count3 pass. The current
source also passes actual ARMv5 API overlay smoke and the separate two-boot
state suite against the manifest-verified cached baseline. The new mandatory
marker requires exactly one pre-enrollment native-lookup result; altered,
missing or duplicate evidence is refused by the driver's executed host tests.
The injected API is SHA256
`02dc89218ec57d2a6f04467efb2fad1d46cdc723cfb7f4936dc1719e8516540d`.
That first result is userspace overlay execution, not a complete image build.
The same frozen source subsequently passes complete cached local integration
on `fa4f25a`: host/race/fuzz, package compilation/source collection, ARMv5 smoke,
MD metadata, two-boot state, launcher/code ownership, loader/atomic dispatch,
restricted-root Samba and synthetic SMART producer/capture. All 862 tracked API
files independently match the compiled package and source archive. The installed,
embedded and exported API match SHA256
`59a605980323dcc46e441ecc3e0dffe64f24e9001eec65354cfcba62a48aeb95`;
all seven artifact manifest entries independently verify. This is cached local
qualification, not independent clean reproduction, complete release licensing,
hosted qualification, native libc consumption or physical EX4 qualification.

The separate fixture above now qualifies lookup-only native libc consumption.
The new tracer above also retains the actual documents through the protected
configuration boundary during one fixed worker. Next compose the whole
identity/configuration lifetime and credential backend with the SAME daemon
state. Actual
disabled-first enrollment, password assignment, enable/revoke, storage leases,
durable recovery and product activation must still be composed; a candidate
lookup alone does not close those gates.

## M4.4 state-bound Samba observation worker — QEMU prerequisite

The fixed disposable capture adapter now runs actual ARMv5 `pdbedit` in the
daemon's restricted root with independent references to the same seven mutable
state directories. The bootstrap masks the old source pathname, attaches the
original objects, closes input FDs before exec and retains the owned process
group. Only a fixed synthetic-account listing with empty regular stdin is
allowed; no tool/action/config/account or password option is added.

The actual campaign qualifies duplicate late-input refusal without launch or
partial-pin leak, closure of all temporary callers before capture, private
bounded output, single-use enforcement, verified group absence, explicit
release and stable FD counts. All old Samba guards and the new mandatory marker
pass within the unchanged 180-second guest budget. The code-only closure adds
only `pdbedit`, with fixed manifest/loader checks and all previous refusals intact.
Native vet/API tests and QEMU-tagged processowner/runtimebundle race-count3 pass;
native host refusal is not a positive ARMv5 result.

This closes a state-bound worker tracer, not real identity-owner enrollment or
revocation. Owner-derived private NSS, the credential backend, authoritative
passdb mutations and tracked storage leases still need composition. Code/config/
data root construction remains fixture-path-based. This increment's own complete
cached local Buildroot/QEMU integration passes on `c4ed376`, including its new
mandatory worker marker, all prior Samba guards and final SMART lanes. All 857
tracked API files independently match compiled and collected source; installed,
image and exported API match SHA256
`aa3b29b301bd4a6f6b65c1377c97568c669f15b6284661bf43222df37fe5f5e8`,
and all seven distinct expected artifact hashes agree. Cached validation is not
independent clean-build reproduction. Exact-head hosted qualification remains open;
no product service, HTTP, NAS, physical disk or installation is enabled.

The subsequent QEMU-only fixture extension also exercises this worker's existing
public capture contract before launch: cancellation before admission returns no
output and does not consume it; a late protected-state directory mode change
causes review without output, retains all nine code/input/state references and
refuses restart after restoration. Verified absence and explicit close release
the complete roster without an FD leak. Actual ARMv5 and all previous Samba
gates pass within the unchanged guest budget; strict fixture tests, native tagged
vet/race-count3 and API/UI cross-compilation pass. No production interface or
behavior changes. This focused result is not a new complete package/image build;
the full `c4ed376` result above remains scoped to that source revision.

## M4.4 Samba state descriptor handoff — QEMU only

A fixed `qemu && linux` construction adapter independently retains seven
read-only directory descriptors (root plus six roles) and the static bootstrap.
No generic `Spec`/`Start` extra-descriptor API is added. The child validates the
fixed FD ABI before effects, clones the admitted mounts with `open_tree` before
namespace isolation, then attaches them with `move_mount` in its private root.
All state views must match the original objects and be writable/nosuid/nodev/
noexec; all seven input FDs are explicitly checked closed before daemon exec.

The parent constructor now also refuses duplicate directory objects and mixed
filesystems before publishing a process set. Actual ARMv5 constructor probes
reject duplicate/nil/closed/O_PATH/regular-file last inputs after six valid
roles, with no process launch, no partial-pin leak and caller references intact.
The real daemon survives closing all seven temporary caller inputs and mutating
the caller's argv/credential objects after construction. A separate frozen-group
state-drift case forces bounded termination, retains code/config/state in review,
refuses restoration/restart and releases only after explicit verified cleanup.
All four lifecycle cases require stable descriptor counts and strict new
admission/copy/forced-stop evidence; the existing180-second guest budget is unchanged.

The actual ARMv5 regression masks the source pathname with an empty tmpfs in
the child only. Path-based construction fails; the descriptor handoff passes
real SMB readiness, live child-object checks, normal stop and config/state drift
with retained review. The complete focused campaign and strict evidence
validator pass, including unchanged base hashes and steady-state FD counts
across all four cases. The initial cross-namespace legacy bind attempt failed
with `EINVAL`; retained mount clones must be created before changing namespace.

This is a state-source handoff tracer, not atomic construction of the entire
service root, product passdb authority or qualified persistent state. Code,
configuration and storage view construction still use fixed fixture paths.
Same real identity/NSS/passdb/storage authority, durable recovery and product
startup remain required. No NAS, physical disk or product listener is used.

The complete handoff/admission/forced-stop source `303adae` passes cached local
Buildroot/QEMU integration, including every existing guest lane and final SMART
fixtures. All 854 tracked API files match both compiled source and collected
archive; embedded/installed/exported API and seven artifact hashes independently
agree. The exported API SHA256 is
`fbc018bcbe497249e61583eb5d5a9981057375009cda22b37f8b0c238a65d585`.
This is this increment's own full local result, not borrowed ancestor evidence.
It does not establish clean reproduction, hosted exact-head qualification,
product activation or physical EX4 support.

## M4.4 mutable Samba state-directory lifetime — QEMU prerequisite

The guarded Samba configuration Owner now retains the original writable tmpfs
state root plus six fixed role directories. Their identity, root ownership,
0700 mode, mount and lack of permission-changing attributes are rechecked;
legitimate TDB/log writes are not treated as immutable-content drift. The
ordinary mount-ID check is used only with retained references and does not
weaken immutable code/config's unique mount-ID requirement.

The focused actual ARMv5 campaign passes with the existing real daemon and
synthetic credentials: same child directory objects, writable/nosuid/nodev/
noexec views, normal mutation, live private-directory mode drift, verified
whole-group stop, retained review, refusal after restoration and explicit
verified code/config/state release. All earlier access/ACL/stream/code/config
checks pass and the manifest-verified base image is unchanged. Native root tests
cover same-mode replacement, missing/symlink roles, mode and actual kernel ACL
refusal, cancellation and independent/idempotent release.

Complete cached Buildroot/QEMU integration on `336c29f` additionally passes
host vet/tests/races/fuzz, source/legal-info collection, ARMv5 smoke and MD
metadata, separate two-boot persistence, isolated/static Owner, loader/atomic,
the entire Samba campaign and both final synthetic SMART lanes. All seven
exported hashes verify independently. Every853 tracked API source file matches
the compiled source and collected archive; embedded, installed and exported
API bytes agree. This is cached local integration, not clean hosted CI,
physical EX4 qualification or complete release licensing approval.

The subsequent state-source descriptor handoff is qualified only as described
above, not atomic whole-root construction, complete passdb-file lifecycle,
product state provisioning or real identity-authority composition. No HTTP/product startup,
physical storage or NAS operation is added. See the
[state-directory contract](support/SAMBA-RUNTIME-PROFILE.md#qualified-mutable-state-directory-lifetime-qemu-only).

## M4.4 identity-consumer retention — internal prerequisite

The Linux identity Owner now retains a bounded, opaque consumer only after
fresh complete evidence exactly matches the expected private fingerprint.
Owner close releases nothing while consumers remain. Tokens share state across
copies, refuse JSON, and release idempotently without closing the original
authority. Verification drift or an uncertain admitted observation is permanent
review even after restoration; pre-admission busy/cancellation is not drift.

Root-run Linux tests exercise exact lifetime/exclusive ownership, restoration,
read uncertainty, capacity/reuse, copied concurrent release and redacted
serialization. Existing explicit revocation and disabled credential rotation
remain usable while a consumer is retained; it does not freeze the Owner lock
or mutable passdb. Full Linux API vet/tests, QEMU-tagged vet, three focused
race repetitions and Windows API/UI/cross-compile pass. Actual ARMv5 credential
fixture integration also passes: exact Owner retention/busy close, real
credential disable/new-login denial, explicit re-enable, permanent review,
stale-acquisition refusal and release without identity mutation. The probe
launches no descendant and is not the Samba service Owner. The complete API
overlay smoke and separate two-boot persistence test pass on the unchanged
qualified base kernel/packages; this is not clean Buildroot CI or hardware
qualification.

This reference is not yet a Samba service Owner. Same-object NSS/passdb/state,
descriptor-bound storage, coordinated account changes, verified group stop
before release, durable recovery and product startup remain required. No NAS,
disk, flash, HTTP endpoint or product listener is involved. See the
[consumer contract](src/phantowd-api/identityowner/README.md#file-service-consumer-retention).

## M4.1 Owner-derived native NSS candidates — internal only

The existing candidate Plan now derives bounded passwd/group/nsswitch text for
its enabled, granted native Samba accounts. Same-number private primary groups,
locked password sentinels and files-only NSS are preserved; unrelated/imported
accounts, supplementary groups and secrets are not copied. Root/nobody lookup
rows grant no SMB access. Retired IDs remain reserved outside the rendered view.
The combined text is limited to 32 KiB/128 accounts, deterministic and bound to
the existing candidate freshness; zero/refused plans return no partial NSS.

An SMB-only regression exposed missing UID/GID-census admission that NFS had
previously checked indirectly. Both missing-number cases fail before the fix
and pass after explicit SMB admission. Host tests also independently parse and
assess generated identities, verify maximum/order/copy behavior and exercise a
valid managed `nogroup` without an invented colliding system group.

The separate disposable ARMv5 Owner/passdb/mounted-roster fixture derives the
same candidate under ordered locks, verifies private identities and both census
refusals, then round-trips desired state with unchanged native/Samba journals
and passdb identity. Old freshness and disabled desired grants are refused.
Local qualification passes the API/UI and ARMv5 cross-compile checks, Linux
QEMU-tagged vet/focused races, and the actual ARMv5 API-overlay smoke followed
by the separate two-boot persistence test. The first overlay attempt failed
on exact serial-marker matching with CRLF; a command-boundary regression and
trailing-CR-only normalization fix it without relaxing evidence or deadlines.
This overlay reuses the qualified base kernel/packages; it is not a clean
Buildroot build, regenerated SBOM/legal-info or hardware qualification.
Candidates are not installed or consumed by the daemon: native libc lookup,
daemon identity-consumer composition, actual same-passdb/state and descriptor-bound grants,
transactional activation/recovery and product startup remain open. See the
[internal candidate contract](src/phantowd-api/internal/fileserviceplan/README.md#candidate-samba-nss).
## M4.4 protected configuration lifetime — QEMU prerequisite

The separate guarded Samba fixture now retains an exact seven-file config/NSS
roster through actual service execution. Expected hashes come from independent
compiled fixture contents, not the filesystem under inspection. A private
configuration plan has a 16-file/64-KiB bound and protected data modes; public
code `NewPlan` keeps its original 0444/0555 admission. Mutable passdb and state
are deliberately excluded from immutable configuration.

Actual ARMv5 verifies config caller closure, retained original objects visible
inside the real child, read-only/nosuid/nodev/noexec views, normal stop, live
configuration-mode drift, retained review, restoration without restart and
release only after verified group absence. The regression found that a
nonrecursive root bind hid the earlier config submount: the fixed bootstrap now
rebuilds that protected view inside the new root. Final daemon capabilities and
generic static/non-root admission are unchanged.

Local final-source qualification passes 22 fixture/seven loader tests, linters,
actual full focused Samba ARMv5 campaign, Linux QEMU-tagged vet/focused races,
and Windows API/UI/cross-compile. All older code/SMB/access/ACL/streams checks
remain green and all seven base hashes unchanged. Renewed complete cached local
Buildroot/QEMU validation on `faf1c88` also passes after the correction below:
host vet/tests/races/fuzz, image/source collection, initial smoke, MD metadata,
two-boot persistence, isolated/static Owner, loader/atomic, actual Samba and
both final SMART lanes. All 847 tracked API files match the compiled source
tree and collected package archive; the API embedded in rootfs matches the
target and exported artifact. This is cached local integration, not independent
clean CI, complete release-source compliance or a product activation claim.
The preceding complete local attempt reached the unchanged Samba guest deadline
after code lifetime but before configuration/DONE. Phase measurements isolated
an initial entropy wait; the driver now supplies the already-supported virtual
RNG from host kernel randomness and refuses a missing provider before staging.
The actual missing-provider negative and complete focused positive pass without
relaxing the deadline, privilege profile or access checks. The failed complete
attempt remains failed; the corrected complete run is independently successful.
Product renderer/identity revision, state and storage authorities,
race-qualified root construction and durable recovery remain open. See the
[protected configuration contract](support/SAMBA-RUNTIME-PROFILE.md#qualified-protected-configuration-lifetime-qemu-only).

## M4.4 retained dynamic-code lifetime — QEMU prerequisite

A separate guarded QEMU constructor now retains the complete Samba code closure
during actual daemon execution, reusing serialized revalidation/review/whole-group
cleanup without widening generic static/non-root `NewOwner`. Caller closure,
actual executed-object identity, live complete-roster recheck, normal stop,
live code-mode drift and forced stop of a frozen Samba group pass on ARMv5.
Review retains code references; mode restoration cannot restart; explicit
verified teardown releases them with no FD leak and safe repeated Close.

Final local qualification includes 20 fixture/seven loader tests, linters,
Linux QEMU-tagged vet/focused races and Windows API/UI. Every previous Samba
authentication, writer/reader, streams, ext4 ACL/inheritance and isolation gate
still passes; seven base artifacts are independently unchanged. Outer containers
are non-root/capability-free and disposable, with bounded RAM scratch, no new
persistent image/volume and no NAS/physical-storage operation.

This advances code lifetime, not complete service authority. Protected config,
identity/passdb revision, mutable state and descriptor-bound storage grants,
race-qualified construction, trusted manifest/ABI/model binding, combined live
supervision, durable recovery and product activation remain open. See the
[qualified lifetime profile](support/SAMBA-RUNTIME-PROFILE.md#qualified-dynamic-code-lifetime-qemu-only).

## M4.4 separate code/service views — QEMU prerequisite

The fixture now preserves an exact code-only staged tree while composing a
different service root. Its private read-only executable code views must expose
the same actual objects after separate config/NSS inputs exist. The strong code
census is unchanged; configuration is not silently excluded from a mixed tree.
An actual same-byte/same-mode different-inode catalog overlay is refused by the
same capability-free observer, not accepted on its hash alone.

Local final-source checks pass: 18 fixture tests, seven loader tests, linters,
Linux QEMU-tagged vet/focused races, Windows API/UI and actual ARMv5 Samba,
preserving all earlier writer/reader/authentication, streams, ext4 ACL,
inheritance and verified whole-group stop checks. Seven base artifact hashes
remain unchanged; no extra persistent image/volume or real-device operation.

The view observation closes descriptors before the later service. Configuration
contents, passdb revision, descriptor-bound grants, race-qualified construction,
complete live input retention/supervision and product activation remain open.
This is not M4 completion or installable firmware. See the
[qualified profile](support/SAMBA-RUNTIME-PROFILE.md#qualified-separate-codeservice-views-fixture-only).

## M4.4 shared code-input preparation — internal prerequisite

The package-private retained-code helper is now shared by static `Owner` and
the guarded QEMU prepared-code probe. It keeps independent root/file references
and original directory/file/alias identities, preserves exact census/hash checks
and the trailing identity fence, and adds no production API or execution grant.
The static constructor retains its static-ELF/non-root restrictions and unchanged
scan sequence; release remains after complete process cleanup.

Local non-root Linux vet/race checks pass, including cancellation before input
inspection and repeated failed preparation without caller-FD consumption or
descriptor leaks. Actual ARMv5 requalifies every existing static lifecycle,
supervision, mid-scan same-byte replacement, restoration refusal and forced-stop
review case. The runtime-owner wrapper now drops all Docker capabilities and
uses UID1000/NNP; privileged fixture setup stays in QEMU.

Actual ARMv5 also qualifies retention/revalidation/release of the prepared Samba
dynamic closure with caller closure, cancellation and stable descriptor count,
plus actual generic-adapter rejection of dynamic Samba with non-root/root
credentials. The preflight executes 17 fixture tests and seven loader tests,
while preserving all real SMB/streams/ext4 ACL/inheritance/owned-group checks.
The complete prepared-code references are released BEFORE configuration/state
composition and Samba startup. This does not complete dynamic service-lifetime
ownership, manifest provenance, product identity/storage/state composition,
input-drift supervision, durable activation/recovery or HTTP/hardware support.
See the [internal contract](src/phantowd-api/internal/runtimebundle/README.md#shared-prepared-code-references).

## M4.4 Samba owned-group boundary — fixture-only prerequisite

A separate QEMU-only probe now composes the pinned bootstrap helper with the
existing process-set owner, without weakening the generic static/non-root
runtime. The owned entry checks group leadership and writable anonymous
diagnostic pipes before bootstrap and before final daemon exec; it preserves the
group rather than calling `setsid`. Caller helper-FD closure, canceled admission,
duplicate Start and live Close refusals are tested.

Actual ARMv5 locally passes fresh SMB write/read bytes, distinct Unix ownership,
reader/outsider/authentication denials, kernel-read-only write refusal, private
namespace/restricted root and the exact six-capability/root/NNP profile. Normal
Stop proves parent reap and complete group absence before helper-pin release.
Six native context refusals and fixed-command admission regressions run before
the guest. The expanded tests caught two fixture defects (missing fixed client
commands and the wrong expected kernel-RO NTSTATUS); neither was repaired by
relaxing permissions or execution/stop guards.

Local verification (2026-10-06): 16 Linux fixture tests, seven loader tests,
linters/workflow contracts, Windows API/UI preflight, Linux QEMU-tagged vet and
process/runtime Owner race tests, and the complete ARM926 Samba experiment with
all old streams/ext4 ACL/inheritance gates. Seven base artifact hashes remain
unchanged. One auto-removed non-root container reuses existing caches read-only
with bounded tmpfs; no new persistent image/volume or product/NAS operation.

This is not the complete Samba Owner: retained authenticated dynamic inputs,
configuration/passdb/identity and storage authorities, input-drift/forced-stop
composition, durable recovery, product startup and HTTP activation remain open.
No milestone is declared complete or hardware/installation band increased.
See the [profile and full integration contract](support/SAMBA-RUNTIME-PROFILE.md#samba-specific-owner-integration-packet-hostqemu-scope-approved).

## M9.1l cooperative backing-object ownership — private prerequisite

All internal writable constructors now require a retained shared use authority.
It samples the actual RW descriptor against each privately held Pin, then
reserves the entire roster atomically by device/inode identity. Mount ID,
logical VolumeID, path and separately opened descriptors cannot create a second
slot for the same object. A later conflict publishes no earlier reservation.
Admission failure returns caller resources; successful lifecycle release occurs
only after verified whole-backend stop, all data/Pin closures and source release.
Uncertain stop/closure retains the reservation in terminal no-retry review.

An actual standard ARMv5 tracer first admitted independent Pins/descriptors for
the same two files; the corrected tracer passes. Scope correction: the three
native actual-object positive tests SKIP on the local WSL 6.6 kernel because
unique mount IDs are unavailable. Aggregate native green does not establish
concurrent admission, verified reuse or uncertain-retention syscall evidence.
The mandatory actual mounted ARMv5 concurrent fixture now executes: independent
Pins/RW descriptions race into the SAME authority; both admissions join before
release; exactly one succeeds, and the refused caller retains its handles.
The winner runs a UID1000 consumer and remains busy until verified whole stop,
child reap and all member closures. The losing original handles then admit and
run a second consumer through that SAME authority. Readiness bytes are cleared
before reuse so the second child must write them anew. Standard ARMv5 and the
complete two-boot regression pass locally with the mandatory concurrency marker.
An additional mandatory mounted ARMv5 fault closes the later caller-owned
descriptor before prepared-Owner teardown. The actual later os.File.Close
failure follows a successful earlier data close; all metadata, whole object
reservation, policy, credentials and mount remain retained in terminal review.
Even a new independent open of the earlier object is refused. Repeated lifecycle
operations cannot retry closure or start a backend. This is a controlled
already-closed-FD fault, not a storage-I/O/ECC failure or live-LIO recovery test.
The actual mounted capacity fixture fills the shared authority with 63 distinct
prepared singleton objects. A complete two-file target refuses atomically with
caller handles intact; the unused first file can still occupy slot64, while
another object refuses. Verified closure frees two slots and the complete
target then admits through the SAME authority. No fabricated identity/map keys
or backend start is used. Standard/two-boot pass. Kernel-independent native
serialization/reconstruction refusal and empty-close checks execute under race
count3; the three actual native statx-positive cases remain explicitly skipped.
Actual mounted ARMv5 also refuses a later-member-only conflict with no earlier
reservation or backend effects, preserving caller resources and allowing a
singleton to claim the unused member through the same authority. Whole tagged
vet/race, focused repetitions, Windows cross-compile, standard/two-boot and
fresh guarded LIO/all previous gates pass locally. Cached overlays do not prove
clean-build reproducibility, complete global-use admission or EX4 qualification.
This is private cooperative in-process exclusion, not a filesystem lock or
complete product authority. The trusted composition must supply the SAME
instance to all consumers; independent authorities, external processes, foreign
targets and concurrent SMB/NFS aliases are not excluded. No product opener,
HTTP endpoint, persistent state, service startup or NAS operation is added.

## M9.1k declared backing exposure — private admission prerequisite

The selected target's complete LUN roster now refuses configured SMB/NFS
equal/ancestor/descendant/root exposure on the same logical VolumeID, including
read-only shares and desired disabled targets. The private planner, LIO definition
constructor and older policy-bound singleton compositions enforce this before
resource transfer or credential/backend preparation. Errors return no partial
definition. Desired validation/save and advisory previews remain unchanged.

Whole Linux tagged vet/race and focused repeated native tests pass locally,
including RO/RW canonical-component boundaries, different logical volumes,
unchanged desired policy and bypass refusal. A mandatory disposable ARMv5 case
for each protocol checks a later-member-only conflict with actual mounted Pins,
RW caller descriptors and root-only policy/CHAP sources; backend effects and
retained source claims must be absent. Actual standard ARMv5 and complete
two-boot regression pass locally. A fresh guarded LIO kernel/guest run also
passes all previous credential, access, session, topology and fault gates.
Base artifacts verify unchanged; this cache-reusing overlay is not clean-build
reproducibility or physical EX4 qualification.

This is only a negative check of configured paths. Actual aliases across paths
or logical volumes, other users/processes/targets, concurrent share activation,
global-use/session/allocation and retained product authority remain open.
No policy schema, HTTP endpoint, product startup or NAS operation is added.

## M9.1j foreign endpoints — disposable host/QEMU proof

The exact target census now has actual guarded ARMv5 cases for a NEW foreign
guest-loopback portal under owned tpgt_1 and a NEW sibling tpgt_2, which stays
default-disabled with no portal. Both cause terminal Owner review, one stop
attempt, preserved captured/path foreign identity and complete retained
file/Pin/mount/policy/CHAP claims. Repeated lifecycle calls never retry.

The portal prevents complete owned TPG removal; disabled readback still works.
The sibling TPG instead prevents target removal after the owned TPG has been
disabled/removed/closed. The fixture verifies that different partial outcome
without reopening a vanished owned object. Only an independent controller
removes its still-witnessed synthetic object and remaining idle owned objects
before releasing sources; it never resets review or the backend stop state.

Fifteen mandatory result-contract groups, mocked wrapper profiles, Windows
preflight/cross-compile, whole Linux tagged vet/race and focused repetitions,
fresh guarded ARMv5/all old LIO gates and standard/two-boot regression pass
locally. Only QEMU fixture/qualification evidence changes; the production
backend is unchanged. No shared-portal race, active foreign session revocation,
exclusive writer/network authority, exhaustive faults/resource limits, durable
recovery or product activation is qualified. No NAS or physical media is touched.

## M9.1i exact target topology — private host/QEMU prerequisite

The retained-storage LIO backend now censuses configurable rosters inside its
owned target: target/TPG, named ACLs, data LUNs, per-peer mappings, portal group,
and owned LUN/mapping/portal directories. Expected names come only from the
captured policy and pinned Linux defaults, never an observed baseline. Each
directory accepts at most 64 entries, with overflow/end-of-list checks, fresh
confined open descriptions and original configfs identity rechecks. Start checks
before/after enable; active observations bracket existing attribute/credential
checks. The census reads names only, not data or authentication attributes.

Actual ARMv5 regression first fails at foreign ACL observation without this
census. Final guarded guest rejects NEW foreign ACL/LUN/mapping objects,
preserves their witnessed identities, retains every file/Pin/mount/policy/secret
claim through uncertain teardown, and never retries from terminal review.
Independent fixture disposal is not recovery. All old protocol/fault/session
gates, native tagged vet/race/repetitions, Windows cross-compile, 14 result
contracts and standard/two-boot tests pass locally. An initial default-name
mistake is corrected from pinned kernel source: fabric-root lio_version and
cpus_allowed_list are not attributes of an individual target.

This is point-in-time target observation, not a global fabric census, atomic
mutation witness, concurrent-root exclusion, pending-login fence or permission
to disable foreign sessions. M9.1j adds two bounded foreign-endpoint cases;
concurrent/shared-portal mutation and full capacity/resource campaigns remain.
Product runtime/storage/network/global-use,
durable recovery, credentials and UI/startup gates are unchanged; no NAS I/O,
new product interface/privilege or Docker image/named volume is introduced.

## M9.1h bounded configfs fault proof — disposable host/QEMU only

The actual retained-storage adapter now tests an existing target before effects
and an existing second storage after the first LUN is bound. Both fail setup,
preserve the foreign object's witnessed identity and original data, and remove
only the adapter's NEW objects before complete resource release. Owner review
remains terminal: failed setup is not readiness or an implicit retry.

A third case adds a separate NEW test-owned LUN referencing the first storage.
Real teardown disables the TPG and removes earlier owned entries, then refuses
to remove the still-referenced storage. Every backing descriptor, Pin, mount,
policy and secret claim remains held; repeated lifecycle calls do not retry.
An independent fixture controller validates and removes only its own blocker,
then disposes remaining idle objects before fixture release. It never resets
the failed backend/Owner or supplies product recovery.

The first fault trigger incorrectly added a second link on an already-bound
LUN. The real guest failed; the corrected test retains an exact EEXIST/no-link
regression and uses the separate LUN's legal binding. This is a test defect,
not a legacy WD/kernel defect. The retention assertions were not weakened.
Windows preflight/cross-compile, native tagged vet/race/focused repetitions,
fresh guarded ARMv5 LIO including all old gates, and standard/two-boot tests
pass locally. A mandatory fault marker rejects missing/duplicate/weakened proof.

These are three bounded fault cases, not exhaustive store/readback/close/delete
coverage, continuous writer exclusion or clean hosted/hardware qualification.
Pending-login/new-login fencing, protected runtime/storage/network/global-use
composition, durable recovery and product activation remain open. No NAS I/O,
product interface/privilege change or new Docker image/named volume is added.

## M9.1g adapter access/session proof — disposable host/QEMU only

The private retained-storage LIO adapter now has its own real initiator tests,
not only the separate manually configured protocol fixture. Two peers use
distinct synthetic credentials. The primary writes/reads both LUN0/7; a peer
sees exactly LUN0 read-only. Its write returns exact SCSI write-protected sense,
LUN7 returns logical-unit-not-supported, crossed credentials and a foreign IQN
fail with exact authentication/authorization status. Original data is preserved.

A separate case keeps ONE libiscsi context connected through the real Owner's
stop attempt. The non-forcing primitive refuses; fresh reads AND writes on both
LUNs still succeed through the same context. Independent retained-descriptor
reads confirm the new bytes. Every data/Pin/mount/policy/credential claim remains
held, Owner review is terminal, and start/observe/stop/close never retry teardown.
Logout does not change this state. A separate QEMU-only controller verifies idle
and witnessed object removal before independent fixture release, without
calling/resetting the failed backend stop or clearing review. This is NOT
product recovery. The refused target remains enabled; this does not establish
new-login fencing or pending-login side-effect freedom.

Final Windows preflight/cross-compilation, pinned whole Linux tagged vet/race and
focused repetitions, fresh actual guarded ARMv5 LIO, all old protocol gates and
standard smoke/complete two-boot regression pass locally. Separate mandatory
access/session result markers reject omission, weakening or duplicate evidence;
their consumer contracts were observed RED/GREEN before each implementation.
No product interface, privilege expansion, physical disk, NAS operation or new
Docker image/named volume is added. Clean hosted qualification remains separate.
M9.1h above adds bounded setup/teardown faults; exhaustive fault qualification,
exclusive configfs/code/network/storage/global-use authority,
durable recovery, credential provisioning and UI/startup remain open.

## M9.1f retained-storage LIO composition — private host/QEMU prerequisite

The private Linux backend captures a validated target definition, duplicates
root-owned configfs directory references, creates only new owned objects and
receives the complete already-admitted backing roster from its containing
Owner. Explicit LUN numbers, capacities, block sizes and per-peer grants are
matched. Integer-only retained proc-FD control values replace desired paths;
no missing-file creation or product data opener is supplied by this adapter.
CHAP-only is deliberate: unsupported required-mutual mode fails before effects.
The loopback portal is fixed and test-only, not a product network selection.

Typed credential readback, object/link identity and fixed authentication/storage/
mapping attributes are rechecked while active. Partial setup is retained for
one stop attempt; readiness is separate from partial-start state. The optional
research kernel's non-forcing idle-disable primitive is required before any
portal/data binding. No forced-disable fallback or retry exists. Confirmed
configfs teardown precedes containing-Owner data/Pin/mount/credential release;
uncertainty retains the remaining references in review.

Windows preflight/cross-compilation, pinned whole Linux tagged vet/race/focused
repetitions, shell/result contracts and a fresh guarded actual ARMv5 guest pass.
The new guest uses one disposable 16 MiB ext2 image, an actual mount Owner,
LUN0/7 with 512/4096-byte blocks and two RW files. Pinned libiscsi writes/reads
both; independent file reads verify the original objects. Changed second-file
identity and mapped permissions quarantine; injected stop uncertainty retains
all live sources without retry, followed by distinct test-only disposal. Actual
write-only attribute probes and a native RED/GREEN regression lock down configfs
`control`/`disable_if_idle` open modes. Old separate authentication, live-session,
RO/RW and multi-LUN assertions remain mandatory. Standard userspace smoke and
the complete clean two-boot state lane also pass locally.

This composition-only increment does **not** qualify RO grants or real
live-session refusal; M9.1g above adds those bounded adapter fixtures. Fault
recovery, exclusive configfs writer authority, retained runtime-code/network
authority, protected storage/registry/allocation/global-use admission, mutual
enforcement, credential provisioning/rotation or durable product recovery.
Old separate protocol proofs do not replace those adapter-specific tests.
No product startup, HTTP activation, physical disk, NAS operation or new Docker
image/named volume is added. Cached local execution is not an independently
clean Buildroot/hosted feature build or physical EX4 qualification.

## M9.1e typed LIO credential installation — private research prerequisite

The Linux-only fixed sink borrows backend-owned TPG/auth directory references,
requires root-owned writable configfs, and binds every supplied auth descriptor
to its named ACL below that retained TPG. Same-configfs foreign ACLs refuse.
Whole peer matching precedes a single installation attempt. Fixed leaves receive
opaque secret buffers directly; bounded exact readback handles the pinned
kernel's show newline without adding a store newline, then wipes scratch.
CHAP explicitly unsets stale outbound fields. Observed field/topology drift or
partial I/O uncertainty stays review without reinstall/retry. This is disabled-
state observation, not an atomic transaction or continuous mutation witness.

Native tagged vet/race and lower-I/O/roster/refusal tests pass. Actual fresh-source
default-profile ARMv5 LIO tests also pass: two successive zero-data-LUN targets
exercise the real sink, root-only retained credential claim, CHAP/reciprocal
exchange through pinned libiscsi, wrong/missing credential refusal, same-configfs
foreign ACL refusal, stale outbound unsetting, restored drift quarantine and
complete configfs-object teardown before claim release. All previous actual
data/session/auth/two-peer/multi-LUN assertions remain mandatory and pass.
Mocked wrapper profile checks do not establish actual strict/idle qualification
for this new case; the final-source actual run uses the unchanged default profile.
Windows no-Docker preflight/cross-compilation, standard cached userspace ARMv5
smoke and the complete clean two-boot state regression also pass. These do not
establish independent clean Buildroot or physical EX4 qualification.

The sink does not create/enable targets, open LUNs, release claims, provision
secrets or offer active-state observation. The tagged fixture alone owns fixed
synthetic target/loopback operations, with no physical disk/NAS/product startup.
No complete targetBackend belongs to this credential-only increment; M9.1f
above adds private composition, not product admission. Exclusive configfs and
session/global-use authority, durable recovery and UI activation remain open.
No guaranteed kernel/runtime memory erasure or mutual-only policy enforcement
is implied. Those M9.1b/product gates remain open.

## M9.1d complete-target resource lifetime — internal host/QEMU prerequisite

The private constructor retains one coherent policy claim, one credential
bundle and every selected target LUN's existing Pin/RW descriptor. It reuses
the existing lifecycle/supervisor. Complete exact membership, explicit numeric
ordering and observed inode/device alias refusal precede real per-member
descriptor/root admission. Failed late admission rolls back provisional claims
without closing caller files or preparing a backend. Desired access/enable
still supplies no activation or permission authority.

The fixed backend borrows the complete defensive roster. Verified teardown of
all borrowers precedes every data close; every data close precedes any Pin
release, and complete reference closure precedes shared policy/credential
release. Second-member drift and partial start/stop/close uncertainty enter
terminal review without retry. Uncertain stop retains all sources; partial close
retains remaining references/global claims, without reopening already closed files.

Windows preflight/cross-compilation, pinned Linux root-focused tagged vet/race
count3, non-root whole tagged vet/race, storage/shell contracts and actual ARMv5
standard smoke plus the complete two-boot state fixture pass locally. Native
lifecycle tests use an explicit seam; real mounted guest cases cover complete
two-member admission, failed second-file rollback, LUN0/LUN7 input-order reversal,
512/4096-byte metadata, replacement of the second file and uncertain stop. A
fixed UID/GID1000 child inherits both descriptors; no credential enters the
child. These are cached userspace-overlay results, not clean hosted-build,
LIO installation, protocol authentication, access enforcement or EX4 proof.

No product data opener, LIO/configfs adapter, allocation/global-use/session/
network admission, provisioning/recovery, HTTP, listener or startup is added.
M9.1b product gates remain open. The earlier single-backing M9.1c evidence below
remains separate and is not retroactively promoted to complete-target proof.

## M9.1c retained root-only CHAP material — internal prerequisite

The first-release decision permits root-owned recoverable plaintext (`0700`
directory, `0600` file); encryption at rest is deferred, not provided. Internal
`iscsicredentials` reuses the protected revision engine for initialized state,
retained claims and restored-mutation quarantine. Policy contains only refs.
All references resolve before target selection; missing/duplicate byte values
and LIO reserved prefixes refuse without partial material. A fixed trusted
consumer receives opaque sink-writable buffers; normal formatting is redacted
and JSON denied. Best-effort wiping applies only to owned buffers, not all
runtime/JSON/kernel copies. Token length is not entropy qualification.

The private backing owner retains its own policy/credential/mount/RW claims,
prepares with the same backend, and releases only after confirmed teardown and
reference closure. Partial preparation/stop/close uncertainty retains review
without retry. No writer, import, entropy generator, endpoint or startup exists.
Only tagged fixture code provisions a fresh synthetic vault.

Windows preflight/cross-compilation, pinned Linux root-focused tagged race
count3, non-root whole tagged vet/race, shell/storage contracts and actual ARMv5
standard smoke plus complete two-boot state pass locally. Root-focused tests
exercise actual protected files but synthetic lifecycle admission; three added
mounted guest cases retain the real UID/GID1000 child through normal/drift/
uncertain stop. Credentials stay in the fixture's root-only synthetic sink,
not the child or configfs. This is neither actual LIO credential-install proof
nor target-wide/multi-LUN ownership, production state/recovery, clean-build or
physical EX4 qualification. M9.1b product activation gates remain open.

## M9.1b private policy/backing supervision — host/QEMU prerequisite

The internal writable-reference prototype now offers one explicit blocking
supervision operation for an already-active consumer. It reserves the lifecycle,
performs an immediate complete scan, then serial scans after a fixed one-second
idle period. Concurrent lifecycle operations refuse busy; no detached monitor,
catch-up queue, automatic start/restart or product init is added. Accepted cancel
uses a fresh five-second operation context to verify stop/reap before reference
and policy release. Drift/exit/stop/close uncertainty retains review without retry.
Regular metadata I/O is not a hard-deadline operation; product polling and
resource qualification remain open.

Windows preflight/cross-compilation, pinned whole Linux tagged vet/race and
focused backing/policy race count3, shell/storage contracts, actual ARMv5 standard
smoke and complete two-boot state pass locally. Native tests include cancellation
during a scan and policy fences. Four actual supervised policy cases and both
actual mounted-loss cases exercise the live UID/GID1000 static child; the test
goroutine is joined before independent fixture cleanup. This cached overlay is
not a clean hosted/EX4 test, LIO runtime, durable recovery or activation authority.
The full M9.1b backend/access/allocation/use/session/credential gates remain open.

## M9.2e private policy/backing lifetime composition — host/QEMU prototype

The private writable-reference owner now acquires and retains its own coherent
NAS-policy revision claim. Construction matches the selected BackingID against
the mounted VolumeID, relative path and exact size, then applies the existing
descriptor admission. Failed construction consumes no caller-owned resources.
Policy verification brackets kernel/readiness observations. Verified stop/reap
and successful RW/metadata/mount-root closure precede policy release; uncertain
stop or reference closure retains claims and publication/Close fences without
retry. No new opener, HTTP endpoint, credential resolution or target activation
is supplied. Matching a disabled desired target is not execution authority.

Windows preflight/ARMv5 cross-compilation, pinned Go1.26.6 whole Linux tagged
vet/race, focused backing/policy-owner race count3, shell/storage contracts,
actual ARMv5 Linux6.18.54 standard smoke and complete two-boot state pass locally.
Three policy lifetime cases and both actual mounted-loss cases compose the
private claim with a live UID/GID1000 inherited-RW static child. Native tests
also cover before/after-start drift, failed admission and close uncertainty.
This is the cache-reusing overlay, not a fresh hosted build, production LIO
backend, physical-device qualification or durable recovery implementation.

Qualified code/backend, protected registry/media identity, access/allocation,
global-use/session and credential ownership, supervised product composition
and operator recovery still precede any live service activation. See the
[private lifetime contract](src/phantowd-api/internal/backingpin/README.md).

## M9.2d retained coherent policy owner — internal host/QEMU prerequisite

The opt-in Linux `naspolicystore.OpenOwner` requires initialized desired policy
and privately reuses the transaction engine. Constructor-issued revision claims
fence Commit and Close; defensive snapshots are not execution/storage authority.
Owned fixed-name reads bracket metadata and a private mutation watch, refusing
cross-mount/symlink traversal and restored-content ABA. Any unexpected change,
watch/read uncertainty or attempted publication failure retains review/claims/
flock without retry. Explicit claim release is the caller's responsibility after
independently confirmed consumer stop, not automatic session/process teardown.

Native and generated-media ARMv5 tests exercise these invariants, including
multiple nonempty three-protocol claims after reboot, a coherent explicit epoch
change and mutation/restoration quarantine. This adds no extra guest boot,
product startup, HTTP endpoint, backing/credential open or service activation.
Windows preflight/ARMv5 cross-compilation, pinned Go1.26.6 whole Linux tagged
vet/race, focused owner/store race count3, shell/storage contracts and actual
ARMv5 Linux6.18.54 standard smoke plus complete two-boot state pass locally.
The final run also includes acquisition concurrent with Commit/Close, mutation
during decode, publication cancellation and terminal close-uncertainty checks.
This is the cache-reusing userspace overlay, not a fresh Buildroot/hosted result,
physical power-loss test or EX4 qualification.

Single product state placement, preventing old/new authoritative writers,
format migration, service ownership/supervision, registry/mount/identity/access/
allocation/global-use/session/credential admission and recovery remain open.
See the [retained owner contract](src/phantowd-api/internal/revisionstore/README.md).

## M9.2c coherent SMB/NFS/iSCSI state — internal local prototype

`internal/naspolicy` binds all three desired protocols and shared volume/user
policy to one positive revision; seven counters/bindings must agree. Bounded
strict envelope and component decoding return no partial policy; nested byte
limits and explicit LUN0 semantics remain enforced. `internal/naspolicystore`
uses the existing fixed-name Linux revision engine, exclusive directory lock
and single rename/sync transaction. Pending is not recovery state, corruption
is not empty, and old formats are neither imported nor modified.

Windows preflight/cross-compilation, pinned Go1.26.6 whole Linux tagged vet/race
and focused model/store/envelope count3 pass. Both old two-protocol and new
three-protocol SIGKILL campaigns pass at seven publication points with three
repetitions: live child lock, exact old/new whole state, unchanged abandoned
pending, stale refusal and later explicit commit. Test hooks are not production
code. This demonstrates process death on a live filesystem, not power loss.

Actual ARMv5 standard smoke and existing generated-disk two-boot lane pass with
the mandatory nonempty three-protocol marker, mixed/stale revision refusal,
pending/corrupt evidence preservation and subsequent coherent commit/reopen.
The cache-reusing overlay retains the base kernel/packages/probe; bounded tmpfs
scratch and container disappear without new Docker image/volume. This does not
qualify clean builds, physical EX4 storage, recovery or installation.

No new HTTP, product state placement, service-runtime owner, credential/backing open,
mount or target activation is introduced. The old development HTTP/store stays
unchanged; product composition must prevent competing authoritative
formats and qualify migration. The opt-in retained policy owner above is not
product startup. This closes a desired-document coherence seam,
not live policy/registry/access/allocation/global-use/session admission.

See the [format/store contract](src/phantowd-api/internal/naspolicy/README.md).

## M9.1b retained mount-backed lifetime — private host/QEMU prototype

`OpenFromMountedLease` retains an existing complete mounted-roster lease through
an opaque member-root pin. It opens independently owned metadata directories,
not lease-tracked references that repeated checks would accumulate or close
twice. Group close refuses while a root pin exists, including an uncertain
consumer stop or uncertain reference closure. Whole-roster checks use canonical
locks; release closes references before dropping the root pin and never unmounts
or reacquires the original roster. No raw Root/data descriptor escapes.

Pinned Go1.26.6 whole Linux QEMU-tagged vet/race and focused package race count3
pass. Native modeled tests cover repeated independent directory ownership,
serialization refusal, concurrent release, mount/generation/drain quarantine,
unselected-member drift and uncertain close retention. Windows preflight and
ARMv5 cross-compilation pass. Actual ARMv5 Linux6.18.54 verifies real mount-owner
composition with normal/replace/exit/uncertain static-child lifetimes, direct
lease-close refusal, failed metadata admission without a stranded lease and
constant FD count across32 checks. A separate same-filesystem overmount proves
metadata-root identity loss retains its independent descriptor and group claim
until explicit release. Additional actual same-filesystem overmount cases use
a live UID/GID1000 inherited-RW consumer: observation quarantines, confirmed
stop/reap precedes release, and deliberately uncertain stop retains the live
child/RW/metadata/mount claims. Restoring the exact original bind cannot revive
review, retry stop or issue a fresh lease. Fixture cleanup must complete exactly
before success, with independently confirmed reap before disposal. This proves
mount-identity loss with a one-write/FD-holding child, not physical I/O failure
mid-transfer, LIO/session behavior, autonomous monitoring or product recovery.

The new native checker-seam drift/uncertain-stop/restoration composition and
nonfixture-input refusal pass alongside whole pinned Linux tagged vet/race and
focused race count3. Mandatory actual ARMv5 mounted-writer-loss assertions and
the existing clean two-boot state lane pass in the bounded API overlay. No
production behavior, backend authority or device startup is added.

Mandatory mounted-lifetime/root-loss assertions and the existing clean two-boot
state fixture pass locally. The API overlay reuses seven verified baseline
artifacts and the unchanged probe, with bounded discarded tmpfs scratch in an
auto-removed container; no new image or volume. This is not an installable EX4
image, hosted/clean-build reproducibility or physical-device qualification.
Production writable acquisition, roster qualification, coherent protected
policy/access/allocation/global-use/session/credential admission and a target
backend remain open. No HTTP, startup, LIO or NAS/disk/flash operation is added.

## M9.1b writable-reference lifetime — private host/QEMU prototype

An unexported owner now accepts an already-open RW file only after its identity
and safe flags match the retained metadata Pin. Successful construction takes
exclusive Pin/file/backend ownership; invalid input, including a typed-nil
backend, takes nothing. Direct Pin close is busy while claimed. Backend choice
is fixed at construction, not supplied by an operation or HTTP request.

Start and caller-driven observations bracket readiness with descriptor/Root
checks. Drift, exit or uncertainty quarantines and attempts stop once; verified
stop precedes RW and metadata release. Uncertain stop preserves the references
and rejects close/retry/restart. Native state-machine seams are not filesystem
admission. Actual ARMv5 Linux 6.18.54 uses the real qualified ext Root, rejects
foreign/RO/append/non-CLOEXEC descriptors and duplicate ownership, and exercises
inherited-FD writes, replacement preservation, unexpected exit, concurrent stop
and uncertain retention with a UID/GID1000 static consumer. Thirty-two credential
observations after readiness cover the previously reproduced shell/second-exec
setuid transition; the fixed consumer never executes another program.

Windows DOM/API vet/unit/cross-compilation, pinned Go1.26.6 whole Linux tagged
vet/race and focused race count3 pass. Storage contracts, smoke ShellCheck,
actual standard ARMv5 smoke and the existing clean two-boot state lane pass
locally. Seven verified baseline artifacts and the unchanged probe are reused;
scratch is bounded tmpfs in an auto-removed container, with no new image/volume.

There is no exported writable constructor, product opener or LIO backend.
Product mount qualification, permission/allocation/global-use/session
admission, credentials, protected policy binding and durable recovery remain
open. Independent fixture teardown after confirmed reap is not owner recovery;
the fixture is not a general process-isolation profile. This is a userspace
overlay, not clean firmware reproducibility, hosted or EX4 qualification, and
does not complete M9.1b. No NAS/HDD/NAND or HTTP/product-startup operation occurs.
See the [component contract](src/phantowd-api/internal/backingpin/README.md).

## M9.1b existing backing metadata pins — local prerequisite evidence

The Linux-only internal pin borrows a qualified Root and retains parent/file
O_PATH references to one existing single-link regular file of exact expected
size. It never opens data for reading/writing or creates a missing file.
Re-resolved and retained mount/inode/size/mode/UID/GID/link identities must
agree; observed drift permanently quarantines without releasing the retained
references until explicit close. Handles/observations refuse JSON, including
Pin values; uncertain close remains explicit without retry. No raw FD escapes.

Windows DOM/API vet/unit and ARMv5 cross-compilation pass. Pinned Go1.26.6
whole Linux QEMU-tagged vet/race and focused package race count3 pass; native
positive syscall lifecycle tests explicitly skip on this host's kernel lacking
unique mount IDs, rather than using weaker identifiers. Synthetic mask/type/
size/overflow/mount/input/serialization checks run there. Actual ARMv5 Linux
6.18.54 covers those lifecycle cases through the real qualified disposable
ext Root: O_PATH data refusal, missing/symlink/special/size refusals, replacement,
unlink/truncate/mode/UID/GID/hardlink/parent drift and restoration quarantine,
concurrent verify/close, uncertain close, nested/leaf bind mounts, private RO
transition and Root loss. The required backing-pin assertion and old mount
guard pass; the existing clean two-boot state fixture also passes. Storage
contracts and smoke ShellCheck pass. This reuses seven verified baseline
artifacts and the unchanged volume probe; bounded tmpfs scratch is discarded.

This does not complete M9.1b. Writable descriptor acquisition/handoff/lifetime,
qualified product mounted rosters, access/allocation/global-use/session admission,
protected credentials and a product target adapter remain missing. Metadata
verification is point-in-time, not content/change-history or nonblocking-I/O
proof. No HTTP, product startup, NAS/HDD/NAND or persistent device operation.
See the [component contract](src/phantowd-api/internal/backingpin/README.md).

## M9.2b registered-volume and cross-protocol review — local component evidence

The private collector now binds desired file-LUN observations to protected
logical registry IDs and expected UUIDs inside the existing complete-census/
reader recheck bracket. iSCSI, volume-policy and registry revisions remain
separate. Missing, unknown, conflicting or cloned volumes cannot select actual
backing topology; unresolved physical evidence remains explicit. Per-BackingID
SMB/NFS path exposure counts include RO shares and remain advisory only.

Windows DOM/API vet/unit and ARMv5 cross-compilation pass. Pinned Go 1.26.6
whole Linux tagged vet/test/race and focused review/collector race count3 pass,
covering the 64-backing/multiple-target bound, distinct volume references,
ordering/owned results, path boundaries, alias/clone/missing/unknown/conflict,
incomplete whole evidence and registry/directory ABA/root/census/cancel refusal.
The actual standard ARMv5 smoke reconciles the existing synthetic MD array,
keeps an absent volume unselected, observes a known share exposure and returns
zero composite after registry restoration during final census checks. The new
assertion is mandatory in smoke and its static storage contract. Existing
two-boot state acceptance, workflow path tests and smoke ShellCheck also pass.

This uses a cache-reusing API overlay, the unchanged base volume probe and
seven checksum-verified base artifacts. No complete new firmware/SBOM, hosted
feature acceptance, secret/backing-file access, lease, global-use admission,
target mutation, HTTP, persistence or product/physical qualification follows.
All disposable rootfs/guest/cache scratch is bounded tmpfs and discarded; no
Docker image/volume is created. See the [component boundary](src/phantowd-api/README.md#m92b-registered-volume-and-cross-protocol-review)
and detailed M9.2b/M9.1b handoff in the roadmap.

## M9.1a actual LIO/initiator fixture — local research only

The separate pinned Linux ARM926 kernel and libiscsi 1.20.0 client now execute
real guest-loopback iSCSI: successful CHAP, exact wrong/missing/foreign refusal,
32 MiB/512-byte capacity, RW readback and RO write denial. A retained descriptor
continues reaching the original file after rename/replace/unlink; closed/missing
descriptors fail without recreating storage. A live session is observed,
forcibly disabled and absent afterward; its I/O and new login fail, re-enable
preserves data, and final target/listener/configfs teardown is checked.

The expanded actual ARMv5 guest also verifies reciprocal CHAP with exact wrong
inbound/target response/name refusal, inactive-session credential rotation with
old login refusal/new login and preserved data, and two simultaneous explicit
ACL peers with independent credentials and primary RW/secondary RO grants.
Cross-peer credentials fail; secondary logout leaves the primary observed and
reading unchanged data. Both logout before ACL teardown. The bounded consumer
now refuses unknown/contradictory readiness lines; five native RED/GREEN cases,
six result/profile test groups, mock wrapper/ShellCheck and actual cached-kernel
guest pass. No additional kernel profile or Docker image/volume is generated.

**Upstream backend limitation:** both pinned source and actual guest confirm that mutual
configfs credentials still permit one-way CHAP. Successful reciprocal exchange
is not required-mutual enforcement. Production admission for such a requirement
must wait for a separately reviewed enforcement solution or a distinct explicit
policy decision; the desired model is not silently weakened. Rotation tests
are neither durable/interrupted nor live-session, and simultaneous-peer evidence
is one LUN/pinned libiscsi client, not Windows or a product authority owner.

An opt-in, default-off research kernel patch now rejects missing initiator
challenges when outbound target credentials are configured. Fresh strict and
unchanged default profiles both pass actual ARM926 QEMU locally, including exact
strict authentication refusal, reciprocal exchange, rotation, independent RO/RW
peers, retained data and teardown. Seven profile/seven result groups, wrapper
refusals, ShellCheck and workflow path contracts pass. Strict mode always
requires a fresh disposable compile; it cannot use a default cached candidate.
The patch is outside product/standard kernel builds. This closes a synthetic
login-enforcement experiment, not independent security review, client-side
verification, transport confidentiality, session revocation or product admission.

Both fresh profiles also pass a second 8 MiB/4096-byte retained backing alongside
the existing 32 MiB/512-byte object. Actual primary LUN0/1 RW/RO and peer LUN0/3
RO/RW mappings have exact reported sets/capacities, distinct seeds, write/refusal
readback, peer-write visibility, exact ungranted-LUN SCSI refusal and complete
teardown. Multi-LUN clients are sequential; the prior single-LUN concurrent-peer
test remains. A reproduced fixture bug required ascending REPORT LUNS order;
LIO walks an ACL hlist. Native RED/GREEN of the same C matcher now checks the
exact unordered two-member set without accepting missing/duplicate/foreign LUNs.
Seven profile/eight result groups and the matcher gate pass before compilation;
host CI checks these contracts, not real target execution. Other client/multiple
target compatibility and production backing/allocation/use/session gates remain.

The source-defined local wrapper checks profile/result refusals and a real
paused-snapshot TMPDIR regression, compiles the pinned upstream client and boots
one bounded disposable guest. Virtual RNG initialization fixes the reproduced
CHAP timeout; no authentication bypass or fixed seed is used. The normal
QEMU/EX4 defconfigs and product init are unchanged. Pure host CI covers contracts,
not actual target execution. See the [research contract](support/ISCSI-LIO-RESEARCH.md).

**M9.3a research prerequisite:** an independent default-off idle-disable patch
uses the existing non-forcing fabric path and completes core RTPI/enabled
bookkeeping under the fabric access mutex. The first prototype omitted that
bookkeeping; actual RED/GREEN retains its core-state assertion. Fresh combined
strict-mutual/idle-guard ARM926 execution now proves active-session refusal with
fresh I/O on that same client, idle stop, exact released RTPI reuse, unavailable-
TPG refusal and explicit re-enable with preserved data. Invalid/repeated stop
refuses. All old auth/rotation/forced-revocation/two-peer/multi-LUN gates remain.
A fresh unpatched default guest passes with the idle attribute absent. Eight
profile/nine result groups and the mocked wrapper cover the four-way option
matrix, not four actual guest builds. This locally passed 2026-10-05 experiment
may interrupt pending logins even when stop refuses; other mutations, concurrent
configfs writers/shared portals and production recovery remain unqualified.

This is not a privileged product adapter, product-wide mutation-refusal owner,
protected credentials/registry/mount/global-use authority, durable iSCSI state,
UI activation, migration, hardware entropy/cooling qualification or installer.
No production NAS/disk/NAND operation occurs. M9.1 backend selection remains open.

## M9.2a desired iSCSI model — local component evidence

The internal `iscsipolicy` schema binds logical target/LUN/file-backing IDs to
the exact shared desired-volume revision, with explicit capacity/allocation,
per-peer grants and symbolic CHAP/mutual-CHAP references. Strict JSON requires
the valid zero LUN number explicitly and returns no partial policy on failure.
Windows DOM/API vet/unit and ARMv5 cross-compilation pass. Pinned Go 1.26.6
whole Linux tagged vet/race, focused package race count3, 2048 fixed malformed
inputs, workflow/storage contracts, actual standard ARMv5 smoke and existing
two-boot state fixture pass locally on frozen source. The unchanged base helper
is reused and all seven base artifacts remain checksum-verified.

This cache-reusing overlay adds no target/backing/secret access or persistent
Docker image/volume; its rootfs copy and caches are disposable RAM scratch.
That model does not execute iSCSI protocol/backend/session operations; the
separate synthetic fixture above does not add persistence, HTTP, product startup,
migration or physical qualification. Authentication/migration exceptions remain a pending policy decision;
the conservative development profile requires CHAP. See the
[component contract](src/phantowd-api/internal/iscsipolicy/README.md) and M9.

Latest desired-model integration: PR #86 exact `06eac24` passed its own host
and QEMU/DTB checks and guarded squash-merged as `ba78e1b`; expected, checked
and integrated whole tree `024847ef` agree. Only its proven integrated topic
refs were retired; the research fixture remains separate development work.

Historical code audit: **2026-10-04**, integrated `develop` baseline
`145c8bf1225a46ffe5d486f48a9ed9d80b716b8f` (PR #84).
PR #84 exact `d8eb97a` passed its own host and complete QEMU/DTB checks,
including guest fixtures and isolated CI volume cleanup. Guarded squash
integration preserves expected/checked/integrated tree `5fa11336`; the proven
integrated topic refs were retired. The locally qualified registry-recheck/
composition follow-up rebases with its complete source/API trees unchanged.
Its hosted acceptance is separate; none of these observations enables product
storage/services, persistent registration, compatibility or installation.

Historical PR #83 integration:
PR #83 exact `8564b15` passed its own host check and guarded squash-integrated
the host-only manifest fix with expected/checked/integrated tree `d85d18b5`.
No firmware rebuild or installation authority follows from that host change.

Historical PR #82 integration:
PR #82 exact `ec8e127` passed its own host and QEMU/DTB checks. Guarded
squash integration preserves expected/checked/integrated whole tree `e84a3759`;
its integrated topic refs were retired. This integrates the read-only protected
volume registry and exact desired-policy binding, not persistent registration,
mount/import, activation or hardware qualification.

Historical PR #81 integration:
PR #81 exact `07058ed` passed its own host and ARMv5/DTB checks, including
standard/two-boot fixtures and final isolated-volume cleanup. Guarded squash
merge `d362c16` preserves the expected/checked/integrated whole tree `4208c42e`;
its integrated local/remote topic refs were retired. The registry/policy batch
rebases onto that actual integration with qualified whole tree `889f8de0` and
API subtree `ab51dcd7` unchanged. Hosted qualification of this newer batch is
separate from PR81 success; no product/physical/install gate is completed.
Earlier audit paragraphs below retain their original verification scope. PR #79
passed its exact-head host/QEMU checks and merged the mounted-ext census and
desired-volume review. PR #80 (`cca8fc5`) separately optimizes system CMake;
its exact-head host/QEMU/B3 checks passed and it guarded squash-merged as
`78080eb`. Expected, checked and integrated whole trees equal `49f9c0bc`;
both topic refs were retired after inclusion/worktree/lease guards. The hosted
QEMU log confirms system CMake selection; total job time is48m22s, not a
guaranteed11-minute whole-job improvement. Variability and other costs remain.

The current M3.2h follow-up adds an internal explicit read-only freshness
recheck: validate previous complete evidence before root I/O, recollect the
entire declared scope and reject mount/storage/MD/root identity changes. Native
focused race tests and Windows preflight pass. Frozen source `616579f` then
passes whole pinned Linux tagged vet/race, three SIGKILL repetitions, bounded
network fuzz and workflow/storage contracts. The actual ARMv5 standard overlay
accepts the unchanged disposable MD census and rejects internally coherent stale
mount-ID and MD-UUID observations; clean two-boot state tests pass. Independent
hashes confirm five frozen runtime/test/support files and seven unchanged base
artifacts. No new persistent Docker image/volume/output is created. This is
cached overlay evidence, not clean firmware/SBOM, hosted feature or EX4
qualification. It retains no lease, does not monitor or persist identity, and
adds no HTTP, mount/import or service activation. Planning bands remain unchanged.

Follow-up `fe1e855` ordinarily unmounts/remounts only the existing fixed disposable
QEMU MD filesystem. Actual ARMv5 standard smoke verifies old-census refusal when
absent and after same-path/device/UUID return, changed unique mount ID, read-only
state and acceptance of a new complete census. Native/Windows/contracts pass.
The original full overlay was interrupted by development-engine shutdown.
After explicit restart approval, rebase `e22199b` retains the entire API subtree
`2aaf95cb` and all five qualified runtime/test/support blobs unchanged. Remaining
integrated contracts and actual ARMv5 standard/two-boot overlay then terminate
successfully on that frozen source. Five source hashes and seven unchanged base
hashes independently agree after completion. This is cumulative cached local
evidence, not a completed original run, hosted feature or clean/EX4 acceptance.

M3.2g was implemented separately from then-frozen PR81: strict internal registry
model, descriptor-anchored read-only reader and private complete-census resolver.
The approved scope has no writer/adoption, production state placement, HTTP,
mount/import or activation. Windows preflight, whole pinned Linux tagged vet/
race, repeated transaction SIGKILL/fuzz/contracts and actual ARMv5 standard/
two-boot overlay pass locally. Native tests cover the strict64KiB/16-volume
model, real file/directory permission/link/FIFO/metadata-race/locking/lifecycle
refusals and complete scoped aliases/clones/missing/unclaimed reconciliation.
The guest reads a fresh tmpfs registry, refuses unsafe mode/foreign ownership,
keeps a missing claim unusable and observes the actual disposable MD array.
No test container survives, no image/volume is added and seven base artifact
hashes remain unchanged. These are cached local component results, not clean
firmware/SBOM, hosted feature acceptance, adoption or physical qualification.
Product gates and planning estimates remain unchanged.

The M3.2g follow-up also privately reconciles atomic SMB/NFS desired policy with
protected registry observations: exact logical-ID/expected-UUID agreement,
separate revisions, explicit unknown/conflicting/missing/ambiguous states,
protocol reference counts and full-census validation even for empty policy.
Whole local Windows preflight, pinned Linux tagged vet/race/fuzz/contracts and
actual ARMv5 standard/two-boot overlay pass. The guest proves ID-not-inferred-
from-UUID, conflicting backing and split-policy refusal against its actual MD
and tmpfs registry. No second policy owner/scanner, writer, HTTP, planner-ready
token, mount/import or activation; clean/hosted/physical qualification remains
separate. No new Docker image/volume or surviving project test container.

M10.2b hardens the host signed-manifest boundary without a firmware rebuild.
A real signed root/artifact case-alias regression fails twice before the fixed
schema scanner refuses non-exact/missing/null/wrong-shape/encoding inputs.
Actual HTTP fixtures prove zero payload requests on malformed signed metadata.
Hash reads stop at signed size plus one detection byte and reject changed
opened size; no new install-time immutability guarantee is inferred. Complete
Windows host vet/unit and pinned Linux whole host vet/race pass. Manifest
schema, signing, trust roots, CLI and device authority are unchanged; target
installation, persistent rollback and recovery remain unimplemented.

The private registry backing follow-up classifies observed physical disk/
partition, MD device/partition/stack and other block-stack relationships, with
physical-leaf/array counts. It validates the entire census, does not select a
backing for missing/cloned claims and retains unresolved physical evidence.
Whole pinned tagged Linux vet/race, interruption/fuzz/contracts and actual
ARMv5 standard/two-boot overlay pass. The guest observes its existing two-leaf
MD fixture; no new disk/boot/image/volume is added. Schema1 is unchanged. This
remains a private point-in-time observation, not stronger durable backing
identity, RAID health, WD compatibility, global-use or activation authority.

Use [ROADMAP.md](ROADMAP.md) for the acceptance specification. This snapshot
includes a locally verified internal reader-bound registry recheck. Actual
rapid tmpfs restoration reproduces identical contents/full timestamps before
the retained mutation watcher fixes the gap; ten native race repetitions and
whole tagged API vet/race pass. The actual ARMv5 fixture refuses old snapshots
after permission/same-byte restoration and completes standard/two-boot tests.
Watch loss/overflow/bounded-drain uncertainty fails closed without retry.
No schema, writer, HTTP, storage lease or physical/service authority is added;
cached overlay, clean hosted integration and product qualification remain distinct.

The internal registry/census composition now validates combined desired policy
before collection, derives private policy/backing reviews from the same
protected registry and complete census, then rechecks both sources before
publication. Invalid/canceled/closed inputs or drift return one redacted error
and no partial result. Native tests cover same-byte restoration during either
census pass, directory ABA, changed roots/excluded/unclaimed scope and early
refusal. Whole Windows, pinned tagged Linux vet/race and actual ARMv5 standard/
two-boot overlay pass. The guest observes its existing two-leaf MD fixture and
refuses registry restoration during the second complete census. Source/base
hashes agree and no persistent Docker resource is added. This is sequential
read-only observation, not an atomic global snapshot, continued freshness,
retained lease, compatibility qualifier, planner input or activation authority.

This snapshot distinguishes tested components from deployed product workflows. It is not
installation approval, a security certification, or an exhaustive line-by-line audit.

PR #79 passed its own exact `a185e0f` host and QEMU/DTB checks, including
guest/state fixtures, research DTB and final isolated-volume cleanup, then
guarded squash-merged as `0731540`. Expected, checked and integrated complete
trees equal `117a6526`; its topic refs were retired after tree/worktree/ref
guards. This integrates the mounted-ext census and scoped desired-volume
review, not persistent VolumeIDs, production mount authority or EX4 migration.

PR #78 passed its own exact56171db QEMU/DTB check37140806223, including
standard guest/two-boot validation, research DTB and final isolated-volume
cleanup, then guarded squash-merged asd1b8dfe. Expected, checked and integrated
complete trees equalc3475d50. Policy-review and separate SIGKILL topic refs
were retired only after checked inclusion, identical original test/contract
and attached-worktree guards. This qualifies the policy-review/interruption
batch, not subsequent storage or a deployable appliance. Mounted-ext census/
desired-volume follow-ups rebase on the actual merge with their complete
qualified tree3c3810cc and API subtree7d0e5828 unchanged. Hosted acceptance of
that newer feature remains separate; all product/hardware gates stay open.

M3.2f follow-up privately reviews desired logical IDs/expected UUIDs against
the full scoped mounted-ext census. Same-device aliases group as one observed
object; cloned UUIDs on distinct devices remain ambiguous. Unclaimed objects,
not-observed-in-scope and unresolved disk evidence remain explicit. A native
regression reproduces circular validation accepting changes to derived UUID/
unique mount ID; corrected validation rebuilds from independently retained
original root observations and complete MD bindings. Whole Windows preflight,
pinned Linux tagged vet/race/fuzz/contracts and actual ARMv5 existing MD/standard/
two-boot overlay pass. Native tests cover16 desired volumes/64 roots, ordering,
aliases/clones, partial input and invalid policy. Six final runtime/test/support
hashes and seven base hashes independently agree after terminal completion.
No I/O, HTTP, persistent registration, qualifying token, Owner/planner authority,
mount/import or activation is added. These local proofs preceded exact-head
PR79 hosted integration above; they do not establish independent clean-build
or EX4 acceptance. Planning bands remain unchanged.

M3.2e local follow-up derives a private complete scoped mounted-ext census from
the current-process mount table and complete sysfs/MD topology. The fixed reader
repeats descriptor-relative UUID/device observations and brackets them with
full topology/mount-table rechecks. Private mountinfo ID/root retention detects
remount/subtree drift; statx unique IDs remain a distinct identity namespace.
Explicit exclusions and the64-root bound avoid claiming complete physical or
global discovery. Native refusals cover incomplete input, buffer reuse, identity
drift, cancellation and64/65 roots. Whole Windows preflight, pinned Linux tagged
API vet/race/fuzz/contracts and actual ARMv5 standard/two-boot overlay pass,
including the existing read-only MD filesystem and its two members. Independent
post-run checks confirm seven frozen source/support hashes and seven unchanged
base artifacts; the project builder was auto-removed and no new persistent
image/volume/output was created. No HTTP, block-node opening, file-data read,
state write, qualification, mount/import or product activation is added.
These local proofs preceded exact-head PR79 hosted integration above; they
do not establish independent clean-build or EX4 acceptance.
M3/overall planning bands remain unchanged; persistent identity, production
qualification/roster, global-use accounting and hardware gates remain open.

PR #77 passed its own exact `07d0ef7` ARMv5/DTB check, including isolated
volume cleanup, and merged as `df9b45b`. Expected, checked and integrated
whole trees equal `15787a19`. Its branch was retired after tree equality and
worktree checks. The redundant integration-triggered QEMU run is confirmed
cancelled, not failed. This qualifies only the panel request-lifecycle change,
not subsequent desired-review/advisory increments or a deployable product.

The desired-review follow-up also identifies specific cross-protocol folder
pairs in the loaded baseline/candidate. Complete counts with at most64
deterministic text-only details cover equal/nested paths on one VolumeID,
root folders and removed pairs; noncanonical path observations refuse review.
Independent SMB/NFS revocation and unresolved runtime aliases remain explicit.
Complete DOM and Windows API/vet/cross-compilation pass, including128x128
pair bounds and a32768-pair union with only64 retained detail records.
Frozen code `29d4d10` (whole tree `82f2eba9`, API subtree `7c0ed3c5`) then passes
the complete pinned Linux tagged API vet/race, three repeated SIGKILL campaigns,
fixed fuzz/contracts and actual ARMv5 standard/two-boot overlay. Seven original
base artifacts remain byte-identical; no new persistent build resource exists.
This is not actual-browser/heap, effective-access, new clean firmware/SBOM,
hosted or EX4 qualification; no product service activates.

M5.4a adds a bounded semantic before/after review to the existing development
SMB/NFS policy editor. It compares stable IDs/CIDRs, includes every NFS mapping/
security field, ignores order/revision-only differences and renders text into
semantic cells. More than512 changed entries or ambiguous rules refuse the
complete review and Save; form/auth invalidation clears it. No endpoint,
request, browser persistence, account provisioning, activation or filesystem
operation is added. The actual-source feature regression first fails with the
comparison absent, then complete DOM/Windows checks pass. Pinned Linux whole
tagged API vet/race, existing fixed fuzz/feedback checks and actual ARMv5 asset
integration plus clean two-boot overlay pass on unchanged kernel/packages/probe.
This is cached local evidence, not browser JS/visual/accessibility, clean new
firmware/SBOM, hosted feature, physical EX4 or effective-access qualification.
The original PR77 qualifies only its frozen panel-lifecycle head; it
cannot establish hosted acceptance for this subsequent change. Planning bands
remain unchanged; no installable firmware exists.

PR #76 passed its own exact `f247139` host check and merged as `bb9802e`.
Expected, checked and integrated whole trees equal `238dbd00`; its topic was
retired with exact ref/remote guards after switching to integrated `develop`.
This host-tool/Markdown-only increment correctly requires no firmware QEMU
build; it does not qualify a target installer or physical device. The duplicate
PR75 merge-triggered QEMU run is confirmed cancelled, not failed or restarted.

M1.4a adds a test-only native SIGKILL campaign for the combined policy store.
At seven actual write/sync/close/rename boundaries, the parent verifies the
writer's exclusive lock, kills it without graceful cleanup, confirms signal
termination and then verifies exact coherent nonempty SMB/NFS state, preserved
pending evidence, stale-writer rejection and a subsequent explicit commit.
All boundaries pass three Linux race-enabled repetitions; complete Linux
`-tags=qemu` API vet/race and Windows API/UI/vet/ARMv5 cross-compilation pass.
Linux files are disposable tmpfs regular files in one bounded non-root pinned
container at a time, automatically removed; no new image/volume/output exists.
Production code and firmware inputs are unchanged. This narrows the native
process-interruption evidence gap, not power-loss, real media/ENOSPC, product
state provisioning, ARMv5 execution or recovery qualification. Planning bands
remain unchanged. This increment is not covered by the integrated PR #77
panel check and has no hosted integration claim.

PR #75 passed exact `c51d452` host and QEMU/DTB checks, including final
isolated-volume cleanup, and merged as `9d2a0bc`. Expected, checked and integrated
complete trees equal `772ed059`. The combined address topic and original Samba
context topic were retired only after whole-tree inclusion, exact patch equality
and attached-worktree checks. This qualifies those component increments, not
product networking, a separate Samba Owner or the later panel lifecycle fix.

M10.2a host-only source `7257019` (complete tree `c5c3b119`, host module tree
`695bd7ed`) adds optional signed-minimum installer preflight to both release
inspectors. A too-old installer refuses before payload reads/downloads/staging;
equal/newer versions still require all existing payload verification. Signature,
target/channel and signed tag checks precede assessment. Invalid host-version
syntax fails before HTTP. Windows full host vet/unit and pinned Go 1.26.6 Linux
whole host-tool vet/race pass. Synthetic HTTP request counters and CLI fixtures
verify early refusal, omitted-option behavior and prerelease/version boundaries.
The tested module tree is unchanged across the independent rebase and subsequent
qualified PR #75 composition. No QEMU rebuild is needed for this host-only tool;
the version is caller-supplied, not device attestation or installation authority.
Target installer, trust-root provisioning, recovery and all release gates remain
open; M10/overall planning bands are unchanged.

PR #74 passed exact `02bdb0c` host and QEMU/DTB checks, including final
isolated-volume cleanup, and merged as `f19e6eb`. The entire expected,
checked and integrated trees equal `933fc32`. Its local/remote branch was
retired with exact-SHA guards and no linked-worktree changes. This qualifies
the nexthop component integration, not the Samba inherited-context or local
address-preflight increments below. Those increments were rebased onto the
actual merge with their complete tree and all three patches unchanged.

PR #73 passed exact `834ccce` host and QEMU/DTB checks, including final isolated
build-volume cleanup, and merged as `0bf3f91`. Its expected, checked and
integrated complete trees are identical. The route/rule topic refs were retired
with exact-SHA guards after complete inclusion and worktree checks. The nexthop
follow-up was rebased onto this actual merge with its complete source tree and
three patches unchanged (`319a331` becomes `37e766a`). Its complete local proof
below remains valid; PR #73 does not qualify that follow-up as hosted.

PR #72 passed exact `1dca772` host and QEMU/DTB checks and merged as `4371102`;
the expected, checked and integrated complete tree is identical. Its local and
remote topic was retired with exact-head guards and no linked-worktree changes.
This qualifies desired-network and link/address component integration, not the
separate configured-route/routing-rule increments below or product networking.

PR #70 passed exact head `1178820` host and QEMU checks and merged as
`dd49e4` with complete qualified/expected/integrated tree equality. Its topic
branch was retired with exact-SHA guards. PR #71 subsequently passed exact
`b64effe` host and [QEMU checks](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37112632559)
and merged as `dda8624`, with complete expected/qualified/integrated tree
equality. Its local/remote branch was retired with exact-SHA guards. This
qualifies retained-census component integration, not physical SMART or product
startup. The network increment below has separate local evidence.

PR #68 passed final head `0e22e01` host and
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37101813148)
checks and was squash-merged as `f9bbfc0`. Its complete expected merge tree
equals the checked head and integrated tree; its local/remote topic was retired
with exact-SHA guards after inclusion and worktree checks. The subsequent
census was rebased onto that baseline with its entire tree unchanged. This
qualifies synthetic fixed-capture integration, not the census's hosted checks,
physical SMART collection, authenticated runtime or product installation.

PR #65 passed exact-head `eeb14a7` host and
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37093392186)
checks and was squash-merged as `ea51f70`. Its complete expected squash tree
was independently checked. PR #66 was subsequently rebased onto that integrated
commit with its complete tree unchanged, passed final-head `fa6969a`
[host checks](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37096901139)
and merged as `d8707aa` with complete expected-tree equality. Both topic branches
were retired with exact-SHA guards after inclusion proof. The new SMART
coordinator below is not covered by those earlier CI results.

PR #67 subsequently passed final head `2aa933a` host and
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37098182141)
checks and was squash-merged as `8579e42`. Its entire expected merge tree equals
the checked head; the integrated topic was retired with exact-SHA guards.
This qualifies the coordinator/fake-backend integration, not the separate
fixed-capture increment below or physical SMART authority.

PR #60 integrated the retained static-code Owner after exact head `7c96f41`
passed hosted host, B3 and QEMU checks. The complete expected merge tree was
verified before removing its branch. PR #62 subsequently integrated the
root-lifetime, supervision and license-checker work after exact head `6ab66f4`
passed all three independent hosted checks, including
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37079287654).
Its expected complete squash tree was verified before removing that branch.
This is component integration, not product service or EX4 qualification.

PR #63 subsequently passed its exact head `97a5b09` host and QEMU/DTB checks
and was squash-merged with complete expected-tree equality. Its local/remote
branch was retired after inclusion proof; no unrelated worktree or stash was
removed. That result does not qualify the separate host-reader, source-collection
and ARM-header follow-ups documented below.

PR #64 subsequently passed exact-head `f7f9477` host, B3 and
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37088513201)
checks and was squash-merged as `dd1dd99`. Its complete merge tree equals the
checked head. The original transport/source topics have tree-identical rebased
ancestors in that checked head; all three integrated local/remote refs were
retired with exact-SHA guards. This does not qualify the separate ARM-attribute
observer or new atomic-dispatch fixture as hosted/product/EX4 results.

PR #59 integrated the C++ toolchain and native/ARMv5 producer replay after exact
head `e22828d` passed both hosted B3 and
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37062393358)
checks. Its complete merged tree equals the checked head and the merged branch
was removed. That earlier CI result alone does not qualify later Owner,
native-boundary, MCU or Perl followups; their evidence is recorded separately.
PR #58 previously integrated the code-ACL refusal correction and offline SMART
parser after exact head `2e8eb6d` passed all host/B3/QEMU checks. Neither merge
qualifies the EX4 product or physical SMART collection.

PR #57 previously integrated the read-only code-bundle inspector and QEMU-only fresh
stager after exact head `870ea9d` passed
[host](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37039612689) and
[QEMU/DTB](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37039612553)
checks. Its merged branch was removed after complete-tree equivalence was
verified. Its result alone did not qualify the later ACL and SMART increments;
their integration is now separately established by PR #58.

PR #55 integrated the native launcher, internal isolated runtime, host ELF
dependency candidate, actual ARMv5 loader differential and separate Samba-root
fixture. Its exact head `e9a7f34` passed hosted
[host](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37018283304),
[Stage B3 compile](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37018283205)
and [QEMU](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37018283374)
checks before squash merge. Planning bands remain unchanged: no new product
acceptance gate has closed.

A subsequent `feat/samba-charset-runtime` increment reproduces missing CP850
as a real ARMv5 `iconv_open` failure in the isolated root. Standard Buildroot
glibc options now install only IBM850 (13,496 bytes) and its minimal catalog
(214 bytes). Full local new-config integration passed on unchanged `b7e06b4`;
full combined integration passed on unchanged `41c90c9`, including exact
bidirectional bytes, four aliases, unsupported/malformed/truncated input
denials, Linux tests/race/fuzz, packages/legal/SBOM, standard/MD/two-boot guest
tests and the loader/Samba experiments. After PR #55 merged, the feature was
rebased to `bedfec4` with an identical complete source tree. The local runs
reuse source/compiler caches; they are not independent reproducibility or
hosted feature results. This enables neither SMB1 nor product service startup.

The same follow-up includes an ext4 default-ACL inheritance fixture:
Samba-created directory/file ACL bytes,
`2750`/`0640` modes, setgid owner/group, reader access and write/outsider denials.
Explicit DOS metadata settings avoid archive-to-Unix-execute mapping while one
archive flag remains visible through SMB. A dedicated fixed-command shell
contract accounts for smbclient's zero exit on denied mkdir without relaxing
generic denial checks. Focused and full combined local integration pass with
the actual installed converter, not a manually injected staging module. The
temporary inheritance worktree/branch and obsolete 13 GiB output were retired;
only the current output and bounded compiler cache remain. This is not a
product permission workflow, legacy metadata preservation or all policies.

The integrated Samba fixture adds one fixed dynamic
`streams_xattr` module, exact alternate-stream xattr bytes, and reader/kernel-RO
overwrite denials. It now also uses a disposable 16 MiB ext4 image to verify
exact POSIX ACL bytes, named-reader access, write/outsider denials and mask-based
revocation. The formerly disabled ext4 ACL option reproduced `EOPNOTSUPP`;
the corrected kernel and full working-tree incremental integration passed.
Fixed kernel-fragment fingerprinting refreshes only Linux and audits the
result before recording a compiler checkpoint. The original base rootfs remains
unchanged. This result is separate from the earlier complete integration
on `fba213d`; it does not qualify Windows ACLs, complete filesystem ACLs, stream
migration, product integration or physical EX4 behavior.

PR #56 subsequently passed exact-head `7f108d2` hosted
[host](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37028964742) and
[QEMU](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37028965197)
checks and was squash-merged as the current baseline. Its merged branch was
removed. QEMU-only experiment paths no longer trigger an unchanged EX4 kernel
rebuild; actual board/build input changes remain covered.

## Roadmap comparison

M5.5a local correction on `fab3b7e` (complete tree `60e04f9`) closes a
deterministically reproduced browser-state race: the existing snapshot could
render retired diagnostic values after a completed logout. The four reads now
share one single-flight generation/controller and a finite 10-second deadline
through body decoding. Authentication boundaries abort/clear that generation;
late successful/error/auth-body responses and finalizers cannot alter a newer
session. Eleven actual-source DOM cases across five groups pass, including
logout/global logout/password change, auth failure, timed-out body, duplicate
reads and a newer pending snapshot. The complete UI suite passes repeatedly;
its success marker now follows every test, not just an earlier subset.
Windows API/UI/vet/tagged/cross-compilation, pinned Linux whole API tagged
vet/race and existing feedback/fuzz contracts pass. Actual ARMv5 standard smoke
and clean two-boot overlay pass with the current embedded assets; seven base
hashes independently remain unchanged. These fixtures do not run JavaScript
in a real browser and do not qualify accessibility, target installation or
product authentication. No HTTP authorization, endpoint, privileged operation
or storage behavior changes. One existing image/output and bounded disposable
RAM scratch reused; no second heavy PR. M5/overall planning bands unchanged.
The correction rebases as `b8e8814` onto qualified PR #76 with both original
patches unchanged, API subtree `2871d3b1` and the same dashboard test blob.
The complete expected composition uses the proven tree-equivalent original
PR75 head as its explicit squash base; actual rebased tree equals `2bffe030`.
Repeated current-source Windows API/UI/vet/tagged tests and ARMv5 test
cross-compilation pass. This is not a new QEMU execution or real-browser proof.

M6.1f local follow-up on code `68fae6b`, tree-identically rebased as `8bf993d`
(complete tree `3055351`), joins a validated desired policy to the existing
immutable inventory through two internal transient interface bindings. Private
overlapping counts report exact/missing static prefixes, same-address/peer use
and subnet overlaps across the full local inventory, blocked link/address flags,
scoped locally assigned gateways, unresolved dynamic families and disabled
unbound slots. Unsupported bindings and invalid/canceled inputs return zero
output; there is no ready/eligible/apply result, I/O, HTTP or new privilege.
Windows API/UI/vet/tagged tests and ARMv5 cross-compilation pass. Pinned Linux
whole API tagged vet/race, fixed 2,000-case mutation/order tests, existing bounded
wire/route/object fuzz campaigns, 7 kernel/21 feedback tests and real workflow
contracts pass. Actual ARMv5 standard smoke requires the generated positive/
negative address fixture as well as separate real kernel collection; clean
two-boot checks pass. All seven base hashes independently remain unchanged.
One existing image/output and read-only workspace are reused, with bounded
auto-removed RAM scratch. This is cached overlay evidence, not a new full
image/SBOM, hosted topic or physical qualification. Local absence of conflict
does not prove address ownership, external availability, lifetimes, DAD or
routing/DNS reachability. Factory binding, freshness and safe application remain
open; M6 and overall estimate bands are unchanged.

Fixture-only Samba inherited-context increment on `bd9ae3f` deliberately passes
original-root/ungranted-file descriptors and blocked/ignored signals through
the existing guarded standalone launcher. Direct pre-exec checks require
descriptor closure, a completely empty mask and default altered dispositions;
live Samba checks add zero inheritable/ambient capabilities. A separate native
executable includes the actual checker, never its privileged bootstrap, and
refuses eight individual leak/signal cases before explicit test-local recovery.
Fourteen Linux fixture tests, seven loader contracts, linters/ARM compilation
and actual ARMv5 distinct-user/streams/ext4 ACL/inheritance/group-stop campaign
pass. The verifier first rejected the older guest solely for missing new
evidence. All seven base hashes are independently unchanged afterward. Existing
image/packages/kernel remain untouched; the local container is UID1000,
cap-drop ALL/NNP with bounded CPU/RAM/PIDs and disposable RAM scratch. No new
full-image/SBOM, hosted topic or product qualification. Separate privileged Samba
Owner development is now approved only for host/disposable QEMU. Its owned-group
prerequisite is described above; the complete retained-input Owner, product
helper/HTTP privileges and physical qualification remain unimplemented. Bands unchanged.

M6.1e local follow-up on code `319a331` / tree `333e81d` adds one fixed strict
AF_UNSPEC nexthop-object dump per matching sample, complete even when empty.
It observes unreferenced objects, correlates route/group IDs and local OIF,
checks bounded ordered groups/effective 16-bit weights and refuses incomplete
rosters. Resilient buckets, FDB and encapsulation are not evaluated; complex
objects and referenced routes remain unresolved. IDs stay private; summary is
counts only. A real parser RED/GREEN corrects inline ECMP sorting that hid
member-order drift; pinned no-flag LWT framing has a separate regression.
Windows API/UI/vet/ARMv5 cross-compilation, pinned Linux whole API tagged
vet/race, actual UID1000/zero-capability capture/recheck/FD census, 5,000 mutations,
25,000-execution object/route fuzz, real workflow and 7 kernel/21 feedback tests
pass. Actual ARMv5 kernel observation plus nonempty generated weighted-group
assertions and clean two-boot overlay pass; seven base hashes verify and the
base remains unchanged. A subsequent complete cached integration on unchanged
`cec1527` (tree `61a8391`, five Markdown-only changes from `319a331`) also passes
whole native/vet/race/fixed-fuzz, package/rootfs/legal-info/SBOM, regular-image
probe and all standard/MD/two-boot/launcher/Owner/loader/atomic/Samba/SMART guest
lanes. Independent post-run checks verify all seven exported hashes, resolved
policy-routing kernel options and exact exported/image/target API bytes. One
existing output and two fixed volumes are reused; temporary containers removed.
That cached local integration did not itself demonstrate independent clean
reproduction, hosted topic or physical qualification. Subsequently PR #74
passed its own exact `02bdb0c` host/QEMU checks and merged as `f19e6eb` with
complete expected/checked/integrated tree equality, qualifying component
integration only. No live nonempty kernel-group campaign, evaluator, network
application, new privilege, HTTP or product startup. Planning bands unchanged.

M6.1d adds two fixed strict IPv4/IPv6 routing-rule dumps to the existing private
collector. A generic request first reproduced an extra family128; a failing
request-shape regression now requires the actual IP family in the packet and
response-family checks. No silent skipping or arbitrary caller selectors.
Rule order within a family and duplicate multiplicity are preserved, including
equal priorities; only cross-family order is normalized. Source/destination,
table/priority/action/flags, interface references and bounded attribute/range
shape are checked. Detached, complex or unknown semantics remain explicitly
unresolved; summary exposes counts only. Final native package vet/race, actual
UID1000/zero-capability capture/recheck/FD counts, 5,000 rule mutations, a bounded
1,000-execution rule fuzz campaign, 7 kernel-input and 20 feedback contracts,
lint/ShellCheck and Windows preflight/ARMv5 cross-compilation pass. The QEMU
kernel did not have FIB_RULES: the existing networked-storage fragment now
requests IPv4/IPv6 multiple tables, with resolved-kernel audit and normal
fingerprint-triggered Linux refresh in the SAME workspace. Complete cached
Buildroot/ARMv5 integration passed on unchanged `e0986fc` (tree `f86d6e3`):
Linux host/vet/race/fixed-fuzz, actual refreshed kernel, package/legal-info/SBOM,
native regular-image probe and all standard/MD/two-boot/launcher/Owner/loader/
atomic/Samba/SMART guest lanes. The resolved kernel independently has IPv4/IPv6
multiple tables and FIB_RULES; the mandatory actual guest rule assertion passes.
All seven exported hashes were independently checked, and image/export/target
API bytes agree. One existing output and two fixed volumes were reused; temporary
containers were removed. This is cached local integration, not hosted topic or
independent clean-build/EX4 qualification. No routing evaluation, application,
HTTP, product startup or EX4 authority. Planning bands unchanged.

The first PR #73 host check exposed a stale workflow-contract count: 17 was
still expected after four legitimate network fuzz campaigns made the roster 21.
The real contract reproduced locally; the corrected exact count, one-copy
network campaign assertions and early full-builder invocation pass with 21
feedback tests. The read-only Git mode check uses only a command-scoped safe
directory for its fixed repository, not a global trust/configuration change.
This preflight-only follow-up changes no firmware inputs or guest behavior;
the preceding full-tested runtime remains unchanged. New exact-head hosted
checks remain necessary; the original host failure is not a firmware failure.

M6.1c local follow-up extends the same private namespace/socket collector to
configured IPv4/IPv6 FIB routes in all returned tables. Checked prefixes,
scalars, table overrides, gateway/via, preferred source, interface references
and bounded ECMP members are retained privately; canonical comparison
normalizes attribute order. M6.1e above supersedes the earlier member-order
sorting assumption and qualifies the correction locally. Unknown attributes, nested metrics and
unread nexthop objects remain explicitly unresolved. Cache usage/expiry does
not establish configuration drift or freshness; reported cache error is retained.
Native failure reproduced the strict IPv6 FILTERED response. Pinned kernel
source and a failing regression distinguish its deliberate cached-exception
exclusion from undeclared selection: only that fixed configured-route scope
accepts FILTERED, never DUMP_INTR or link/address filters. Final native race and
actual unprivileged capture/recheck/FD counts pass. Windows full preflight/ARMv5
cross-compilation, pinned whole API tagged vet/race, 5,000 additional generated
route mutations, bounded 1,000-execution wire and route fuzz campaigns,
20 runner contracts, mandatory actual ARMv5 route assertion and clean two-boot
overlay pass locally. Base artifacts' seven hashes pass; kernel/packages/probe
are reused, not a new full Buildroot release/SBOM/clean reproduction. No rule/
nexthop-object resolution, route choice, reachability, application, HTTP,
product startup or physical qualification. M6/overall estimate bands unchanged.

The earlier M6.1b follow-up adds a private Linux kernel interface/address observation.
A thread-bound namespace pin and one unprivileged route socket issue only fixed
link/address dumps. Kernel sender, port/sequence, completion status, interruption,
filtering, truncation and byte/object budgets are checked without dump retry.
Two normalized sets must match in the same namespace; names, current MACs,
addresses, state flags/scope and point-to-point peers remain private. JSON and
copied/forged results are refused; public summary is counts only. Recheck is
point-in-time comparison, not a generation lease or sticky Owner recovery.
Final Windows preflight/cross-compile, pinned Linux whole API vet/race,
5,000 generated wire mutations, 1,000 fuzz executions, 20 feedback contracts
and actual same-boot ARMv5 plus clean two-boot overlay pass. Additional native
IPv6/full-flag/scalar tests pass on unchanged guest runtime (87.9% Linux package
statement coverage). Actual native collection/recheck succeeds as UID1000 with
all capabilities removed, with stable descriptor counts after repeated calls.
The standard guest self-test runs as root; its collector pass is not non-root
ARM privilege qualification. No product collector startup, HTTP, interface
binding, DAD/conflict admission, routes or network change is authorized.
Cached overlays are not regenerated release artifacts or a clean full build.
M6/overall planning bands remain unchanged.

M6.1a local follow-up implements an internal schema-1 desired network model:
exactly two logical slots, IPv4 DHCP/static/disabled and IPv6 auto/static/disabled,
static aliases, default priorities, non-default routes, hostname, manual/automatic
DNS and search domains. It reuses bounded strict JSON; errors are constant and
failed decode returns no partial policy. Cross-slot static overlap, duplicate
addresses, incoherent gateways and route ties are refused without normalization.
Windows API/UI/vet/tests and ARMv5 cross-compile pass (network package statement
coverage 98.7%). Pinned Linux Go 1.26.6 tagged vet and complete API race tests,
3,000 fixed mutation cases, a 1,000-execution fuzz campaign, 19 build-feedback
contracts, workflow contracts and actual ARMv5 smoke/clean two-boot overlay pass.
The required guest marker is in the existing boot, not a new stage. Logical
slots are not qualified hardware identities; no network application, ownership,
persistence, runtime conflict check or HTTP workflow exists. Original base
kernel/packages are reused; this is not a new full image, clean build or EX4
qualification. M6 and overall estimate bands remain unchanged.

M8.5b local follow-up: a private Linux complete-census witness set requires one
already-open read-only block source per whole leaf and retains independent
generation-checked descriptors all-or-error. Whole-inventory observations
surround descriptor checks; any uncertainty keeps permanent review and pins
until explicit release. Native race tests and actual ARMv5 standard smoke plus
two-boot overlay pass, including all seven virtual leaves, partial rollback,
caller-close independence and injected-reader failure. A native regression
first reproduced the QEMU wrapper's missing `ReadLinkFS.Lstat`; the corrected
reader preserves the full contract, with a compile-time assertion. No collector
guard was relaxed. A subsequent complete cached local integration passed on
frozen `35ae558` (tree `b6decde`): host vet/unit/race/fuzz, package/image,
legal-info/source collection/SBOM, native image probe and all standard/MD/
two-boot/launcher/Owner/loader/atomic/Samba/SMART guest lanes. Independent
checks verify all seven exported hashes and byte equality of image, exported
and target API, including the mandatory seven-leaf assertion. Five manifest
entries, including kernel/DTB, are unchanged from the previous base; API/rootfs
are new. This is cached integration, not independent clean reproduction,
hosted qualification, physical SMART authority or a product provider.
No new privilege is authorized; the historical state EBUSY remains unresolved.
Milestone estimate bands remain unchanged.

M0 fixture reliability follow-up: the two-boot Samba shutdown previously
accepted direct-parent exit while a same-group adopted child could retain a
directory descriptor. A deterministic native subprocess regression failed
before the correction. The fixture now requires parent reaping and whole-group
absence with bounded TERM/KILL phases; forced termination remains a failure.
Cooperative late child closure, forced child termination and invalid ownership
are tested. Windows preflight/UI/vet/ARMv5 cross-compilation, pinned Linux
QEMU-tagged vet/main+SMART-device race, 17 runner contracts and the actual ARMv5
standard smoke plus two-boot overlay pass. No unmount retry/delay, generic Owner
change, product privileges or physical operation is added. This is not proof
of historical state `EBUSY` causality; the original full failure remains evidence.
The census prerequisite PR #69 passed its exact-head host/QEMU checks on
`b4ed92d` and merged as `3594234`; integrated/head trees match and the topic
branch was retired. The complete cached local integration subsequently passed
on frozen `28b16f4` (tree `327f671`): source/signature preflights, complete
API/toolkit vet/unit/race/fuzz, package/image/legal-info/source collection/SBOM,
native regular-image probe, standard ARMv5 smoke, MD v1.0, two-boot state,
launcher, retained static Owner/supervision, loader differential, atomic
dispatch, restricted-root Samba and SMART parser/producer/capture fixtures.
Independent exported hashes match all seven manifest files; five are unchanged
from the census baseline, API/rootfs are new. Image-extracted, exported and
target API bytes agree and include both witness and group-settlement code.
This is cached local qualification, not independent clean reproduction,
hosted topic success, physical support or historical `EBUSY` causality.
Milestone estimate bands remain unchanged.

A separate M8.5b prerequisite adds the Linux-only internal `smartdevice.Witness`.
It duplicates an already-open O_RDONLY block descriptor under SyscallConn,
checks CLOEXEC/type/access/major/minor and BLKGETDISKSEQ and revalidates that
same retained FD. A failed observation keeps review permanently; copied/busy
handles are refused and only explicit Close releases the duplicate. Windows
API/UI/vet and ARMv5 cross-compilation pass. Pinned Linux Go 1.26.6 tagged
vet/main+package race, 17 runner contracts and actual existing ARMv5 smoke pass
after final cleanup changes. Native refusal preserves caller flags/offset and
leaks no duplicate across 128 attempts. Existing active disposable MD members
prove real kernel generation checks, stale tuple refusal, caller-close survival,
sticky review and explicit release; expected-tuple drift is simulated, not
physical replacement. The manifest-verified base/helper remain unchanged; no
new image/volume or boot stage. These initial checks used a smoke-only cached
overlay; the subsequent full local result above supersedes their integration
status, not the remaining hosted or physical gates. No contents, SMART transport command,
SourceAdmitted, report attribution, descriptor-to-child handoff, HTTP or product
startup is added. Hosted/physical integration remains unqualified; planning bands unchanged.
The original complete cached run on `12f54d2` passed native/race/fuzz,
build/legal-info/probe, standard guest smoke and MD v1.0, then failed ordinary
state-volume unmount with the historical intermittent `EBUSY`. No retry or
lazy/forced unmount was added; later export and guest lanes were not reached.
The preserved diagnostic has no owner-tree FD/path references, but excludes
reparented processes and mappings, so it does not establish the cause. Separate
declared ten-pair state-only campaigns pass on both the older exported census
image and the actual cached witness image, with target/image API equality
verified for the latter. These non-reproductions are not a fix or full-pass
substitute. At that failed run, exported artifacts still described the older
image because export follows state-reboot success. The later complete `28b16f4`
pass exports the new hash-verified image; it does not erase the original failure.

An additional M8.5b prerequisite provides a private complete sysfs census for
future health-source binding. It uses the existing bounded collector and
complete schema-v2 validator, not the import/mount candidate filter. Mounted
whole disks, active MD members, removable/read-only state and missing/invalid/
ambiguous VPD remain observed. Comparison validates both derived views and
the entire inventory, including private evidence and unrelated topology.
Windows API/UI/vet and ARMv5 cross-compilation pass; pinned Linux Go 1.26.6
QEMU-tagged vet/race and 16 feedback contracts pass. The actual existing ARMv5
single-boot overlay also passes mandatory mounted-root and active-MD-member
assertions with the original base unchanged. It reuses the unchanged metadata
helper and skips the separate two-boot fixture. Subsequently, the complete
cached local lane passed on unchanged published `c3f017a` (tree `082be769`):
all host/race/fuzz, image/packages/legal-info/SBOM, native probe and existing
standard/MD/two-boot/launcher/retained-Owner/loader/atomic/Samba/SMART guest lanes.
Independent hashes find five exported artifacts unchanged from the capture
baseline, while the API and rootfs have new hashes. A separate API-only rebuild
with the pinned builder and target stripping matches the target, export and
image-contained API byte-for-byte. This is not independent full clean-build or
hosted topic qualification, source admission, report-to-device binding, SMART
transport/ioctl authority or product integration. Existing two volumes, one
14 GiB output and 971 MiB compiler cache were reused; test containers removed.
No HTTP, broker/device rules, privilege profile or normal startup is changed.
Milestone estimates remain unchanged.

A subsequent M8.5b prerequisite adds `processowner.NewCapture` for one retained
fixed command and one bounded regular read-only stdin, never a device. Complete
Windows API/UI and pinned Linux process-owner/coordinator vet/race pass. Native
negative tests cover separate stream bounds, signals vs genuine ordinary exits,
input drift, forced cleanup, copied handles and persistent release uncertainty.
The existing actual ARM926 generic-producer boot now also passes seven real
capture/coordinator projections and a fake source-change/refusal case. Both
success markers and unchanged original-base hash are required. Adding the second
test binary first reproduced image-space exhaustion hidden by debugfs's zero
exit; exact injected-byte comparison now fails before boot, and debug-free test
binaries pass within the unchanged 80 MiB copy. The complete cached local lane
then passed on frozen `6bd3995` (tree `883d9d1f`), including all host/race/fuzz,
image/legal-info/SBOM, native probe and standard/MD/two-boot/launcher/Owner/loader/
atomic/Samba/SMART guest tests. The rebase to `6c25cec` preserves that entire tree.
Independent hashes find five artifacts unchanged, while the API and rootfs have
new hashes. A separate API rebuild with Buildroot's target stripping matches the
exported API, target file and image-contained API byte-for-byte. Only the existing
two volumes, one 14 GiB output and 971 MiB cache remain. This is cached local
integration, not hosted topic or independent full clean-build qualification,
authenticated runtime/device provenance,
an isolated physical SMART collector, standby or product activation. All milestone
bands and the first-release scope remain unchanged.

The first fixed-capture PR selection exposed missing producer-fixture path
coverage: it selected unchanged EX4 B3 and omitted the fast host workflow.
A path regression now requires those files to select host/QEMU and exclude B3;
host adds POSIX syntax checks, while actual ARM execution remains in QEMU.
The correction changes only CI/contracts/status, not the full-tested command,
coordinator, guest runner, firmware input or product authority.

The M8.5b internal generation-bound coordinator now passes the complete Windows
API/UI preflight (Go 1.27.0), pinned Linux Go 1.26.6 vet/race checks and a
25,000-execution publication fuzz campaign. Fake-backend state-machine tests
cover source replacement/incompleteness, process signals and uncertain cleanup,
cancellation, output limits, non-queued concurrency, private evidence and copied
handle refusal. The existing diskless ARM926 parser fixture now runs both
binaries in one boot and requires separate success markers; focused guest tests
pass with the manifest-verified original rootfs unchanged. Runner contract tests
prove missing-marker refusal, one fake boot and scratch cleanup separately;
these mock tools are not guest execution. The focused wrapper uses the existing
image/workspace read-only, a non-root zero-capability container and disposable
bounded RAM scratch. Focused evidence alone is not physical SMART provenance,
an implemented command/device provider, a full image or hosted qualification. M8 and
overall bands remain unchanged; no product service, metadata-broker privilege,
HTTP endpoint, history or device operation is added.

The unchanged published `e960454` subsequently passed the actual complete
`build-qemu.ps1 -CachedOnly` lane: source verification, all Linux host/race/fuzz,
package/image/legal-info/SBOM, native probe and all standard/MD/two-boot/launcher/
retained-Owner/loader/atomic/Samba/SMART guest fixtures. Seven exported artifacts
were independently rehashed against the preceding known baseline and all match;
the target library and collected Buildroot archive also retain pinned hashes.
Only the existing two volumes, one 14 GiB output and approximately 971 MiB compiler
cache remain; the temporary container is removed. This is cached local full
integration, not independent clean-build, hosted topic or physical qualification.
The subsequent CI-only follow-up selects host/QEMU rather than unchanged B3 for
SMART fixture paths and adds command-boundary/default-path tests; it does not
change the coordinator, guest runner, firmware inputs or product authority.

The combined ARM-attribute observer and actual libatomic dispatch fixture passed
complete cached local integration on unchanged `ea87772` (tree `e899614c`):
source verification, Linux vet/unit/race/fuzz, image/legal-info/SBOM, native
storage probe and all standard/MD/two-boot/launcher/retained-Owner/loader/atomic/
Samba/SMART guest lanes. Seven exported artifact hashes were independently
verified and match the preceding full baseline. The actual library and collected
Buildroot source archive also retain their pinned hashes. This run used the
existing image, two fixed volumes and one output, with bounded disposable RAM
caches and scratch. A cold full API race differential reproduced insufficient
256 MiB temporary space and passed with 2048 MiB; the complete lane then passed
with that allocation without weakening tests. This is not a new hosted result,
independent clean build, full ISA/ABI qualification, physical EX4 qualification
or product activation. The product gates and estimate bands remain unchanged.

A subsequent disposable ARM926 fixture calls the actual image's libatomic
through 36 versioned dynamic resolutions after UID/GID 1000, zero-capability
and no-new-privileges checks. Four widths each pass 50 semantic scenarios,
including upper-64-bit CAS mismatches and wraparound, plus 4,000 two-thread
increments on the single-CPU guest; neighbouring cells remain unchanged.
The readelf IFUNC roster and resolved offsets agree on non-resolver targets,
the kernel reports helper version 5, and a missing-symbol control is refused.
Exact target/image library hashes and unchanged original rootfs are checked.
This is focused local fixture evidence, not every dispatch implementation,
complete ARMv5/ABI or memory-model qualification, a new full image/hosted run,
physical EX4 qualification or service activation. No milestone band changes.

A separate host-only increment observes bounded explicit aeabi file-scope
attributes, preserving integer zeros and exact NTBS bytes, with absent/
unobserved/invalid/unsupported states and no partial roster after refusal.
Windows unit/vet checks pass. Pinned Linux unit/vet/race and a 50,000-execution
parser fuzz campaign pass; the optional real GNU target-readelf oracle agrees
on 1,444 CPU/ISA values across 361 attributed objects and the Go API's absence.
The final version/text-budget refinements pass the same oracle/race/fuzz checks;
this is not new full image/QEMU or hosted qualification. libatomic's v7/Thumb-2
declaration and IFUNC alternatives demonstrate why these observations are not
a complete CPU gate or evidence of a broken library. RuntimeClosure remains
dependency/header-only and never authorizes execution. No package, privileged
profile, HTTP or product startup changes; milestone bands remain unchanged.

The combined host-reader, original-source collection and ARM-header increments
passed complete cached local integration on unchanged `21f2f9b` (tree
`f27f4ef6`): source verification, Linux host/vet/race/fuzz, image/legal-info/SBOM,
native storage probe and all standard/MD/two-boot/launcher/retained-Owner/loader/
Samba/SMART guest lanes. Seven exported artifact hashes were independently
checked and match the preceding full baseline. The separately collected
Buildroot archive also matches its pinned digest; upstream legal-info warnings
are deliberately unchanged. This qualifies local integration of these increments,
not an independent clean build, hosted feature result, complete corresponding-
source bundle, dynamic service activation or physical EX4 installation.
The helper experiments remain disposable and the product gates/bands below
are unchanged. Existing image, two fixed volumes and one output/cache were reused.

A host-only M4.4 runtime prerequisite now records exact processor-specific ELF
header flags and requires observed EABI5/base procedure calls without BE-8 code
for every object in the bounded ARM dependency candidate. Missing headers,
hard-float or contradictory flags and unsupported EABI versions return no
partial candidate. Windows and pinned Linux host checks pass; independent
GNU readelf comparisons agree across 381 observations in the five actual target
entry/module/converter graphs. Header acceptance is not full ARMv5 instruction,
symbol or ABI qualification, a signed manifest or service activation. No firmware
package/startup/privilege profile changes; planning bands remain unchanged.

A separate M11.4 source-collection increment retains the pinned original
Buildroot archive alongside upstream `legal-info` without clearing its warnings.
Linux ShellCheck/flake8, generated-file refusal/idempotence/cleanup tests and
the build-order contracts pass. The exact legal-info/collector command block
also passed against the existing real Buildroot output with networking disabled;
kernel, rootfs and API hashes were unchanged. This was a scoped cached
source-collection test, not a full image/QEMU rerun or independent clean build.
Complete corresponding-source review, release publication and hardware gates
remain open; M11 and overall estimate bands are unchanged.

A separate host-only release-reader follow-up corrects rejection of GitHub's
signed CDN query strings and redacts those URLs from transport-error messages.
A public-asset header-only observation confirmed the HTTPS redirect/query
shape; no external payload was downloaded or treated as PhantoWD evidence.
Real local HTTP/TLS tests prove the old rejection and error-query disclosure,
then verify successful Ed25519/SHA-256 inspection, invalid-signature/no-payload,
same-size tampering refusal, exact API URL checks, cancellation/caller-policy
retention and staging cleanup. Windows toolkit vet/tests and pinned Linux
Go 1.26.6 vet/unit/race plus four existing 100,000-execution fuzz lanes pass.
The host-only delta changes neither firmware packages nor product startup;
hosted follow-up integration is pending. No new QEMU/EX4 or installer
qualification is inferred, and M10/the overall estimate bands are unchanged.

The native static-child launcher now verifies that stdout and stderr are
writable anonymous `pipefs` pipe ends. Actual ARMv5 tests first reproduced
acceptance of a named stdout FIFO and then a read-only stdout pipe; the fixes
pass eleven refusal cases and existing positive Owner/handoff checks. Both
stderr variants are covered, and a high inherited original-root FD is verified
closed before execution. This is focused development-helper evidence, not
complete integration, a legacy WD finding or product activation. Its local
runner has explicit CPU/memory/PID caps and no new persistent Docker resources.

Complete cached local integration subsequently passed on unchanged `febc799`
(tree `eadb2f3e`): source verification, Linux host/vet/race/fuzz, image/legal-info,
native probe and every standard/MD/two-boot/launcher/Owner/loader/Samba/SMART
guest lane. The eleven launcher refusals and inherited high-FD check are
actually executed in the disposable ARMv5 guest. Seven exported artifacts were
independently verified; only `buildroot-show-info.json` differs from the prior
full result, now recording the probe's license-hash file. The uninstalled
launcher is tested by fixture injection, so unchanged product binaries are
not service-activation evidence. The temporary container auto-removed; one
existing output and the two fixed volumes/caches were reused. This is not an
independent clean build, hosted result, physical qualification or installable
release. The Buildroot source-packaging warning remains open.

The subsequent workflow-only correction excludes the probe license-checker
test from unchanged EX4 B3 kernel compilation, while requiring its QEMU
coverage for both push and PR. The path contract first failed on the missing
exclusion; its validation is separate from the full runtime result above.

An explicit blocking supervisor now extends the internal static/non-root code
Owner only. Complete scans are serialized with a fixed idle interval and no
catch-up burst. Actual disposable ARMv5 fixtures cover rejected admission,
concurrent close refusal, accepted cancellation/stop, live code drift, unexpected
exit and forced-stop review. Code pins remain until explicit close and review
never permits automatic restart. Complete cached local integration on unchanged
`8e3ce63` subsequently passed source verification, host/vet/race/fuzz,
image/legal-info/SBOM and every existing/new guest lane, including supervision,
actual Samba permissions and the seven-case ARMv5 SMART producer. Seven exported
artifact hashes independently match the preceding image: the internal
supervisor is tested by a separately compiled disposable probe, not product
startup. A stale runner-marker contract failed before compilation and was
corrected; the focused wrapper now checks that contract first. Hosted and clean
qualification remain separate. The separate Samba fixture measures its
existing positive scan with bounded redacted evidence; emulation timing is not
physical EX4 qualification or a production polling recommendation.

The storage probe's previously missing license hash is now supplied and tested
through pinned Buildroot's real checker: the repository license verifies, and
an altered temporary copy is refused. Its actual scoped `legal-info` target
also passes, without rebuilding an image. This metadata/test-only follow-up
does not imply a full build of the newer head or close source-distribution and
complete licensing review. Earlier full-run license warnings remain historical.

A separate follow-up fixes a reproduced `NewIsolated` constructor lifetime
defect: direct `Fd()` duplication accepted a caller root after Close had begun
while an active Control kept its kernel FD alive. The constructor now duplicates
through `SyscallConn.Control`, preserving `os.File` lifetime across the syscall.
Deterministic root-host RED/GREEN, ten race repetitions, non-root Linux API/vet
and package race checks, Windows API/UI/cross-compile and the actual ARMv5
isolated-launcher fixture pass. Existing readiness, namespace, input-loss,
stop/reap and grant-only handoff cases still pass with unchanged base hashes.
Complete cached local integration subsequently passed on unchanged published
`6cb8d46` (tree `a1f1a35d`): actual builder host/vet/race/fuzz, refreshed image,
legal-info/SBOM and all existing guest lanes, including this root-close refusal,
retained Owner teardown, restricted-root Samba and actual SMART producer.
Seven exported artifact hashes were independently verified; the temporary
container auto-removed, reusing existing volumes/output/cache. This is neither
hosted/clean-build qualification nor proof of an exploit. No static-child
privilege or HTTP/storage/product authority changes. The earlier retained-code
Owner full result remains scoped separately.

The retained runtime-code Owner prototype privately holds the verified root and
all regular code files, plus fixed independently pinned process executables.
Its initial adapter supports only static ELF/non-root children; it does not
authorize dynamic Samba or NFS. Host/race and disposable ARMv5 fixtures cover
caller descriptor closure, immutable launch inputs, duplicate Start without
side effects, canceled teardown with group reaping, identical-byte executable
replacement and live root drift with permanent review after restoration.
Forced process cleanup keeps pins until explicit group-reap verification.
The dedicated local wrapper and full QEMU fixture reuse cached read-only inputs,
bounded tmpfs and unchanged base hashes. This is component evidence, not hosted
qualification, persistent review/recovery, complete service activation or EX4
hardware qualification. See the
[Owner contract](src/phantowd-api/internal/runtimebundle/README.md).

The dedicated ARMv5 Owner fixture now also proves two deterministic mid-scan
identity changes: an inner executable directory replaced with identical bytes,
and an alias replaced with the same target, after the initial census/alias
checks and earlier hash. Independent point-in-time inspection controls still
accept the declared bytes; the retained Owner refuses both before any child
starts, keeps review after restoration and verifies release/normal unmount.
Scheduling uses actual guest read descriptors, without fabricated metadata,
production hooks or relaxed checks. Native tagged vet/race and the bounded
fixture/marker preflight also pass. This is local component evidence, not
hosted/clean-build, an atomic snapshot, exhaustive race coverage, a performance
improvement or the separately proposed privileged Samba Owner composition.

Complete cached local integration passed on unchanged published `c93d936`:
the actual non-root builder's API/tool tests, vet, race and fixed-count fuzz,
package/image/legal-info/SBOM, native regular-image probe, standard/MD/two-boot
guests, isolated launcher, retained-code Owner, real loader, restricted-root
Samba and pure/actual-producer SMART lanes all passed. Seven exported artifact
hashes were independently checked. The earlier full attempt correctly refused
builder-owned positive fixture executables; the corrected tests use existing
root-owned system programs and explicitly retain the ownership refusal. No
production guard was weakened or target Python dependency introduced. The
full container auto-removed; two existing volumes and the current output/cache
were reused. This local result is not hosted feature qualification, independent
reproducibility, license/recovery closure or product installation approval.

A subsequent test-only ARMv5 increment covers forced cleanup at the aggregate
code-Owner boundary, not just its pinned process set. A static child ignores
SIGTERM; the first canceled-context Close retains ownership/pins and requires
review despite kernel-confirmed group absence. Normal unmount of the disposable
code bind returns `EBUSY`; after explicit reap verification it succeeds, while
review is never cleared and restart remains refused. Focused guest execution
passes against the manifest-checked cached base; production Owner code and
physical storage remain unchanged. Complete cached local integration then
passed on unchanged published `ad18fff` (tree `969a6459`), including this forced
cleanup proof, actual non-root builder host/vet/race/fuzz checks, image/legal/SBOM,
native probe, standard/MD/two-boot guests, launcher/loader/Samba and both SMART
lanes. All seven exported artifact hashes were independently verified and match
the preceding local integration. The temporary full container auto-removed;
the existing image, two volumes and single output/cache were reused. This is
not hosted feature qualification, clean reproducibility, complete license
compliance or permission to install or activate services on the EX4.

The subsequent code-permission audit reproduced an undeclared root access ACL
being accepted by `runtimebundle.Inspect` despite unchanged mode bits and hashes.
Inspection and QEMU-only staging now share the same ACL/capability refusal check.
The focused local ARMv5 fixture passes an ACL-free positive control and five
actual-kernel ACL refusals (root access/default, inner-directory access/default,
file access), followed by every existing Samba/CP850/stream/ext4 data-ACL/
inheritance/client/stop regression. Miniature code trees and read-only binds
exist only in the disposable guest's private namespace; data-grant ACLs remain
supported and untouched. This is focused local evidence on the working source,
not new full Buildroot/two-boot/hosted or physical EX4 qualification.
Pinned Linux Go 1.26.6 ordinary/QEMU-tagged vet, all API race tests and the
QEMU-tagged runtime package race tests pass; Windows API/UI preflight and
ARMv5 API test cross-compilation also pass. The focused wrapper reuses only
read-only base/cache inputs and auto-removes its container/tmpfs; no new
persistent image, volume or output namespace was created.

Full local incremental integration subsequently passed on unchanged published
`9d6eb03`: complete API/tool vet/race/fuzz, package/legal-info/SBOM, native probe,
standard ARMv5 smoke, MD, two-boot state, isolated launcher, loader and final
Samba/code-ACL fixture. All seven artifacts were independently rehashed and
match the preceding baseline, consistent with the code-only helper remaining
uninstalled. This cached exact-source run is not independent clean-build,
hosted feature, hardware or legal-distribution qualification. The existing
license-hash/source-packaging warnings remain release work. The README now
summarizes current capabilities and contributors' entry points; detailed
verification and internal lifecycle contracts remain in the linked documents.

The separate `feat/runtime-bundle-verification` follow-up adds an internal,
read-only code-tree inspection prerequisite for M4.4. A privately copied plan
checks complete census, read-only mount identity, hashes, file permissions and
exact direct aliases without symlink traversal or cross-mount opens. A focused
exact-commit `e8d347d` ARMv5 Samba fixture passes the actual tree and five altered-plan
refusals before adding test configuration/state/grants; all prior CP850/stream/
ACL/inheritance/client/group-stop cases still pass. It is not an approved
manifest, retained lease, root builder, service activation or hosted result.
Linux package vet/race, 25,000 bounded fuzz executions and ARMv5 test cross-
compilation also pass on that commit. The earlier broader working-tree Linux
API vet/race suite passed; neither result is a full new Buildroot integration.
See the [internal contract](src/phantowd-api/internal/runtimebundle/README.md).

The next source-only prototype, excluded from ordinary builds by `qemu && linux`,
now constructs the fixture's code tree from pinned read-only source descriptors
into an exclusively owned empty 0700 tmpfs root. Fresh `O_EXCL` copies verify
bounded hashes during copying; only verified files get final modes, and direct
aliases are generated from the fixed plan. The local final-source ARMv5 fixture
passes five staging refusals (occupied destination, wrong hash, writable source,
cancellation and source symlink), dirty-tree re-entry refusal, failed-copy
0600/0700 confinement and the following read-only inspector/Samba regressions.
The original base hashes remain unchanged. Host API/vet/cross-compile and Linux
QEMU-tag vet/package race tests pass. This is disposable construction evidence,
not an authenticated product manifest, retained root/lease, production Owner,
installer, full new Buildroot integration or hosted feature result.

Subsequent full local incremental integration on unchanged `7c6048c` passed
the complete Buildroot/package/legal-info run, Linux API/tool vet/race/fuzz,
native image-probe tests, standard ARMv5 smoke, MD fixture, two-boot state,
native launcher, real loader differential and combined Samba staging/inspection/
CP850/stream/ACL/inheritance/client/stop fixture. All seven published artifact
hashes equal the previous baseline, consistent with this prototype not being
installed in the firmware. This exact-source cache-reusing result is not an
independent clean build, hosted feature pass, complete legal certification or
EX4/product qualification. The pre-existing legal-info source-packaging warnings
remain release work, not evidence that distribution obligations are complete.

The separate `feat/smart-report-observation` increment adds the first M8.5
prerequisite: a pure internal smartctl 7.4 / JSON 1.0 ATA report parser, not a
collector. It matches embedded/process exit values, preserves collection errors
and current/historical flags separately, retains explicit failure during partial
collection, and rejects contradictory/ambiguous/oversized input without retaining
raw identities or tool messages. Internal observations cannot be serialized or
constructed from JSON. Local Windows API/UI preflight, pinned Linux ordinary/
QEMU-tagged vet and all API race tests pass; 10,021 fuzz executions pass.
Actual ARMv5 QEMU runs the package's synthetic 256-mask/state/refusal/privacy
tests and fuzz seeds, with the base hashes unchanged. The runner was corrected
from unsupported poweroff to reboot-with-no-reboot exit and exact optional-CR
serial marker matching; earlier failed runner attempts are not green runs.
Full local incremental integration then passed on unchanged published `2d4ab45`:
API/tool vet/race/fuzz, packages/legal-info/SBOM, native probe, standard ARMv5
smoke, MD, two-boot state, launcher/loader, combined Samba/code-ACL/data-ACL
and the new SMART fixture. All seven manifest artifacts were independently
rehashed and match the preceding baseline. After PR #57 merged, the follow-up
rebased to `8a3b95a` with an identical complete tree. This cache-reusing result
is not independent clean-build, hosted follow-up, legal or physical/product
qualification; known legal-info warnings remain release work. No smartmontools package,
device command, ioctl, self-test job, history, notification or endpoint is enabled.
Physical tool reports/transport/standby/device generation and product UI remain
unqualified; see the [SMART contract](src/phantowd-api/internal/smartreport/README.md).

The next `feat/smart-replay-corpus` test-only follow-up builds native upstream
smartctl 7.4 with only its generic backend and feeds seven invented ATA debug
transcripts through the documented stdin pseudo-device. The real JSON and
independent Go projections pass pinned Linux vet/race, including exit-zero
SMART-disabled, empty input and partial collection with reported fail. The
synthetic oracle initially expected disabled exit 4 and a device field after
empty stdin; actual execution/source review corrected those expectations. The
product parser required no behavioral change. Windows API/UI and the current
pure-parser ARMv5 suite also pass, with base hashes unchanged. Compilation and
reports stay in a bounded disposable tmpfs; no image/volume/package/device
authority or installed binary is added. This qualifies native synthetic
producer compatibility, not physical/ARM transport, standby or full integration
of this follow-up. See [scope and invocation](support/SMART-REPLAY.md).

The subsequent profile update separately verifies the current stable 7.5 release
archive/hash and native producer, then admits only exact release 7.4/7.5 with
JSON 1.0. The original 7.5 corpus fails before the allowlist change and passes
after; the 7.4 producer remains green. Both profiles get all 256 synthetic exit
projections and malformed/contradictory-input refusals, including older/future/
major/patch/prerelease rejection. Windows API/UI, pinned Linux ordinary/QEMU
vet/all API race and 10,000 fuzz executions pass; the updated parser passes on
ARMv5 with base hashes unchanged. None of these runs executes smartctl on ARM.
The tested C-only toolchain has no cross g++/cc1plus/libstdc++; actual
ARM producer testing requires a complete C++-enabled rebuild, bounded cache
transition and guest/service requalification. No such rebuild or collector is
claimed by this profile update; no obsolete cache was deleted merely to test JSON.

The follow-up adds a C++-enabled QEMU defconfig and a diskless ARM producer
fixture for pinned smartctl 7.5. It statically builds only the generic stdin
backend in bounded scratch, checks ARMv5TE/ARMv5TEJ soft-float linkage, and executes seven
invented inputs plus the Go projection tests in a read-only QEMU snapshot. A
focused wrapper refuses a missing compiler before launch; fast regression tests
cover the real `g++` filename and reject unsafe paths. Native 7.4/7.5 regressions
pass after sharing the trace generator. **The C++ toolchain is rebuilt and the
focused actual ARM producer fixture passes** against the manifest-verified
earlier base, with all seven exits/projections and unchanged base hashes.
The test exposed and corrected an overly narrow v5TE tag check and QEMU7.2's
/tmp-to-/var/tmp snapshot fallback; snapshots now use the owned tmpfs subdirectory.
The initial full build was stopped after the reproducible runner failure;
complete C++ image/service/SBOM integration subsequently passed locally on
`dd55481`: standard boot, MD/two-boot persistence, isolated launcher, loader,
restricted-root Samba, pure SMART parser and actual ARM producer all passed.
The seven final artifacts were independently rehashed. The generated rootfs
is 80 MiB, kernel 4,009,408 bytes and API 9,460,244 bytes. This reused verified
sources/compiler caches; it is not independent clean-build reproducibility,
hosted feature qualification or complete license/distribution review.
This is not a product collector, physical transport/standby qualification or
closed release gate.

The separate native boundary follow-up adds eight actual-producer tests per
release for checksum policy and power-query errors/default continuation.
Both 7.4/7.5 suites and the existing seven report projections/vet/race pass
locally. Version-specific power JSON is checked explicitly; sentinel power
exits are not treated as ordinary health bitmasks. No ARM runner, package,
product parser or collector authority changes; this is characterization only.

Percentages are **engineering planning estimates**, not measured test coverage,
probabilities of success, release readiness, or a delivery-date promise. Credit
includes source, negative tests and fixture integration; the remaining scope
includes product wiring, operator recovery and hardware qualification. Bands
remain wide because physical storage, cooling and installation may require
substantial redesign. Rows overlap and must not be added.

| Milestone | Implemented evidence | Main remaining acceptance work | Estimated completion |
| --- | --- | --- | ---: |
| M0 — Engineering baseline | Pinned builds, signatures/hashes, host/race/fuzz tests, QEMU, SBOM; an earlier independent reproduction | Reliable hosted integration, unresolved fixture failures, renewed release reproducibility | 50–65% |
| M1 — Durable state | Revision stores, intent/result journals, refusal of uncertain state, synthetic clean-reboot tests | Product state placement, bootstrap/schema migration, operator reconciliation, real durability/power-loss qualification | 30–45% |
| M2 — Identities | Unix allocation/creation; Owner-bound Samba disabled-first enrollment, explicit enable/disable and account-session revocation in QEMU | Complete ownership/import inventory, product boot authority, account API/UI, retirement and recovery | 50–65% |
| M3 — Storage lifecycle | Complete sysfs census, generation-bound read-only broker, GPT/ext/MD observations, collision checks, scoped desired-volume review, internal mount/lease fixtures | Persistent logical VolumeID resolver, global-use accounting, production qualifier/roster, supported layouts and EX4 media qualification | 40–55% |
| M4 — SMB/NFS | Real loopback clients, desired policies, coherent candidate planner, process-set supervision, share-scoped handoff, grant-only isolated runtime and retained static-code Owner with explicit supervised lifecycle in QEMU | Approved daemon runtime manifests, isolated process sets, privilege profiles/ACLs, transactional activation/recovery, production wiring and storage-loss monitoring | 35–50% |
| M5 — Management UI/security | Development authentication/TLS, sessions/password changes, diagnostics dashboard and policy preview/editing | Product enrollment/reset/certificate lifecycle, authorized live workflows, recovery UX, browser/accessibility/security qualification | 25–40% |
| M6 — Network/system | Dual-stack desired-policy model, private bounded read-only kernel inventories and internal local-address diagnostics in host/ARMv5 QEMU; brief two-port board research | Qualified interface/external-conflict and routing admission, safe network transactions/rollback, supported dual-port modes, time/discovery, notifications and administrative jobs | 5–15% |
| M7 — Board/cooling/recovery | DTS and bounded diskless RAM trials; passive MCU framing/catalog tooling | Qualified factory identities, fan/tach/fail-safe, LCD/LED/buttons/power/watchdog, SATA/USB and NAND recovery | 15–25% |
| M8 — RAID/health/migration | Generic offline GPT/ext/MD inspectors, static WD layout analysis and synthetic offline SMART report interpretation | Attributable EX4 layout corpus/importer, ownership/ACL migration, RAID jobs, trusted SMART collection/history/jobs/UI, backup/restore tests | 15–25% |
| M9 — iSCSI | Specification and legacy research; no product target implementation | ARMv5 backend selection, LUN model, session/ownership guard, migration and failure campaigns | 0–5% |
| M10 — Installer/upgrades | Host-only signed release/payload/version verification | Reviewed boot/state/install layout, target installer, signing-key lifecycle, boot health/rollback and demonstrated unbrick | 10–20% |
| M11 — Public release | Portions of test infrastructure, package SBOM and earlier reproducibility evidence | Measured EX4 budgets/mixed load, independent security/legal review, physical recovery campaign and signed release assets | 5–15% |

Overall planning band: **roughly 25–40% of the first-release engineering scope**.
This is a judgment weighted toward storage/sharing, board safety and migration,
not an average of file counts. **0 of 12 milestones are product-qualified**;
there is no installable beta. Applications/mobile/multi-model support are
excluded. No calendar estimate is defensible before the hardware/recovery gates.

## Evidence map and integration gaps

M0.3 local build-environment follow-up: two successful exact-head hosted jobs
(PR77 `37136391769`, PR78 `37140806223`) took 3410/3465 seconds. In the PR78
log, host-cmake bootstrap/configure/build consumed about 11 minutes before
host-Go, despite an exact compiler-cache hit: this dependency cannot use
ccache. The pinned container now supplies snapshot-authenticated system CMake
3.25.1, accepted by the current QEMU configuration's Buildroot minimum 3.18.
The source-contract regression first fails with CMake absent; 23 Linux
feedback tests and shell/workflow contracts then pass. A fresh disposable
configuration proves ordinary host-tool selection with no host-cmake cache
dependency and refusal of an unsuitable version. An actual cold host-ccache
4.10.2/dependency build passes in 86 seconds using only existing source archives
and disposable tmpfs, without network or host-cmake compilation. Frozen
`4202bbf` then passes the complete local cached Buildroot lane: pinned native
vet/unit/race/fuzz, target/legal/SBOM, regular-image probe, ARMv5 smoke, MD,
two-boot state, isolated runtime/Owner/loader, atomic, Samba/ACL and SMART
fixtures. Seven generated artifact hashes independently match after terminal
exit zero; the builder is removed and only the two fixed volumes/one pinned
image tag remain. This is not measured hosted speedup, clean independent
reproducibility, EX4 or a product milestone. No target feature, compiler-cache
trust rule or guest assertion is weakened; no new persistent workspace or
device operation is added. That initial complete local run used integrated
`d1b8dfe`, before PR79. After guarded PR79 integration, rebase `46341c7`
retains all four qualified CMake input blobs and the exact PR79 API subtree.
Whole tagged Linux vet/race, repeated SIGKILL regressions, feedback contracts
and actual ARMv5 standard/two-boot overlay pass for this union. Seven base
artifacts remain unchanged; the overlay does not regenerate legal/SBOM or
qualify a new clean image. The build-environment follow-up's own hosted
acceptance remains pending.

- M0: [build harness](support/container/build-qemu.sh),
  [QEMU workflow](.github/workflows/qemu-armv5.yml),
  [fast-lane limitations](support/QEMU-FAST-TESTS.md).
- M1/M2: [administrator store](src/phantowd-api/admincredentials/README.md),
  [service store](src/phantowd-api/fileservicestore/README.md),
  [identity Owner](src/phantowd-api/identityowner/README.md) and
  [credential lifecycle](src/phantowd-api/SMB-CREDENTIAL-LIFECYCLE.md).
- M3/M4: [read-only helper](src/phantowd-volume-probe/README.md),
  [mount Owner](src/phantowd-api/internal/mountowner/README.md),
  [process Owner](src/phantowd-api/internal/processowner/README.md) and
  [candidate planner](src/phantowd-api/internal/fileserviceplan/README.md).
  The mount qualification/driver remains QEMU-only. The fixed roster is not
  an appliance discovery provider. The handoff's original volume path remains
  reachable in the host mount namespace; a read-only clone alone is not an
  authorization boundary. A separate single-static-child isolated runtime now
  closes that bypass in its disposable grant-only fixture, not for ordinary
  process sets or real daemons. Ordinary API startup activates neither runtime.
- M5/M6: [management component](src/phantowd-api/README.md) and
  [startup code](src/phantowd-api/main.go). Saving desired policy is not applying it.
- M7: [board research](board/wd/ex4/README.md) and
  [MCU tooling](tools/phantowd-lab/mcuproto/). Protocol selectors and sensor
  observations do not establish a functioning, safe hardware-control daemon.
- M8/M9: [compatibility matrix](STORAGE-COMPATIBILITY.md) and
  [offline inspectors](tools/phantowd-lab/diskimage/). All legacy migration
  layouts remain unqualified; metadata consistency is not health or mount authority.
  [SMART report interpretation](src/phantowd-api/internal/smartreport/README.md)
  is offline only; no report provenance, freshness or device control is established.
- M10/M11: [host verifier](tools/phantowd-lab/releaseverify/) and
  [GitHub release reader](tools/phantowd-lab/githubrelease/). Neither installs firmware.

## Validation and CI findings

The local wrapper's opt-in `-CachedOnly` mode encodes the previously passing
bounded local profile without building/pulling an image, explicitly creating
volumes or repairing ownership. It refuses absent cache inputs and mismatched
current-config output before compilation. Mock command-boundary tests cover
the fixed arguments and seven refusal paths; seven real Linux shell-preflight
tests cover initialized, missing, changed-config and nonwritable inputs.
The actual complete wrapper run subsequently passed on unchanged `9a40538`
(tree `60ddde8d`), including all host/race/fuzz/image/legal/SBOM and guest lanes.
Seven artifacts independently match the preceding baseline; the temporary
container is removed, with only the two fixed volumes, one 14 GiB output and
approximately 971 MiB compiler cache remaining. Exact-head
[host workflow](https://github.com/PhantoNull/phantowd-ex4/actions/runs/37094418091)
also passes, including PowerShell and the Linux preflight. This qualifies this
cached local wrapper, not independent reproduction or physical/product safety.

The unmodified audited baseline passed the local pinned incremental Buildroot
pipeline on 2026-10-02: Linux vet/unit/race and bounded fuzz, native volume-probe
fixtures, standard ARMv5 QEMU smoke, mdadm-authored MD v1.0 comparison and the
two-boot state fixture. Existing fixed cache/workspace volumes were reused.
This is not an independent clean build or EX4 qualification.

Hosted evidence is separate:

- [Run 36990449160](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36990449160)
  compiled successfully but hit the standard smoke's 120-second readiness
  deadline. Its detailed failed-guest artifact is now retained. A local
  CPU-limited differential reproduced timeout at 121 seconds and completed
  the same full smoke at 162 seconds with the new bounded 240-second budget.
  This supports budget exhaustion; it does not conclusively rule out another
  hosted problem. No assertion is removed and QEMU is not retried. This run
  never reached the separate MD/state fixtures, so it does not confirm the
  executable-mode correction below. Later exact-head validation passed in
  PR #54 and PR #55; this does not retrospectively validate the failed run.
- [Run 36967317155](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36967317155)
  failed Linux process lifecycle tests after the expensive build. Later
  handshake/timing test changes and current local race checks pass; they do not
  retrospectively validate that failed revision.
- [Run 36975422468](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36975422468)
  passed standard guest smoke and failed the MD v1.0 fixture. The workflow did
  not upload its saved failure log. The current baseline passes locally; the
  hosted fixture failure's precise root cause remains unresolved.
  Follow-up differential QEMU testing found a concrete clean-checkout defect:
  the MD fixture's PID-1 script was recorded as Git mode `100644`, while Docker
  Desktop local builds installed it executable. Setting only the copied image's
  init inode to `0644` reproduced kernel `EACCES`/panic; `0755` passed the complete
  MD/Owner fixture. The executable Git-mode correction and an early source-mode
  regression now address this discrepancy. The old run's missing detailed log
  prevents proving that no additional defect was involved. PR #55 passed the complete
  exact-head hosted QEMU lane, including the MD fixture.
- Current workflow concurrency separates PR and branch refs: a merged PR can
  continue compiling alongside its `develop` integration. Cancel only a
  confirmed superseded run, not a still-needed qualification run.
- A compiler-cache miss followed by downstream failure previously prevented
  saving the completed compilation, causing the next run to rebuild cold.
  Compiler-cache reuse must never imply test success or release qualification.

The feedback improvement runs pinned Linux tests before the full target build,
prints the last 120 guest-log lines on failure, uploads failure-only diagnostics,
and permits only non-cancelled trusted `develop` pushes with a fresh completed-
compile checkpoint to seed the bounded compiler cache. It does not suppress
tests, retry mutations, or claim the historical MD/state failures are fixed.
The exact cache key was absent on the latest failed run. Restore now tries
older QEMU/Linux compiler-cache entries only after exact-input keys; ccache
still revalidates compilation inputs and the trusted-only write/size rules
are unchanged. This is not a cached workspace or an established speedup.

## Next implementation sequence

The integrated PR #55 implements a native
static-ELF launcher and internal fixed-input `IsolatedOwner`, passing disposable
ARMv5 namespace/root/FD/privilege/signal/PID/read-only tests, seven refused
launches, real readiness/stop, and pre-launch/live input-loss quarantine. See its
[contract](src/phantowd-service-launcher/README.md). It is not connected to
product startup or ordinary process Set and does not complete M4.4 or change
the planning bands above. Runtime manifests, product root construction, leases, native
daemon integration and kernel NFS authority remain unresolved.

Published follow-up `aecfdb4` passed the full **local incremental** pinned
Buildroot pipeline on 2026-10-02: Linux vet/unit/race/fuzz, target/legal/SBOM,
native regular-image probe, standard ARMv5 smoke, MD v1.0 comparison, separate
two-boot state fixture and native/Go isolated Owner fixture. All seven artifact
hashes were rechecked. The standalone launcher and its Go fixture are injected
only into a temporary test image, not installed by the firmware package.
This does not qualify a clean build, hosted integration, physical EX4 or
Samba/kernel-NFS activation. PR #54 and PR #55 later passed their exact-head
hosted QEMU checks; those are separate evidence, not release approval.

1. **M0.3:** validate the feedback changes locally and in exact-head CI; retain
   failed-guest evidence. Investigate any recurrence before changing semantics.
2. **M4.4:** integrate the independently tested launcher into one trusted,
   fixed process boundary per service, preserving supervised PID/
   process-group ownership; private mount namespace with private propagation
   and restricted root. Pin only the granted share roots and necessary runtime
   inputs; remove access to original volume paths, inherited host root/FDs,
   devices and mount privileges. Probe actual Linux/ARMv5 behavior before
   choosing a production mechanism. No HTTP path or product enablement.
3. **M3/M4:** complete trusted production roster/qualification and durable
   logical volume identities; then a single service configuration/activation
   owner with freshness, leases, readiness, stop-before-release and uncertain-
   outcome recovery. Do not copy QEMU-only constructors into product startup.
4. **M1/M2/M5:** product-owned persistent authority/startup and operator
   reconciliation, then authorized account/share management workflows.
5. **M7/M8/M10:** separately reviewed exact-model hardware, cooling, healthy
   disposable-media migration and recovery evidence before installation.

## Re-audit: execution path, backlog and next deliverable

The ordinary API entrypoint (`src/phantowd-api/main.go`) wires diagnostics,
authentication, desired policy and manual read-only GPT observations. It does
not instantiate the mount/process/identity Owners as a persistent product
activation manager. `package/phantowd-api/S50phantowd-api` likewise starts only
the non-root development API. The isolated launcher remains a fixture-injected
helper, not an installed package. This is the main difference between our many
tested building blocks and a usable appliance, not a missing cosmetic screen.

The earlier statement above that the launcher has no handoff/runtime
composition is superseded by `f7571ea` **only for a dedicated grant-only handoff
and one static non-root child**. Ordinary process sets, multi-user Samba and
kernel NFS control retain their separate gaps. The feature is already pushed;
at this audit it has seven commits beyond integrated `develop`, zero committed
changes waiting for push, and PR #54 is the only open PR. Do not manufacture
extra PRs or merge a still-pending exact-head check to reduce the count.

The host-only `inspect-runtime-closure` now reuses the existing ELF inventory
instead of a second parser. Pinned Linux Go 1.26.6 vet/unit/race checks and
50,000 fuzz executions pass. On the existing Buildroot target, the restricted
candidate for `usr/sbin/smbd` resolves **105 distinct regular ELF objects,
27,110,832 bytes**. A regression distinguishes an entirely empty RUNPATH
(ignored by glibc) from unsafe empty components of a nonempty search list.
Windows API/UI and lab-tool preflights also pass. This is an offline extracted
view, not a fresh image build, ARMv5 loader comparison or permission/ABI/runtime
qualification. All candidate outputs explicitly deny execution authority.

Continue M4.4 with these concrete acceptance steps:

1. **Local differential complete:** actual ARMv5 loader in a disposable QEMU
   image resolves 104 dependencies, exactly matching the 105-object candidate
   excluding the main executable. Guest hashes and canonical aliases match;
   both default and 1000:1000 builders pass, original rootfs unchanged. This does
   not start Samba or qualify its runtime/privileges. Seven host refusal/budget
   tests, lint and existing feedback/workflow contracts pass. Full-build hooks
   now reuse this comparison; the complete local incremental pipeline passed
   on unchanged `357be1d`: Linux vet/unit/race/fuzz, package/license/SBOM checks,
   standard ARMv5 smoke, MD v1.0 comparison, two-boot state, native isolation and
   loader match. Seven generated-artifact hashes passed. This reused existing
   caches, not an independent clean build, hosted run or hardware qualification.
2. Inventory Samba's required `dlopen`/NSS modules, configuration, state, sockets
   and privilege transitions. Keep root/UID switching distinct from the generic
   zero-capability child; do not widen that helper or use shared client identity.
3. Construct the trusted per-service root from independently pinned, validated
   runtime inputs and explicit share grants; prove denied original paths,
   ungranted shares and read-only bypass attempts, then stop-before-release.
4. Integrate a service-specific owner and recovery transaction only after the
   complete production storage qualifier/roster and state authority exist.

Hosted update: PR #54 head `d827026` passed both host (`37001276886`) and
ARMv5/DTB (`37001276464`) checks and merged into `develop` as `3902f97`.
The successful hosted smoke took about 124 seconds under the new 240-second
bound; the old 120-second budget would not cover it. The roughly 84-minute job
spent most time compiling. Older compiler cache restored, but its speedup is
not measured. The normal `develop` run is separate from this exact-head result.
Historical timeout, executable-mode and state-unmount failures remain distinct;
this pass does not resolve intermittent EBUSY or qualify physical hardware.
No new image or named volume was created for the dependency research.

The separate [Samba restricted-root fixture](support/SAMBA-RUNTIME-PROFILE.md)
now passes locally with real distinct-user SMB3 access, owner/mode checks,
kernel read-only enforcement, original-path/symlink denial, one UTF-8 filename
and process-group stop. It retains only six root capabilities for Samba identity
switching; the generic non-root helper is unchanged. This is disposable ext4
and a cached image overlay, not an Owner-backed product root, daemon activation,
full dynamic-module/encoding/ACL qualification. The whole updated incremental
pipeline also passed on unchanged `fba213d`, including Linux race/fuzz,
package/license/SBOM, standard ARMv5, MD, two-boot state, native Owner/handoff,
loader and this Samba experiment. This is not hosted feature CI or an
independent clean build; existing fixed caches were reused.

Host/QEMU work can continue now. Valuable disks, the live NAS and NAND/MTD
remain outside this implementation/test scope.
