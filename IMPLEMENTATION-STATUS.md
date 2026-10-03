<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation status

Code audit: **2026-10-03**, integrated `develop` baseline
`dd1dd99c83fa5458f6b55bf72e582c389123b7a3` (PR #64).
Use [ROADMAP.md](ROADMAP.md) for the acceptance specification. This snapshot
distinguishes tested components from deployed product workflows. It is not
installation approval, a security certification, or an exhaustive line-by-line audit.

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
| M3 — Storage lifecycle | Complete sysfs census, generation-bound read-only broker, GPT/ext/MD observations, collision checks, internal mount/lease fixtures | Persistent logical VolumeID resolver, global-use accounting, production qualifier/roster, supported layouts and EX4 media qualification | 40–55% |
| M4 — SMB/NFS | Real loopback clients, desired policies, coherent candidate planner, process-set supervision, share-scoped handoff, grant-only isolated runtime and retained static-code Owner with explicit supervised lifecycle in QEMU | Approved daemon runtime manifests, isolated process sets, privilege profiles/ACLs, transactional activation/recovery, production wiring and storage-loss monitoring | 35–50% |
| M5 — Management UI/security | Development authentication/TLS, sessions/password changes, diagnostics dashboard and policy preview/editing | Product enrollment/reset/certificate lifecycle, authorized live workflows, recovery UX, browser/accessibility/security qualification | 25–40% |
| M6 — Network/system | Diagnostic observations and brief two-port board research | Safe network transactions/rollback, supported dual-port modes, time/discovery, notifications and administrative jobs | 5–15% |
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
