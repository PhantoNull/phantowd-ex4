<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation status

Code audit: **2026-10-03**, integrated `develop` baseline
`d1b8dfeda4a15f74d17030f17f92b4132e7d5e54` (PR #78).
Use [ROADMAP.md](ROADMAP.md) for the acceptance specification. This snapshot
distinguishes tested components from deployed product workflows. It is not
installation approval, a security certification, or an exhaustive line-by-line audit.

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
mount/import or activation is added. This is local unintegrated overlay evidence,
not hosted, clean-build or EX4 acceptance; planning bands remain unchanged.

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
This is local unintegrated evidence, not hosted, clean-build or EX4 acceptance.
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
full-image/SBOM, hosted topic or product qualification. The separately proposed
privileged Samba Owner composition still requires its explicit scope decision;
neither it nor a new product/helper/HTTP privilege is implemented. Bands unchanged.

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
device operation is added. The follow-up is based on integrated `d1b8dfe`,
not the still-separate PR79 storage runtime.

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
