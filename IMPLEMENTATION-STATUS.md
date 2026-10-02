<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Implementation status

Code audit: **2026-10-02**, integrated `develop` baseline
`3902f9735737b9708022014b1e4703d8d53d6358` (PR #54).
Use [ROADMAP.md](ROADMAP.md) for the acceptance specification. This snapshot
distinguishes tested components from deployed product workflows. It is not
installation approval, a security certification, or an exhaustive line-by-line audit.

Follow-up audit includes published feature head `fba213d` on
`feat/service-namespace-launcher`, the host-only ELF dependency candidate and
actual ARMv5 loader differential and separate Samba-root fixture described below.
The full local incremental pipeline passed on this unchanged feature commit.
These additions are not yet integrated into
`develop`; do not confuse feature evidence with an integration/release result.
Planning bands remain unchanged: no new product acceptance gate has closed.

The subsequent local Samba fixture adds one fixed dynamic
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

## Roadmap comparison

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
| M4 — SMB/NFS | Real loopback clients, desired policies, coherent candidate planner, process-set supervision, share-scoped handoff and a single-static-child grant-only isolated runtime in QEMU | Approved daemon runtime manifests, isolated process sets, privilege profiles/ACLs, transactional activation/recovery, production wiring and loss monitoring | 35–50% |
| M5 — Management UI/security | Development authentication/TLS, sessions/password changes, diagnostics dashboard and policy preview/editing | Product enrollment/reset/certificate lifecycle, authorized live workflows, recovery UX, browser/accessibility/security qualification | 25–40% |
| M6 — Network/system | Diagnostic observations and brief two-port board research | Safe network transactions/rollback, supported dual-port modes, time/discovery, notifications and administrative jobs | 5–15% |
| M7 — Board/cooling/recovery | DTS and bounded diskless RAM trials; passive MCU framing/catalog tooling | Qualified factory identities, fan/tach/fail-safe, LCD/LED/buttons/power/watchdog, SATA/USB and NAND recovery | 15–25% |
| M8 — RAID/health/migration | Generic offline GPT/ext/MD inspectors and static WD layout analysis | Attributable EX4 layout corpus/importer, ownership/ACL migration, RAID jobs, SMART product collection, backup/restore tests | 15–25% |
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
  executable-mode correction below. Exact-head hosted validation is pending.
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
  regression now address this discrepancy. Exact-head hosted confirmation is
  still required; the old run's missing detailed log prevents proving that no
  additional defect was involved.
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

Local follow-up on `feat/service-namespace-launcher` implements a native
static-ELF launcher and internal fixed-input `IsolatedOwner`, passing disposable
ARMv5 namespace/root/FD/privilege/signal/PID/read-only tests, seven refused
launches, real readiness/stop, and pre-launch/live input-loss quarantine. See its
[contract](src/phantowd-service-launcher/README.md). It is not connected to
the existing handoff/Set/runtime and does not complete M4.4 or change the planning
bands above. Runtime manifests, product root construction, leases, native
daemon integration and kernel NFS authority remain unresolved.

Published follow-up `aecfdb4` passed the full **local incremental** pinned
Buildroot pipeline on 2026-10-02: Linux vet/unit/race/fuzz, target/legal/SBOM,
native regular-image probe, standard ARMv5 smoke, MD v1.0 comparison, separate
two-boot state fixture and native/Go isolated Owner fixture. All seven artifact
hashes were rechecked. The standalone launcher and its Go fixture are injected
only into a temporary test image, not installed by the firmware package.
This does not qualify a clean build, hosted integration, physical EX4 or
Samba/kernel-NFS activation. PR #54's exact-head hosted QEMU remains pending.

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
