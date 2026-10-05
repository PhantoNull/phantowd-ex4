# M9.1: disposable LIO qualification

This is a research contract, not a selected production backend or an installer.
The scope is ARMv5 QEMU, synthetic 32 MiB and 8 MiB backings and test-only loopback
initiators. The original single-peer fixture now also checks two simultaneous
peers with independent credentials/grants. No NAS, physical device, host port
forwarding or product activation.

## Source findings

The pinned Linux version in `versions.env` contains LIO/FILEIO. The current
QEMU kernel does not enable `TARGET_CORE`, `CONFIGFS_FS` or `ISCSI_TARGET`.
Architecture-independent Kconfig eligibility is not ARMv5 runtime qualification.

In `drivers/target/target_core_file.c`, `fd_configure_device` calls `filp_open`
with `O_RDWR | O_CREAT | O_LARGEFILE | O_DSYNC`. Missing backings can therefore
be created. Its control parser also splits on commas/newlines; desired backing
paths must never be interpolated directly into that interface. FILEIO initially
uses 512-byte blocks initially. The separate 8 MiB/4096-byte fixture below now
passes locally; this does not qualify that option for product storage.

`target_dev_enable_store` calls `target_configure_device`, which calls the
backend's `configure_device` directly. A retained `/proc/self/fd/N` binding is a
candidate for the fixture, not yet a proven safe product handoff. Opening a
descriptor read-only is not writable storage authority: FILEIO reopens it RW.

In `iscsi_target_configfs.c`, authentication attributes require `CAP_SYS_ADMIN`.
Their show functions return credentials; never recursively dump configfs.
Store treats an uppercase `NULL` prefix as unset. A future backend adapter must
reject reserved values before use, independently of the generic desired model.
Credentials, daemon/portal state and active sessions need their own typed owner.

**Mutual configuration is not mutual-only enforcement.** In the pinned
`iscsi_target_auth.c`, a missing initiator CHAP_I takes the successful one-way
path even when `authenticate_target` is set. The actual fixture confirms this,
as well as successful reciprocal exchange and client-side refusal of a wrong
target response/name. Do not admit a product policy promising required
bidirectional authentication merely because outbound configfs credentials exist.
The optional research-only enforcement profile below now passes local guest
tests. Product use still needs separate review/qualification; never silently
downgrade a requirement or infer enforcement from configured credentials alone.

The kernel documentation's illustrative setup disables authentication and uses
a wildcard portal. It is not an acceptable fixture or production default.
See [upstream configfs examples](https://docs.kernel.org/target/scripts.html).

## Increment A: isolated kernel prerequisite

`container/build-qemu-lio-kernel.sh` extracts the hash-verified pinned Linux
archive into a fresh tmpfs workspace, copies a supplied QEMU configuration and
enables built-in LIO/FILEIO and MD5 for the CHAP interoperability fixture.
MD5 here is the protocol algorithm, not a password-storage recommendation;
CHAP does not encrypt storage traffic. Kernel initiator, userspace backstores
and physical/pass-through target backends stay disabled.

The script must use an existing pinned compiler/workspace read-only, with no
network, image build/pull or new named volume. The caller owns a bounded tmpfs
and an auto-removed non-root container. The compile helper retains output only
in that tmpfs. A caller may keep one small, ignored local kernel candidate with
input/output checksum manifests for feedback; that is not a signed release or
an independent reproducibility claim. Never accumulate full source/build trees.
It checks the final configuration, hashes kernel/config/DTB, and verifies source
archive/base configuration are unchanged. This lane is not the normal QEMU
kernel, a release build, SBOM regeneration or an EX4 board change.
The existing baseline mounts its ext2 root using the ext4 driver; the audit
requires that existing driver, not a newly enabled separate ext2 driver.

Local qualification on 2026-10-04: ShellCheck and six Windows/Linux profile
test groups pass; the fresh-source ARMv5 kernel compile succeeds using the
pinned existing toolchain. Source/config inputs remain unchanged and scratch
uses 1.9 GiB before the ephemeral container exits. Subsequent actual guest
qualification is described below; the original compile-only marker is not
runtime proof. No kernel output is published as an installable release.

Run the fast profile tests independently:

```powershell
python -B support/tests/test-qemu-lio-inputs.py
```

The compile helper's five arguments are: read-only checkout, pinned Linux
archive, existing QEMU `.config`, existing Buildroot `host` directory, and a
fresh empty tmpfs output directory. Use `sh` to invoke it inside the bounded
builder; do not run it against a writable persistent build cache. Its success
marker explicitly says `guest=false activation=false`.

## Increment B: actual target and initiator fixture (local research)

### Typed credential install/readback prerequisite

The dedicated guest additionally runs the current tagged Go fixture before the
existing FILEIO tests. Two new fixed targets are created and removed sequentially
with **zero data LUNs**. A public synthetic root-only vault retains a credential
claim while the private fixed configfs sink matches the complete peer roster,
binds auth descriptors to the retained TPG's named ACLs, writes fixed leaves and
performs exact bounded readback. Same-configfs foreign ACLs refuse. The pinned
libiscsi client verifies CHAP/reciprocal login and exact wrong/missing credential
refusal without SCSI commands; its output is discarded by the fixed Go caller.
Observed credential drift remains review after exact restoration, with no retry.
All client processes join, TPG disables and portal/ACL/TPG/target objects are
removed before the claim is released. Independent fixture disposal is not
product recovery. The final default-profile actual ARMv5 run passes locally;
mocked strict/idle wrapper checks are not actual qualification of this new case.

The sink borrows backend-owned references and never creates/enables targets,
opens data, provisions a store or releases a claim. It is not the complete
targetBackend adapter, exclusive mutation/session authority, active-state
credential observer or required-mutual enforcement. CHAP stale outbound fields
are logically unset, not guaranteed erased from kernel memory. Disabled-state
snapshots do not prove continuous change history or an atomic transaction.
The fixture executable is added only to a discarded copy of the root image,
not installed in the standard overlay. The runner's seventh required argument
is that independently compiled tagged fixture binary; the wrapper compiles it
using the pinned existing Go toolchain with a disposable cache and no download.

### Retained-storage adapter access and active-session cases

The optional guarded kernel profile also runs the private complete-target
adapter with a real mount Owner and one disposable 16 MiB ext2 data image.
Already-admitted two-file/LUN0/7 references bind through integer-only proc-FD
control values, with 512/4096-byte blocks. No desired path is passed to FILEIO.
The primary CHAP peer writes/reads both LUNs. A separately authenticated peer
reports exactly LUN0, reads it, receives exact write-protected sense on writes
and logical-unit-not-supported on LUN7. Crossed credentials and a foreign IQN
fail with exact expected status, not connectivity errors. Independent data
readback confirms the original files remain correct after these refusals.

A second case keeps a single libiscsi context connected through the real Owner's
stop refusal. Fixed bounded stdin/stdout commands coordinate fresh two-LUN reads
and writes AFTER refusal; reconnect is disabled. Independent retained-descriptor
reads confirm new bytes. Every file/Pin/mount/policy/secret claim remains held;
all lifecycle calls keep terminal review and do not retry. After verified logout,
a separate QEMU-only disposal controller rechecks identities/idle state, uses
non-forcing idle disable and removes witnessed objects before fixture release.
It never calls or resets the failed backend stop, and does not clear review.
This is disposal, NOT durable recovery or a product route. A refused stop keeps
the target enabled; pending-login side effects and new-login fencing remain open.

Both new cases pass locally on actual ARMv5 guarded QEMU. Separate mandatory
result markers have native omission/duplicate/weakening RED/GREEN contracts;
old protocol gates and standard/two-boot checks remain. No image/named volume
is created in Docker; guest image and kernel/client/source scratch are discarded.
Exclusive writer/code/network/registry/storage/allocation/global-use authority,
setup/teardown faults and product recovery/startup/UI still need qualification.

Use the isolated kernel and a disposable snapshot of the verified root image;
start a dedicated guest init, not product services. The guest alone may use
root/configfs. Attach no operator/physical disks and disable external QEMU
networking; only the guarded adapter's newly generated regular image is writable.
Only explicitly allowed initiators on guest loopback may log in. Use fixed
synthetic secrets, never operator credentials; redact auth diagnostics.

The test client uses pinned upstream libiscsi 1.20.0, not a home-grown wire
protocol. `build-qemu-iscsi-client.sh` verifies the source archive and three
license hashes, disables examples/test tools/shared libraries/iSER/libgcrypt,
builds its internal MD5 implementation and statically links original Apache-2.0
test glue. The upstream package includes GPL-2.0+/LGPL-2.1+ components: this
development executable is not shipped in the product or a release asset.
Release source/notice obligations would require a separate review.
Do not add the Python targetcli management stack merely to write fixed configfs
attributes; resource efficiency of a native adapter is still unmeasured.

Implemented independent assertions, exercised on actual ARM926 QEMU:

- Good CHAP succeeds; wrong/missing credentials and foreign initiator fail.
- Explicit RO mapping denies writes; RW mapping reads back exact synthetic data.
- Unlink/rename/replace the original pathname after retaining its descriptor:
  kernel I/O must still reach the admitted object, never its replacement.
- Missing/closed descriptors fail without creating any replacement backing.
- Check actual capacity/block size, write-cache policy and target state.
- Observe a live session, disable the portal group, verify its disappearance,
  refuse I/O from that session and new login while disabled, then re-enable
  and verify unchanged data. Configfs disable **forcibly closes sessions**;
  this is not a product active-session mutation-refusal guard.
- Verify no listener outside loopback, no copied credentials in logs, no leaked
  target objects/sessions and unchanged base artifacts after exit.
- Reciprocal CHAP succeeds with separate inbound/outbound synthetic secrets.
  Wrong inbound credentials, wrong target response and wrong target username
  require exact pinned protocol/library failures, not a network error. A one-way
  peer still succeeds with mutual credentials configured in the unchanged
  upstream profile. The optional strict profile requires authentication refusal
  instead, while leaving peers without outbound credentials unchanged.
- With no active session, rotate the primary inbound credential: old login
  fails, new reciprocal login succeeds and existing data remains unchanged.
  This is not durable or interrupted/live-session credential rotation.
- Observe two simultaneous explicit ACL sessions: primary RW writes/readback
  and secondary RO write denial use independent credentials. Cross-peer
  credentials fail; secondary logout leaves the primary session observed and
  capable of reading unchanged data. Both logout before ACL teardown. This
  concurrent-session test uses one target/LUN and the same pinned client, not Windows,
  per-account revocation or a production session/use owner.
- A second retained 8 MiB FILEIO object uses 4096-byte blocks, while the original
  32 MiB object remains 512-byte. Primary ACL sees LUNs 0/1 with RW/RO access;
  peer sees 0/3 with RO/RW access. Exact reported sets, both capacities/block
  sizes, ungranted-LUN SCSI refusal, opposite write permissions, distinct seeds,
  readback and peer-write visibility are mandatory. Every session logs out
  before exact link/storage/descriptor cleanup. These multi-LUN I/O clients run
  sequentially; the earlier single-LUN concurrent-session test is retained.

Use strict bounded timeouts and mandatory markers. Any uncertain cleanup fails;
no retries, silent recreation or reuse of a partially configured target.

The runner uses a private tmpfs `TMPDIR` for QEMU snapshot files. A paused-VM
RED/GREEN regression proves that missing TMPDIR fails on the read-only builder
and the actual call site uses its owned scratch. The dedicated guest init is
never installed in a normal overlay. It mounts only its root snapshot read-only
and tmpfs/configfs; dense 32 MiB and 8 MiB files are the only data backings,
inside the existing 64 MiB guest tmpfs.
The runner attaches no NIC/data disk/host port and accepts only guest-loopback
listeners. The pinned kernel's inactive `sit0` tunnel is accounted for explicitly.

CHAP challenge generation in the pinned kernel waits for initialized randomness.
The runner provides `virtio-rng-pci` from host `/dev/urandom`; the client requires
nonblocking `getrandom` readiness before connecting. No fixed entropy seed or
authentication bypass is used. This qualifies neither EX4 entropy nor production
secret generation. FILEIO write cache and FUA emulation are disabled; the test
does not send unadvertised FUA commands and makes no power-loss durability claim.
Negative logins require the exact pinned protocol refusal class/detail, not a
network failure. Diagnostics and result validation never expose credentials.
The bounded result validator also refuses unknown/contradictory LIO readiness
lines in addition to missing/duplicate markers and secret/error tokens. A
native RED/GREEN regression verifies this consumer boundary. Each invocation
selects one exact expected profile; default/strict, mixed, missing and duplicate
markers cannot substitute for each other.

### Optional strict mutual-login research profile

`fixtures/patches/linux-lio-strict-mutual.patch` adds a default-off kernel option,
`CONFIG_ISCSI_TARGET_STRICT_MUTUAL_CHAP`. Only an explicitly selected fresh tmpfs
research compile applies it, with zero patch fuzz. With outbound target
credentials configured, a missing initiator challenge now fails authentication
instead of taking the successful one-way branch. Peers without outbound
credentials retain their one-way behavior. Standard QEMU/EX4 kernels, Buildroot
patch directories and product startup remain unchanged.

Both fresh profiles pass actual ARM926 QEMU locally on 2026-10-04: strict mode
requires the exact protocol authentication refusal for the one-way attempt;
default mode still requires its measured acceptance. Reciprocal exchange,
wrong inbound/target response/name refusals, credential rotation, independent
RO/RW peers, retained backing and cleanup assertions pass in both modes.
Seven profile and eight result test groups, ShellCheck, workflow path checks
and the mocked wrapper's strict-cached refusal also pass. Host CI does not
execute these actual target tests.

### Exact multi-LUN set regression

Pinned LIO's `spc_emulate_report_luns` walks its ACL hlist, not a numeric sort.
The first multi-LUN fixture wrongly required ascending order and failed in the
actual guest at `multi-report-luns`. A native C regression of the exact helper
used by the client reproduces that failure before correction. Its 512 finite
pair/count vectors plus null/unsupported-selector/high-LUN checks pass afterward:
either order is accepted, but exactly two distinct expected LUNs remain required.
The actual fresh strict/default guests then pass the original full scenario,
including 4096-byte I/O, permissions and teardown. No I/O/auth check was relaxed.

```sh
sh support/tests/test-lio-lun-set.sh "$PWD"
```

This tiny native matcher test runs before local kernel compilation and in host
CI. It is not a target boot, protocol interoperability or storage authority.

This is login-time enforcement of a supplied challenge, not proof that a hostile
client verified the target response, transport encryption, existing-session
revocation, credential ownership or production backend selection. Independent
security review and product integration remain required. CHAP still uses its
protocol MD5 construction; do not describe it as confidential transport.

### Optional non-forcing disable research profile

Pinned `lio_target_tiqn_enabletpg` calls `iscsit_tpg_disable_portal_group(tpg, 1)`:
the ordinary `enable=0` command forcibly closes established sessions. The
existing force-zero path checks `nsessions` under the session lock before
closing any session and restores the previous TPG state on refusal. It first
resets login threads, however: a refused stop may interrupt **pending logins**.
This is not an entirely side-effect-free operation or a general mutation guard.

`fixtures/patches/linux-lio-idle-disable.patch` adds default-off
`CONFIG_ISCSI_TARGET_IDLE_DISABLE`, exposing a write-only `disable_if_idle`
attribute only in an explicitly selected fresh research kernel. Writing the
numeric value 1 takes the existing TPG access mutex, calls the non-forcing path
and completes core RTPI/enabled bookkeeping on success before releasing the
mutex. It returns the actual refusal error. Other values and inactive groups refuse;
there is no fallback to forced disable, automatic enable or retry. Ordinary
disable/delete, standard QEMU/EX4 kernels and product startup are unchanged.

The guarded fixture requires active-session refusal, unchanged enabled state
and a fresh read on the **same** established client before retaining the
ordinary forced-revocation test. With no sessions, guarded disable must succeed,
new login must give the exact unavailable-TPG protocol status, and explicit
re-enable must preserve the data. A short-lived portal-less second TPG must be
able to reserve the exact released RTPI. Invalid values/repeated inactive disable also
refuse. An unguarded guest requires the attribute to be absent. Pure profile,
result and wrapper tests cover both mutual modes crossed with both idle modes;
native contracts are not actual kernel/guest qualification.

Local qualification on 2026-10-05: the fresh combined strict-mutual/idle-guard
kernel passes the full actual ARM926 scenario, including all old assertions.
A fresh unpatched default kernel passes the original scenario and requires
the idle attribute to be absent. The full four-way mode matrix is covered by
native contracts, not four actual guest builds. Eight profile/nine result groups,
mocked wrapper and Linux ShellCheck/workflow contracts pass; host CI is not
actual target execution.

The first prototype stopped the iSCSI fabric but omitted core bookkeeping.
The actual guest regression reproduced `idle-core-disabled-state`: core still
reported enabled. The corrected optional helper releases the RTPI reservation
and clears core enabled only after successful fabric disable, under its access
mutex. The original assertion was preserved, not weakened. No production or
legacy firmware defect is inferred from this new research-prototype bug.

Pending-login and concurrent-writer races, multiple TPG/shared-portal behavior,
production ownership, interrupted recovery and all other mutations remain
unqualified. This research prerequisite does not complete M9.3 or select a
production kernel patch/backend. Do not use normal forced disable as a fallback
for a failed idle check.

### Reproduce locally

Seed the ordinary pinned builder/workspace and verified baseline artifacts once
using the normal QEMU build. Provide the exact upstream source archive at
`artifacts/fixture-sources/libiscsi-1.20.0.tar.gz`, downloaded from
[upstream tag 1.20.0](https://codeload.github.com/sahlberg/libiscsi/tar.gz/refs/tags/1.20.0).
Required SHA256: `6321d802103f2a363d3afd9a5ae772de0b4052c84fe6a301ecb576b34e853caa`.
The wrapper performs no downloads, image pulls/builds or volume creation.

```powershell
# Fresh verified kernel + client + actual guest, with disposable 4 GiB scratch.
.\support\test-qemu-lio.ps1 -CompileKernel

# Separate opt-in strict mutual-login kernel + actual guest; always fresh.
.\support\test-qemu-lio.ps1 -CompileKernel -RequireMutual

# Separate opt-in non-forcing disable + strict mutual-login research.
.\support\test-qemu-lio.ps1 -CompileKernel -RequireMutual -IdleGuard

# Fast iteration only if a previously verified local kernel candidate exists.
.\support\test-qemu-lio.ps1

# Pure command-boundary/profile/result tests; these do not boot a guest.
.\support\tests\test-qemu-lio-wrapper.ps1
python -B support/tests/test-qemu-lio-inputs.py
python -B support/tests/test-qemu-lio-result.py
```

The fresh mode exports nothing. The cached mode requires exactly the local
candidate convention `artifacts/lio-research/{zImage,versatile-pb.dtb,kernel.config,
SHA256SUMS,INPUTS.sha256}`; check output hashes and compile-helper/version/base
config/compiler input hashes before and after. Local retained candidate size is
approximately 4.1 MiB, not an additional Docker volume. If absent/stale, use
fresh mode rather than bypassing a checksum failure.
`-RequireMutual` without `-CompileKernel` refuses before Docker inspection;
an old/default cached candidate cannot qualify strict mode. Changes to the
compile helper invalidate its previous input manifest even for default mode.
Never rewrite a stale manifest to bypass that refusal; use a fresh compile.
`-IdleGuard` independently requires a fresh compile and refuses cached mode
before Docker inspection. The two research options may be selected separately
or together; each selects exact mandatory configuration/result evidence.

One non-root, read-only, networkless, zero-capability auto-removed container
reuses the existing workspace read-only. Cached mode has 4 GiB memory/1 GiB
tmpfs; fresh mode has 8 GiB memory/4 GiB tmpfs; both have four CPUs/512 PIDs,
a 900-second outer budget and a 180-second guest budget. All client/root snapshot
and build scratch disappears at exit. Do not edit tested source during a run.
Host CI checks only syntax, pure refusal tests and the mocked wrapper boundary;
it does not claim a target boot. These research-only paths do not rebuild the
unchanged standard QEMU or EX4 profiles automatically.

## Remaining product gates

Success would qualify only this synthetic guest backend profile. Protected
credential/registry/mount/global-use/network authority, durable transactions,
session races, legacy import, capacity/allocation modes, EX4 resource/thermal
qualification and UI activation remain separate roadmap requirements.
The actual reciprocal exchange, two-peer RO/RW isolation and inactive-session
credential rotation above are now covered locally, not product-qualified.
Still pending: product review/integration of required-mutual enforcement,
durable/live-session rotation,
active-session mutation refusal, crash/backing-loss/full-storage campaigns,
typed privileged ownership and complete release licensing. A successful forced
session teardown is not permission to revoke production clients automatically.
