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

Use the isolated kernel and a disposable snapshot of the verified root image;
start a dedicated guest init, not product services. The guest alone may use
root/configfs. Attach no data disks and disable external QEMU networking.
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

One non-root, read-only, networkless, zero-capability auto-removed container
reuses the existing workspace read-only. Cached mode has 2 GiB memory/512 MiB
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
