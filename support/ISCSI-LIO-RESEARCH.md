# M9.1: disposable LIO qualification

This is a research contract, not a selected production backend or an installer.
The approved scope is ARMv5 QEMU, one synthetic 32 MiB backing and a loopback
initiator. No NAS, physical device, host port forwarding or product activation.

## Source findings

The pinned Linux version in `versions.env` contains LIO/FILEIO. The current
QEMU kernel does not enable `TARGET_CORE`, `CONFIGFS_FS` or `ISCSI_TARGET`.
Architecture-independent Kconfig eligibility is not ARMv5 runtime qualification.

In `drivers/target/target_core_file.c`, `fd_configure_device` calls `filp_open`
with `O_RDWR | O_CREAT | O_LARGEFILE | O_DSYNC`. Missing backings can therefore
be created. Its control parser also splits on commas/newlines; desired backing
paths must never be interpolated directly into that interface. FILEIO initially
uses 512-byte blocks; the model's 4096-byte option remains unqualified.

`target_dev_enable_store` calls `target_configure_device`, which calls the
backend's `configure_device` directly. A retained `/proc/self/fd/N` binding is a
candidate for the fixture, not yet a proven safe product handoff. Opening a
descriptor read-only is not writable storage authority: FILEIO reopens it RW.

In `iscsi_target_configfs.c`, authentication attributes require `CAP_SYS_ADMIN`.
Their show functions return credentials; never recursively dump configfs.
Store treats an uppercase `NULL` prefix as unset. A future backend adapter must
reject reserved values before use, independently of the generic desired model.
Credentials, daemon/portal state and active sessions need their own typed owner.

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
and an auto-removed non-root container. It retains output only in that tmpfs.
It checks the final configuration, hashes kernel/config/DTB, and verifies source
archive/base configuration are unchanged. This lane is not the normal QEMU
kernel, a release build, SBOM regeneration or an EX4 board change.
The existing baseline mounts its ext2 root using the ext4 driver; the audit
requires that existing driver, not a newly enabled separate ext2 driver.

Local qualification on 2026-10-04: ShellCheck and six Windows/Linux profile
test groups pass; the fresh-source ARMv5 kernel compile succeeds using the
pinned existing toolchain. Source/config inputs remain unchanged and scratch
uses 1.9 GiB before the ephemeral container exits. The guest has **not** booted
this kernel and no target/client or credential test has run. Kernel outputs
are discarded with scratch, not published or reused as release artifacts.

Run the fast profile tests independently:

```powershell
python -B support/tests/test-qemu-lio-inputs.py
```

The compile helper's five arguments are: read-only checkout, pinned Linux
archive, existing QEMU `.config`, existing Buildroot `host` directory, and a
fresh empty tmpfs output directory. Use `sh` to invoke it inside the bounded
builder; do not run it against a writable persistent build cache. Its success
marker explicitly says `guest=false activation=false`.

## Increment B: actual target and initiator fixture (pending implementation)

Use the isolated kernel and a disposable snapshot of the verified root image;
start a dedicated guest init, not product services. The guest alone may use
root/configfs. Attach no data disks and disable external QEMU networking.
Only explicitly allowed initiators on guest loopback may log in. Use fixed
synthetic secrets, never operator credentials; redact auth diagnostics.

Qualify an upstream initiator rather than implementing the wire protocol.
Buildroot's pinned libiscsi 1.20.0 is a client candidate (GPL-2.0+/LGPL-2.1+),
but its default recipe disables examples/test tools. Its source and license
hashes, actual build options and the test client's license must be recorded.
Do not add the Python targetcli management stack merely to write fixed configfs
attributes; resource efficiency of a native adapter is still unmeasured.

Required independent assertions:

- Good CHAP succeeds; wrong/missing credentials and foreign initiator fail.
- Explicit RO mapping denies writes; RW mapping reads back exact synthetic data.
- Unlink/rename/replace the original pathname after retaining its descriptor:
  kernel I/O must still reach the admitted object, never its replacement.
- Missing/closed descriptors fail without creating any replacement backing.
- Check actual capacity/block size, write-cache policy and target state.
- Exercise active session refusal, disconnect, teardown and re-enable identity.
- Verify no listener outside loopback, no copied credentials in logs, no leaked
  target objects/sessions and unchanged base artifacts after exit.

Use strict bounded timeouts and mandatory markers. Any uncertain cleanup fails;
no retries, silent recreation or reuse of a partially configured target.

## Remaining product gates

Success would qualify only this synthetic guest backend profile. Protected
credential/registry/mount/global-use/network authority, durable transactions,
session races, legacy import, capacity/allocation modes, EX4 resource/thermal
qualification and UI activation remain separate roadmap requirements.
