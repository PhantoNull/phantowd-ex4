<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Samba restricted-root QEMU profile

This is a **test-only experiment**, not a product runtime manifest, installed
helper, activation permission or EX4 qualification. It is separate from the
generic static non-root launcher, which remains unchanged. Do not run it on
physical hardware or connect user data.

## Reproduce locally

With an existing pinned Buildroot image/workspace and manifest-verified QEMU
artifacts, run `support/test-samba-root.ps1`. The wrapper refuses missing caches;
it never builds/pulls an image or creates a named volume. Source, workspace and
base inputs are read-only; one disposable container uses bounded 512 MiB `/tmp`
and 128 MiB `/var/tmp` tmpfs. Compiler scratch is removed before the image copy.
One ARM926/VersatilePB boot is bounded to 180 seconds, without retries, guest
NICs, host ports or physical-device attachments. The base image hash must remain
unchanged. Generated images and state are destroyed when the fixture exits.
The host formats only a newly created 16 MiB regular tmpfs file as ext4 and
attaches it as a second QEMU snapshot disk. Guest PID1 requires the exact
VersatilePB guard, explicit fixture cmdline flag and expected virtual-disk size
before mounting it. No physical block-device path is formatted or attached.

## What the experiment does

- Derives non-authorizing ELF candidates for three fixed public Buildroot
  programs (`smbd`, `smbpasswd`, `testparm`) and the single fixed
  `usr/lib/samba/vfs/streams_xattr.so` module. Merging refuses conflicts, unknown
  paths, missing entries, partial graphs or asserted execution authority.
- Inside the guest, verifies every selected SHA-256 and canonical alias before
  copying regular ELFs and generating symlinks into a root-controlled tmpfs.
  The ordinary target filesystem and original image remain read-only.
- Creates only fixture-owned Unix account/group files and passdb. The profile
  uses standalone SMB3 with required signing, three separate accounts, local
  file-based NSS, no guest, DNS, AD or arbitrary includes. The only selected
  dynamic VFS plugin is hash-verified `streams_xattr`; it is not inferred from
  the executable's `DT_NEEDED` graph.
  Password setup is a disposable test setup, not the product identity Owner.
- A fixed ARM/VersatilePB-guarded native fixture creates a private mount
  namespace and restricted root. Only declared subdirectories and fixture state
  are bound into it. The runtime root is read-only; shares use
  `nosuid,nodev,noexec` and the read-only grant is verified in the kernel.
- Samba retains UID 0 for its native per-client Unix identity/group switches.
  Effective, permitted and bounding capabilities are exactly `0xdb`:
  `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `SETGID`, `SETUID`.
  Ambient/inheritable sets are zero and `no_new_privs` is set. There is no
  `SYS_ADMIN`, `SYS_CHROOT`, `PTRACE`, `SETPCAP` or network-administration grant.
  Extra FDs are closed before exec; no host directory/device handle is retained.
- The guest independently checks the live parent capability sets, NNP, root
  and distinct mount namespace. Original storage paths, `/proc` and block nodes
  are absent. A direct create on the read-only grant must return `EROFS`.
- Real SMB3 clients require writer ownership `1801:1800`, reader success,
  password/outsider denial, Unix-mode denial on a writable but root-only share,
  write denial through the kernel read-only grant, original-anchor denial and
  symlink denial with no residual files. One accented/Greek filename roundtrip
  is checked; it is not a complete encoding/normalization campaign.
- Fixed client operations have a native ten-second deadline; timeout/signal
  exits cannot count as access denials. The native wrapper accepts no arbitrary
  executable, hostname, credential pathname or SMB command.
- A real SMB alternate-stream roundtrip exercises the selected VFS plugin.
  A native bounded `lgetxattr` on one fixed fixture file checks the exact
  `user.DosStream.fixture:$DATA` bytes (including Samba's terminating NUL),
  while the ordinary file data remains unchanged. Reader and kernel-read-only
  overwrites with different payloads must be denied without changing either
  stream or file; no literal `created:fixture` file may appear. This is a small
  ext4/SMB3 plugin proof, not complete NTFS-stream migration or Windows ACL evidence.
- POSIX ACL checks now use that actual ext4 fixture, not tmpfs. The native
  test helper drops to the writer's Unix UID with zero effective/permitted
  capabilities, creates one fixed file and sets/reads back exact ACL bytes.
  Real SMB clients prove baseline denial, named-reader success, denied reader
  writes and outsider reads, then effective revocation through the ACL mask.
  The distinct original file payload must remain unchanged. This is not an
  HTTP ACL editor, Windows ACL import or a persistent/reboot ACL campaign.
- Stop signals only the fixture-created group, waits for the parent and requires
  the group to disappear. BusyBox may report the requested SIGTERM as status143;
  that is accepted only after group absence. Other outcomes fail. There is no
  stop retry or forced-success fallback, and no crash/durability claim.

## Boundaries still missing

The fixture's fixed paths, state and Unix IDs are not a production constructor
or resolver. It does not use production mount/identity Owners, persistent
transactions, process-set integration, session revocation or operator recovery.
It does not prove resistance to concurrent runtime-root replacement, all root
escape mechanisms, syscall attacks or credential/ACL migrations. A private
mount namespace plus limited root is not a security certification.

Samba's source supports configuration-selected `dlopen` modules; the pinned
target contains 39 VFS modules. This deliberately small baseline does not
qualify `acl_xattr`, Windows ACL preservation, durable stream migration,
recycle or other plugins. Only the fixed temporary `streams_xattr` case above
is exercised. The QEMU kernel now requires ext4 POSIX ACLs; the previous
disabled option was reproduced as kernel `EOPNOTSUPP` before being corrected.
The build fingerprints its fixed fragment roster and reconfigures only the
cached kernel on change, then audits required storage options before recording
the compilation checkpoint. It never treats tmpfs support as ext4 evidence.
The public target lacks the CP850 conversion module and logs an ASCII fallback;
the observed SMB3 UTF-8 case does not resolve that separate compatibility gap.
Quota observations on disposable tmpfs are not RAID/storage-health evidence.
Do not change encodings or silently relax legacy ACLs to mask missing runtime.

Next qualify the required dynamic modules/conversions and explicit configuration,
state, socket and privilege contract; construct roots from trusted pinned inputs
and Owner-held grants; then integrate service-specific supervision and recovery.
Product startup and all physical-device safety/migration/install gates remain
closed. Kernel NFS authority is a separate design, not granted by this experiment.
