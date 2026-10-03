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
  `usr/lib/samba/vfs/streams_xattr.so` module plus the fixed glibc
  `usr/lib/gconv/IBM850.so` converter. Merging refuses conflicts, unknown
  paths, missing entries, partial graphs or asserted execution authority.
- Inside the guest, the QEMU-only staging prototype makes fresh exclusive
  regular-file copies, verifies selected SHA-256 during copying and generates
  direct symlinks from the fixed plan into a new root-controlled tmpfs tree.
  It refuses symlink/cross-mount source traversal, occupied destinations,
  writable sources and cancellation. Hash-failed files remain non-executable
  under a private root, and incomplete trees cannot be resumed. Neither shell
  copying nor source xattrs/ACLs/hardlinks are used to construct the code tree.
  The bounded conversion catalog is separately validated against exactly four
  IBM850 aliases and two conversion rows, then SHA-256 verified with the runtime.
  Additional modules, relative module paths, duplicates or missing rows fail.
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
- A dynamic glibc probe executes inside that same restricted root under the
  fixture launcher. It checks exact non-ASCII CP850/UTF-8 bytes in both directions
  for IBM850 and all four catalog aliases. Unrepresentable, malformed and
  truncated UTF-8 must fail without substitution. Samba explicitly uses CP850
  and UTF-8, and converter-error/ASCII-fallback logs fail the fixture. This adds
  no SMB1 support or weaker protocol setting. The probe is test-only, not
  installed by the product packages or a proof of complete legacy-name migration.
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
- A second fixed subtree has exact access/default POSIX ACLs created by the
  writer UID with zero effective/permitted capabilities. Real SMB creates a
  child directory and file; native readback requires owner/group `1801:1800`,
  setgid directory mode `2750`, file mode `0640`, exact directory access/default
  ACL bytes and the file's mode-limited inherited access ACL. The reader can
  retrieve the file but cannot overwrite it with different bytes or create a
  directory; the outsider cannot read or create. Metadata and data remain
  unchanged after denial. This is one synthetic inheritance policy, not an ACL
  editor, all inheritance combinations, legacy import or reboot qualification.
- The profile explicitly stores DOS attributes and disables archive/system/
  hidden-to-Unix-execute-bit mapping. The pinned default archive mapping was
  reproduced as file mode `0740`; disabling it produces the required `0640`
  without relaxing the ACL. SMB `allinfo` still reports archive `A (20)`.
  This proves only that one attribute case, not complete Windows metadata.
- Pinned `smbclient` can exit zero after printing a denied `mkdir`. Only two
  fixed reader/outsider mkdir cases use a separate evidence rule: status 0 or 1,
  exactly the expected NT access-denied line and no created directory. Timeout,
  signal, other errors, duplicate/mismatched lines or an existing target fail.
  Other denial checks still require status 1. Linux shell contracts and the real
  ARMv5 guest both exercise the exception; it is not product error handling.
- Stop signals only the fixture-created group, waits for the parent and requires
  the group to disappear. BusyBox may report the requested SIGTERM as status143;
  that is accepted only after group absence. Other outcomes fail. There is no
  stop retry or forced-success fallback, and no crash/durability claim.

## Boundaries still missing

The separate internal code-only runtime inspector checks the prepared fixture
tree before configuration/state/grants are added: complete census, exact
hashes/permissions/direct aliases and a read-only unique mount identity. Its
fixed QEMU probe runs with non-root credentials and zero capabilities and
refuses five altered plans. This is point-in-time read-only evidence, not an
approved product manifest, retained lease or trusted root constructor. See
the [contract](../src/phantowd-api/internal/runtimebundle/README.md).

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
The previous public target lacked CP850 and logged an ASCII fallback; direct
ARMv5 conversion reproduced `iconv_open: Invalid argument` in the isolated root.
The QEMU defconfig now selects Buildroot's standard glibc converter installation
with only `IBM850`, not the entire converter collection. Full local new-config
integration on `b7e06b4` verifies the actual target installation, regenerated
rootfs and package/legal/SBOM steps. Full local combined integration on
`41c90c9` also passes the inherited ACL/mode/DOS-attribute checks, standard/MD/
two-boot guest tests and all prior loader/Samba cases without manual converter
injection. Rebasing onto merged PR #55 retained the complete source tree as
`bedfec4`. These runs reuse source/compiler caches, so they are not independent
clean-build reproducibility or hosted feature qualification.
Quota observations on disposable tmpfs are not RAID/storage-health evidence.
Do not change encodings or silently relax legacy ACLs to mask missing runtime.

Next qualify the required dynamic modules/conversions and explicit configuration,
state, socket and privilege contract; construct roots from trusted pinned inputs
and Owner-held grants; then integrate service-specific supervision and recovery.
Product startup and all physical-device safety/migration/install gates remain
closed. Kernel NFS authority is a separate design, not granted by this experiment.

## Next Owner integration packet (proposed, not qualified)

Implement a separate internal Samba-specific Owner; do not broaden the generic
static/non-root adapter. The new privileged composition requires its own
explicit host/QEMU decision before running it. Existing separate fixture passes
do not qualify the composition, product boot, HTTP activation or user disks.

### Construction and retained resources

- Fix the backend, launcher, daemon, arguments, readiness/stop budgets and
  protected roots once at construction. No operation accepts replacements,
  arbitrary paths, executable selection, credentials or a new backend.
- Use the trusted expected code roster, including loader, selected NSS/VFS
  modules and conversion catalog; dependency-only ELF observations and hashes
  measured from an untrusted tree are not manifest authority. Retain independent
  descriptors and original inode/mount identities for the complete code tree.
- Separate the **code-only inspection root** from the composed service root.
  `runtimebundle.Inspect` requires a complete exact census: adding passwd,
  configuration, state or grant entries to that inspected tree invalidates it.
  Do not skip undeclared entries or weaken that inspector. Independently verify
  the declared read-only code views inside the composed root, then bind the
  explicit protected configuration, mutable state and descriptor-bound grants.
- Define a bounded exact roster for configuration/NSS inputs and state roots;
  code hashes alone do not qualify either. Treat legitimate state mutations
  separately from code/configuration drift. Passdb and identity revision must
  belong to the identity authority, not fixture password setup or self-discovery.
- Retain configuration, state and storage authority through confirmed group
  stop/reap. Construction failure publishes nothing: discard the fresh partial
  root, never resume it, adopt an old daemon or reuse an uncertain tree.

### Native execution boundary

- Preserve one owner of PID/process-group creation. The Go Owner starts its
  child with `Setpgid=true`; the current standalone server helper calls
  `setsid()`. A process-group leader cannot perform that call (the native
  disposable probe returned `EPERM`). Do not compose these unchanged. A separate
  fixed owned-group entry must verify `PID == PGID`, preserve it through exec
  and never detach into an unowned session. Leave standalone fixture behavior
  intact; no PID-only shutdown or arbitrary group selection.
- The fixed bootstrap helper, not the multithreaded Go parent, creates the
  private namespace/restricted root. Bootstrap authority is distinct from the
  daemon's six-capability profile: namespace/chroot preparation needs privileges
  the final daemon explicitly lacks. Do not claim the final `0xdb` observation
  proves that a six-capability parent can perform bootstrap.
- Before daemon exec, close original-root/device/grant escape descriptors,
  verify the fixed diagnostic pipe boundary and reset inherited signals. Verify
  exact effective/permitted/bounding `0xdb`, zero inheritable/ambient sets,
  UID0 and NNP. Retain distinct per-client Unix identities; never use `force user`,
  shared credentials, SMB1, guest access or widened permissions to obtain a pass.
- The final service root permits only declared code/configuration/state/grants
  and explicitly reviewed device nodes. The existing fixture has null/entropy
  nodes, not arbitrary block devices, `/proc` or original storage paths.
  Original anchors and undeclared shares must be unreachable; read-only grants
  must reject actual kernel writes, independently of Samba configuration.

### Lifecycle and acceptance evidence

1. Admission rejects missing/incomplete inputs, mutable spec replacement,
   invalid privilege/profile/FD state and canceled context without launching.
2. Readiness exercises real SMB authentication and writer/reader/outsider Unix
   permissions. A listener, pre-exec marker or successful `testparm` is not ready.
3. Revalidation covers retained code, protected configuration, identity freshness
   and grants. Drift/source loss stops the known group before resource release;
   restored bytes never clear review or trigger automatic restart.
4. Normal stop proves owned parent reap and complete group absence before release.
   Forced/uncertain stop requires review and retains resources until an explicit
   absence verification; no adoption, lazy unmount, signal replay or retry-to-green.
5. Test at least constructor refusal, caller-FD close survival, immutable inputs,
   duplicate start, distinct-account readiness/denials, normal stop, unexpected
   exit, forced-stop review, live code/configuration/source drift, restoration
   refusal and attempted close while live. Use one disposable guarded QEMU root
   and storage fixture; verify original base hashes and resource cleanup.

These are implementation/acceptance requirements, not completed tests. Product
configuration transactions, durable review/recovery, identity/storage authority,
HTTP authorization, installation and EX4 safety remain separate release gates.
