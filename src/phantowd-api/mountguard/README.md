# Qualified-mount descriptor guard (Linux)

This package retains a previously qualified mount and resolves directory
descriptors on it. It does not discover volumes, read filesystem UUIDs, prove
uniqueness/compatibility, check user permissions, mount/unmount filesystems or
activate services. There is no HTTP route for it.

## Required caller contract

A future trusted volume/lifecycle component must first establish the intended
filesystem and its compatibility, then supply the expected **unique mount ID**,
root inode, device major/minor and filesystem magic in the current mount
namespace/kernel. These values must not come from an HTTP client or simply be
learned from whatever directory happens to occupy the desired path.
`RequireWritable` additionally rejects read-only mounts. Filesystem magic is
an identity comparison, not an approved-filesystem list or integrity check.

The unique ID is `STATX_MNT_ID_UNIQUE`, not the recyclable mountinfo ID.
Do not persist this tuple as stable disk identity, reuse it after reboot or
share it across namespaces. Filesystem UUID collision detection, WD layouts
and permission qualification are separate prerequisites that remain unfinished.

## Operations

- `Open(anchor, expected)` opens a canonical non-root absolute directory with
  `openat2`, rejects symlinks in all components, and checks the expected tuple,
  directory type and mount-root attribute. It retains an `O_PATH` descriptor.
- `Verify()` reopens the named anchor and compares its identity/state and the
  retained descriptor. A missing mount, replacement or changed writable state
  cannot quietly become a directory on the system filesystem.
- `OpenDirectory(relative)` revalidates the anchor then resolves an existing
  directory relative to the retained descriptor. `RESOLVE_BENEATH`,
  `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_XDEV` reject
  traversal, links and nested mounts, including binds of the same filesystem.
  The result is a caller-owned `O_PATH` file that must be closed; it does not
  read or write file contents. `.` means the mount root.
- `Close()` releases the guard; repeat close and zero-value close are safe.
  Methods are serialized, but the object must not be copied.

Unsupported syscalls, absent required statx masks/attributes and resolution
errors fail closed. There is no `realpath`/ordinary-open fallback. The intended
target kernel is the project-pinned modern Linux; this is not stock EX4 Linux
3.2 compatibility code. See the upstream [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html)
and [statx](https://man7.org/linux/man-pages/man2/statx.2.html) contracts.

## Important limits

Checks are point-in-time observations. Opened descriptors pin the original
objects; they do not automatically revoke when the namespace changes. A
directory can be renamed after it is opened. The eventual activator must own
the mount lifecycle/namespace, retain and safely hand off these references,
and revoke services on storage loss. It must not throw away the descriptor
and hand a newly resolved, unchecked textual path to Samba/exportfs. That
service handoff/lifecycle is not implemented by this package.

Only directories are resolved. No data-file API, recursive permission change,
UID mapping, authentication, ACL management or privileged RPC is added.
An `O_PATH` descriptor is a reference, not proof that an SMB/NFS user can read
or write beneath it.

## Tests

Linux host tests exercise identity masks/tuple matching, read-only logic,
unsafe path refusal, real descriptor resolution and closed-state concurrency.
Mount-changing tests run only in guarded ARMv5 QEMU on the fresh synthetic
data disk. The fixture uses private bind mounts to test symlink refusal,
same-filesystem nested-mount refusal, read-only transitions, same-device/root
overmount replacement and refusal to fall back after unmount. Ordinary
unmounts must succeed after references close; no lazy/forced unmount is used.
This does not qualify physical EX4 storage, arbitrary mount races or migration.
