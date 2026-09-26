# Qualified-mount descriptor guard (Linux)

This package retains a previously qualified mount and resolves directory
descriptors on it. It checks the mounted filesystem UUID through a read-only
kernel ioctl. It does not discover unmounted volumes, prove
uniqueness/compatibility, check user permissions, mount/unmount filesystems or
activate services. There is no HTTP route for it.

## Required caller contract

A future trusted volume/lifecycle component must first establish the intended
filesystem and its compatibility, then supply the expected **unique mount ID**,
root inode, device major/minor and filesystem magic in the current mount
namespace/kernel. These values must not come from an HTTP client or simply be
learned from whatever directory happens to occupy the desired path.
`FilesystemUUID` must separately come from the intended volume in trusted
desired policy: canonical lowercase, nonzero, 128-bit UUID text is required.
`RequireWritable` additionally rejects read-only mounts. Filesystem magic is
an identity comparison, not an approved-filesystem list or integrity check.

The unique ID is `STATX_MNT_ID_UNIQUE`, not the recyclable mountinfo ID.
Do not persist this tuple as stable disk identity, reuse it after reboot or
share it across namespaces. Filesystem UUID collision detection, WD layouts
and permission qualification are separate prerequisites that remain unfinished.

The expected UUID is compared with `FS_IOC_GETFSUUID` from a safely reopened
directory descriptor on the pinned mount, not a path name, label, device name,
udev symlink or blkid cache. The read-only ioctl returns the kernel's external
filesystem UUID; it does not prove on-disk integrity or uniqueness. Clones can
have the same UUID. No block device is opened, filesystem mounted, directory
listed or data file read. Zero or non-128-bit replies and unsupported ioctls
fail closed. The metadata descriptor is reopened with O_NOATIME, requiring
appropriate ownership/capability; there is no weaker retry or privilege gain.

## Operations

- `Open(anchor, expected)` opens a canonical non-root absolute directory with
  `openat2`, rejects symlinks in all components, and checks the expected tuple,
  directory type, mount-root attribute and expected filesystem UUID. It retains
  an `O_PATH` descriptor; the temporary read-only ioctl descriptor is closed.
- `Verify()` reopens the named anchor and compares its identity/state and the
  retained descriptor, including the expected UUID. A missing mount,
  replacement or changed writable state
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
The UUID ABI and generic read-only implementation are defined in Linux
[fs.h](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/fs.h)
and [ioctl.c](https://github.com/torvalds/linux/blob/v6.18/fs/ioctl.c); the same
definitions were checked in the project-pinned Linux 6.18.53 build sources.

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
unsafe path refusal, UUID syntax/byte order/width, unsupported procfs UUID,
real descriptor resolution and closed-state concurrency.
Mount-changing tests run only in guarded ARMv5 QEMU on the fresh synthetic
data disk. It verifies the actual kernel-returned UUID against the fixture's
known mkfs UUID and rejects a different expected UUID. The fixture uses private
bind mounts to test symlink refusal,
same-filesystem nested-mount refusal, read-only transitions, same-device/root
overmount replacement and refusal to fall back after unmount. Ordinary
unmounts must succeed after references close; no lazy/forced unmount is used.
This does not qualify physical EX4 storage, arbitrary mount races or migration.
