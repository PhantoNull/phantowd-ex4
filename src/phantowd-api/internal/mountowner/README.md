# Internal mount owner

`mountowner` is an internal M3.4 lifecycle prototype. It is not constructed by
normal product code, is not wired to the storage broker or service startup, and
has no HTTP/RPC surface. Its current real mount driver and qualification helper
exist only in `qemu_linux.go` (`qemu && linux`) and refuse machines other than
the disposable Versatile PB guest.

## Contract

- A private, one-use `Qualification` carries a transient trusted source tuple
  and a pinned `mountguard.Root`; it is not serialized or accepted from a
  request. Qualification verifies the source and captures an existing empty,
  non-mount-root target before any mount operation.
- `Owner` binds one fixed driver, observer and root opener at construction. It
  performs one bind mount, then requires the target to have a new unique mount
  ID while matching the qualified filesystem's inode, device, type, writable
  state and kernel-checked UUID before issuing a lease.
- A `Lease` opens existing directories only through the pinned mountguard.
  Returned `O_PATH` handles are tracked by the Owner and revoked when identity
  verification fails. They cannot read file contents. Draining denies new
  leases and new opens; outstanding leases must close before unmount.
- Unmount revalidates the mounted identity, closes the pinned root descriptor,
  calls the fixed unmount operation once, and succeeds only if the target has
  returned to its exact pre-mount identity and is empty. Keeping the pinned
  mount descriptor open during `umount` produced `EBUSY` in QEMU, so release is
  deliberately ordered after the last pre-unmount verification.
- Any uncertain mount/unmount result, changed identity, or failed postcondition
  transitions to `review-required`. The Owner blocks further access and does
  not retry or implicitly clean up. `Close` never unmounts.

The state machine and Linux fake-driver tests are in `owner_linux.go` and
`owner_linux_test.go`. The QEMU-only integration runs real bind mounts from the
fixed synthetic ext2 fixture into a private `/run` directory. It covers the
normal lease/drain/unmount sequence, an overmount with handle revocation, lost
mount/unmount results, and a mismatched filesystem. Teardown may unmount only
the exact private fixture target it created.

The token currently comes only from the QEMU fixture. There is no production
qualifier, mount-point allocator, durable volume identity, service handoff, or
operator review/recovery workflow. Passing QEMU tests does not qualify physical
EX4 disks or authorize mounting user media.

See [M3.4 roadmap acceptance](../../../../ROADMAP.md#m3-complete-storage-discovery-and-volume-lifecycle) and the private
dated evidence record in `doc/sources/m34-owner-lifecycle-local-qemu-2026-09-30.md`.
