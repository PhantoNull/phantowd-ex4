# Desired share-policy storage (Linux)

This library persists the [versioned share policy](../shareconfig/README.md).
It is not connected to HTTP endpoints, account provisioning, volume mounting,
service configuration or the EX4's persistent flash. The QEMU probe uses only
a newly created temporary directory, which it removes after the test.

## Contract

- The caller supplies an absolute, clean path to an existing 0700 directory owned by the effective
  UID, under trusted parents on a local filesystem. The store does not create,
  chmod, relocate or choose that directory. Provisioning and its parent sync
  are outside the library. Do not use network filesystems or a shared directory.
- One directory-descriptor `flock` is held for the store lifetime; a second
  opener is refused immediately. The mutex also serializes goroutines.
  The directory must not be replaced or modified by other writers. Advisory
  locks do not defend against root or another process using the same UID.
- Fixed filenames are opened relative to the retained directory descriptor.
  Symlinks, special files, hard-linked current files, wrong permissions and
  excessive input are refused. Parent path trust remains the caller's duty.
- `Load` distinguishes absent configuration, corruption and storage errors.
  Corruption is never converted into an empty appliance configuration.
- `Commit(expected, next)` requires `next.revision == expected + 1` and the
  current revision to match. Expected zero initializes only absent state.
  Every saved document must pass the bounded decoder as well as validation.
- A commit writes a reserved 0600 pending file, syncs and closes it, renames it
  over the current file, then syncs the directory. Ordinary pre-rename failure
  does not publish the pending file. At most one pending entry is retained.
  On retry, only a regular, private, singly linked reserved pending file is
  discarded; it is never promoted as recovery state.
- A rename error or failure after rename returns `ErrUncertain` and poisons further use of that
  instance. Close/reopen, inspect the loaded revision and reconcile before any
  retry or service activation. Reopening validates and syncs current state and
  the directory; it does not claim which revision survived a power loss.

The file and directory sync requirements follow Linux
[`fsync(2)`](https://man7.org/linux/man-pages/man2/fsync.2.html). Lock semantics
follow [`flock(2)`](https://man7.org/linux/man-pages/man2/flock.2.html).

## Evidence and remaining gates

Linux tests cover initialization/reopening, stale writers, goroutine races,
exclusive open, invalid files, abandoned pending state, partial writes and
injected ENOSPC/EIO at write/sync/close/rename boundaries. A subprocess exits
before rename without cleanup; reopening confirms lock release and preservation
of the prior revision. These are software fault tests, **not power-cut tests**.

The ARMv5 QEMU smoke checks revision commit/reopen and lock/conflict behavior
in temporary guest storage. It does not prove reboot persistence, EX4 flash
durability, controller write-cache behavior or media-failure recovery. A
filesystem-qualified crash/power-loss matrix, chosen product state location,
backup/recovery policy and schema migration remain required. There is no
automatic fallback to an older revision and no compatibility importer yet.
