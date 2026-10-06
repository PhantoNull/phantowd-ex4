# Private SMART descriptor-generation witness

Linux-only M8.5b prerequisite, not a command/device provider. `Retain` borrows
an already opened `O_RDONLY` block descriptor, creates its own CLOEXEC duplicate
under `SyscallConn.Control` and checks device type, access flags, major/minor and
`BLKGETDISKSEQ`. Closing the caller's descriptor does not close that duplicate.
It accepts no path, reads no content, sends no transport command and changes no
capability. There is no HTTP/RPC, broker integration or normal startup call.

`Check` revalidates that same retained descriptor. A failed observation keeps
the duplicate in permanent review; restoration cannot resume the handle.
Operations refuse concurrent use and value copies. `Close` explicitly releases
only this duplicate; no child/command uses it and this is not a capture Owner.
The witness exposes neither a descriptor nor serialized identity evidence.

Matching generation is transient evidence, not stable media identity, topology,
whole-disk status, current pathname identity or command authorization. The
trusted caller must independently qualify complete leaf discovery and reconcile
the entire census. BLKGETDISKSEQ may also succeed on a partition: only the
validated whole-leaf census can establish that prerequisite. A shared file
description can change status flags; each Check revalidates access/O_PATH.
Context checkpoints do not interrupt an uninterruptible kernel ioctl. No
physical standby, transport support or hot-unplug behavior is established.

Native tests cover observation predicates, real non-block refusal, caller
ownership, copies/busy/cancellation, review and explicit release. The opt-in
QEMU MD fixture checks actual generation ioctls against its already-active
temporary members, wrong expected sequence, caller close and sticky review.
Review drift is an intentionally modified expected tuple, not physical hotplug.
Its root fixture does not qualify least-privilege product deployment.
