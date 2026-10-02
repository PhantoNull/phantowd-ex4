# Internal process owner

`processowner` provides Linux-only owners for foreground process groups and a
fixed, ordered set of such processes. It is not a product service manager and
is not reachable over HTTP or RPC.

The caller supplies a fixed executable, arguments and bounded readiness/stop
timeouts. The owner opens a regular executable without following symlinks,
starts it in its own process group with a minimal environment, captures a
bounded 32 KiB diagnostics tail, and reports `ready` only after the supplied
probe succeeds. The probe must be service-specific, bounded and must not
re-enter the same owner.

`Observe` does not start, stop, adopt or restart a process. If a process that
previously reached readiness has exited, observation moves the owner to
`review-required`; a new start is blocked. `Stop` performs bounded graceful
shutdown and may force termination; uncertain or forced cleanup also requires
review. Generation advances only after readiness is confirmed.

`NewSet` constructs private Owners from copied, fixed `MemberSpec` values. It
starts members in declaration order and advances the set generation only when
all readiness probes succeed. If a later member fails, already-ready members
are stopped in reverse order; if the failed member or rollback is uncertain,
the set enters permanent `review-required`. An observed unexpected exit also
quarantines set restart but does not automatically stop healthy peers. An
explicit `Stop` attempts cleanup of every member in reverse order and never
clears review. Set and member snapshots reject JSON serialization. This
provides startup/cleanup coordination only; it does not apply configuration,
hold storage leases, persist state, adopt existing daemons, or decide whether
SMB/NFS may remain partially available.

Diagnostics and snapshots are internal, non-serializable data. Diagnostics
may contain paths or account names and must not be logged or returned to a
network client without a separate redaction boundary. Non-Linux builds return
`ErrUnavailable`.

The package has no adoption of pre-existing processes, durable state,
automatic recovery, aggregate SMB/NFS configuration lifecycle, last-known-good
configuration transaction, or production startup wiring. Host tests exercise
unexpected exit/quarantine, forced-stop cleanup, failed-start review
persistence, reverse-order set rollback, all-ready set shutdown, immutable
arguments, and member-level quarantine that preserves a healthy peer until
explicit stop. The one-boot ARMv5 QEMU smoke exercises normal ownership of
disposable `smbd`, three controlled BusyBox failure cases, and a two-member
BusyBox Set for successful start/stop, rollback, unexpected exit, peer
preservation and explicit cleanup. All guest fixtures require process groups
to be reaped. They do not simulate a real `smbd` crash or forced termination
of `smbd`.
