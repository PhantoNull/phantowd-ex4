# Internal process owner

`processowner` is a Linux-only primitive for one foreground child process. It
is not a product service manager and is not reachable over HTTP or RPC.

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

Diagnostics and snapshots are internal, non-serializable data. Diagnostics
may contain paths or account names and must not be logged or returned to a
network client without a separate redaction boundary. Non-Linux builds return
`ErrUnavailable`.

This primitive has no adoption of pre-existing processes, durable state,
automatic recovery, aggregate SMB/NFS lifecycle, last-known-good configuration
transaction, or production startup wiring. Host unit tests exercise unexpected
exit/quarantine and forced-stop cleanup. The one-boot ARMv5 QEMU smoke exercises
normal ownership of disposable `smbd` plus two controlled BusyBox children: one
exits unexpectedly and one ignores `SIGTERM` until bounded forced termination.
Both guest cases require `review-required`, blocked restart and a reaped process
group. They do not simulate a real `smbd` crash or forced termination of `smbd`.
