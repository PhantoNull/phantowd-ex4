# Typed native identity executor (Linux)

This is the command backend for journaled creation of a reserved native Unix
account and its same-number private primary group. It replaces the raw command
construction in the guarded ARMv5 fixture. It is not a privileged daemon,
authorization boundary, LAN API or complete account-management service.

`Open(account)` requires real/effective UID 0 and one valid disabled native reservation. The
object is permanently bound to its full ID/name/UID/GID/state. It accepts only
`Observe`, `CreateGroup`, `CreateUser` and `Close`. There is no public executable,
argument list, directory, password, shell, deletion or ownership-change option.

The binary is always `/bin/busybox`: a regular root-owned executable ELF,
without symlinks, extra hardlinks, group/other write, setgid or sticky bits.
The pinned Buildroot BusyBox is root:root 4755: setuid-root is accepted only for
that ownership and an already-root caller, with real/effective UID rechecked
before dispatch. It is not a privilege-elevation mechanism for the web API.
`openat2` is mandatory. O_PATH classification precedes any read, so special
files are never opened for I/O. A retained read descriptor is executed as child
FD 3 with a fixed `busybox` argv[0], not through an applet symlink, PATH lookup
or replaceable executable name. Metadata is rechecked before and after use.
The firmware image and parent directories must be trusted; this is not binary
signature verification or protection against a malicious root writer.

Each command freshly observes protected local files. Group creation requires
complete absence; user creation requires exactly the matching group and no
user. Post-command observations must match the expected partial/complete state.
The user vector fixes `-D -H -s /sbin/nologin`: no interactive password command,
no home creation, no caller-selected shell or supplementary groups. The ARMv5
integration additionally checks the generated guest's locked shadow entry,
nologin shell and absent home. Generic identity observations alone do not prove
these login properties or Samba credential readiness.

The runner has a fixed minimal environment and `/` working directory, no stdin,
a five-second cancellation deadline and a private process group. Cancellation
signals that group and waits for the direct child. Output is discarded under a
16 KiB total limit; neither arguments nor child diagnostics are returned/logged.
No shell is launched. Uninterruptible kernel I/O can delay reaping: the timeout
is not a hard wall-clock or power-failure guarantee. This is not an adversarial
process sandbox or a general descendant supervisor.

An instance admits only one operation without queuing. That mutex does **not**
serialize other executor instances, Unix tools, the registry or storage changes.
The eventual privileged owner must retain a global cooperative writer authority,
qualified durable `/etc` and registry/journal storage, complete allocation
exclusions and a reviewed recovery policy. The API must remain unprivileged.
No production caller currently opens this executor; the only wiring is a
machine/disk/account-guarded disposable QEMU scenario. That scenario now uses
the [local identity channel](../identityrpc/README.md) from a separate
unprivileged client; production listener/global ownership remain unimplemented.

Use it behind [identityprovision](../identityprovision/README.md), which commits
intent before dispatch and never blindly repeats an uncertain command. **Any
command error may follow a mutation.** No rollback, automatic replay, adoption,
password provisioning or service activation is provided. A success is a bounded
observation, not an authorization lease against later account changes.

Host tests use modeled identity files and a Go test subprocess, never real
host account creation. They check exact vectors, immutable binding, invalid
identities, pre/postconditions, busy/closed/cancelled requests, executable-file
policy, sanitized environment, output overflow, exit failures and timeout.
The real BusyBox invocation is qualified only in the guarded ARMv5 fixture.
