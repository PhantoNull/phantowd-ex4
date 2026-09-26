# Local identity operation channel (Linux)

This library connects an unprivileged caller to one **already reserved and
journaled** native identity operation. It is not a deployed `privd`, a general
account API or a deployed socket service. Production HTTP does not open it.
The guarded ARMv5 scenario now uses it for actual group/user creation through
[identityprovision](../identityprovision/README.md) and
[identityexec](../identityexec/README.md).

## Contract

The root owner constructs `New(apiUID, journal, loadRegistry, backend)` with
trusted in-process dependencies. UID 0 is forbidden as the API principal;
real and effective root are required for the owner. Every accepted connection
must be an AF_UNIX stream. Both sides inspect kernel `SO_PEERCRED`: the owner
requires its configured API UID, the client requires root. An unauthorized
peer is disconnected before request parsing or state observation.

`NewOperation(apiUID, operation)` instead accepts a trusted bound operation from
the [native identity owner](../identityowner/README.md), which serializes its
ledger and Unix changes inside Step. Load is not a lock/authorization lease.
The original New adapter remains a lower-level primitive for already-owned
journals; it does not acquire the authority's lease by itself.

Each connection carries exactly one four-byte big-endian length followed by
one strict JSON request (1..1024 bytes), then one equally bounded response.
All four request and response fields are mandatory; version is exactly 1.
Duplicate/unknown/case-variant keys, nulls, invalid UTF-8/surrogates, nested
objects, trailing JSON and invalid actions/revisions are refused. Subsequent
frames are never dispatched: the connection closes after the first response.

```json
{"version":1,"action":"step","account_id":"example","revision":1}
```

Only `status` (revision 0) and `step` (positive expected journal revision)
exist. The symbolic account ID must match the bound journal. The client cannot
select UID/GID, names, paths, binaries, arguments, passwords, storage or a
backend. `step` reloads the trusted registry and delegates exact revision and
account checks to the journal before any native command. There is no Begin,
reset, rollback, delete, adoption, repair or arbitrary execution operation.

Successful replies carry a validated journal phase/revision. Other codes are
only `busy`, `conflict`, `review`, `unavailable` or `invalid`, with no backend
diagnostics, credentials or raw input. `status` reads the durable journal; it
does not prove current Unix/Samba state or service readiness. `ok` can describe
a review-required journal when reading status; it is not activation permission.

The server admits one connection without queuing per instance, before reading
its body. Both ends own/close the supplied socket, enforce a ten-second context
and I/O deadline, and close blocked I/O on cancellation. This is not a hard
bound on kernel storage stalls or uncooperative trusted backends. The listener
owner must bound accept/goroutine counts separately, or use `Listen` below.

Overload now closes without attempting a structured busy reply. Closing before
consuming a request can reset unread peer data or precede its write; a reply
cannot reliably be delivered in that ordering. The server returns local ErrBusy,
the client reports channel unavailability and never retries automatically.

**No automatic retry.** A lost reply, timeout or cancellation can follow a
committed native mutation. Read status through a new authenticated connection
and reconcile. Never translate a transport failure into a fresh operation or
erase an intention record. A stale revision cannot repeat a confirmed command;
an interrupted intention remains subject to the journal's review requirement.

## Protected listener lifecycle

`Listen(directory, apiGID, server)` is an opt-in Linux lifecycle primitive.
The caller pre-provisions an exact root:apiGID 0710 directory with trusted
parents and a dedicated non-root API group. No directory is created, repaired
or recursively removed. `openat2` refuses symlinks/magic links; a retained
directory descriptor and advisory lifetime flock identify the cooperating owner.
The fixed `channel` socket is root:apiGID 0620, single-link, on that filesystem.
Binding through the retained descriptor does not change process cwd or umask.
The server still requires its exact API UID through `SO_PEERCRED`; possession of
the filesystem group alone does not authorize requests.

Only an exact expected socket is eligible for stale-name recovery. A nonblocking
connect probe must return ECONNREFUSED, followed by a second metadata/inode
check, before unlink. Files, symlinks, foreign/malformed/hardlinked sockets,
live listeners and all ambiguous errors are preserved. The probe sends no
request. This follows Linux [pathname-socket](https://man7.org/linux/man-pages/man7/unix.7.html)
and [connect](https://man7.org/linux/man-pages/man2/connect.2.html) semantics;
ECONNREFUSED alone is not sufficient without the type/ownership checks.

`Run(ctx)` starts once, with at most four connection workers and a listen
backlog of eight (Linux may queue one extra). Overflow closes without parsing;
kernel backlog saturation can refuse connection with EAGAIN. There is no
userspace request queue or automatic retry. Socket/directory metadata is
rechecked after accept. `Close` or cancellation stops accepting, cancels active
connections and waits for every worker **before** releasing the socket and
directory lease. Only then may the caller close the bound identity authority.
Uncooperative trusted backends/kernel stalls can delay shutdown; no hard drain
deadline is promised. Close before Run, repeated Close and concurrent Run/Close
are supported. Cleanup checks the captured socket inode and permissions and
preserves replacement names instead of following them.

The pathname must remain within trusted, stable parents. Other root tools must
not move/replace its directory or manipulate that socket. This is cooperative
ownership, not protection against an adversarial root or a differently named
authority. Client connection paths remain trusted deployment configuration;
the client always verifies a root peer. No product daemon, auto-start, runtime
directory provisioning or general multi-account routing is installed here.

## Trust and remaining integration

`SO_PEERCRED` identifies connection-time credentials, not the executable or
the current holder of a delegated descriptor. Use a dedicated service UID,
trusted processes in the same intended user namespace, no socket delegation,
and a root-owned protected listener directory/path. Do not share the API UID
with applications or assume this authenticates individual browser users.
See the upstream [Unix socket credential semantics](https://man7.org/linux/man-pages/man7/unix.7.html).
The protocol uses ordinary reads and accepts no descriptor-passing API.

The caller must retain one global cooperative identity writer authority across
registry/Unix/journal operations and own qualified durable state and recovery.
This per-instance admission mutex is not that authority; identityowner now
coordinates one configured authority's cooperative writers. Other root tools and
other server instances are not serialized. The in-process dependencies and
their lifetimes are trusted; do not close/change them during service use.
Production listener deployment, complete allocation exclusions, durable Unix
layout, recovery UI, HTTP authorization-to-operation binding and Samba password
coordination remain unimplemented. No production listener or LAN access is
enabled by this package.

## Verification

Linux tests use temporary journals and modeled identities, never host account
creation. They cover strict frames, actual UID-65534 client processes, rejection
of an unauthorized root client and a rogue non-root server, stale revisions,
review-required failures, lost replies, cancellation, unavailable state and
bounded request fuzzing. The QEMU fixture additionally drops a real child to
UID/GID 65534 with no supplementary groups, performs both journaled commands,
and rejects stale requests after each confirmation. It now uses `Listen` with
a root:65534 0710 runtime directory and root:65534 0620 socket, verifies the
exclusive lease and requires drained cleanup after each group/user phase.
These are disposable fixture choices, not product deployment settings.
Host tests additionally cover stale recovery, live/foreign/path refusal,
replacement preservation, slow clients, bounded backlog, retained lease during
backend drain and concurrent lifecycle calls. Native identity cleanup and prior locked-login/nologin/
no-home checks remain required by the same scenario.
