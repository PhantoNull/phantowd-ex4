# Development diagnostics API

This is the first product-owned Go package, not a complete management plane.
It is included only in the non-flashable QEMU development configuration and
contains an embedded browser dashboard with read-only diagnostics and a
non-mutating desired file-share preview form.

The [share configuration package](shareconfig/README.md) validates the first
desired-policy schema for volumes, file-service users and share grants. It is
exercised with synthetic fixtures in the QEMU self-test and accepted by the
authenticated [file-service preview API](fileservice/README.md). A separate,
explicitly enabled development-only HTTP save is described below; no service
activation is implemented. The Linux-only
[share store](sharestore/README.md) adds validated revision transactions and
failure handling, exercised in temporary host directories and across two
independent QEMU boots using a generated disk. An authenticated read endpoint
can return that stored desired share policy from an explicitly configured
Linux store; it does not load NFS policy or claim running-service state. The
firmware does not yet provision persistent product configuration storage.

The separate [atomic file-service store](fileservicestore/README.md) now keeps
SMB and NFS desired policy in one strictly coherent revision. It shares the
tested transaction engine with the original store but has a distinct format
and filenames, no implicit migration, and no service activation.

## Development file-service configuration API

`GET` and `PUT /api/v1/file-services/configuration` operate on the combined
[SMB/NFS document](fileservicestore/README.md), not on live services. This
backend is compiled only with `qemu && linux`, disabled by default, and requires
explicit `PHANTOWD_SERVICE_STATE_DIR`. Other builds refuse that setting.
Startup also refuses a non-loopback listener or simultaneous
`PHANTOWD_SHARE_STATE_DIR`: the two formats must not become competing policy
authorities. No default directory, automatic creation, migration, initialization
or pending-file recovery is provided. Use only an existing private 0700 local
directory owned by the API user, under trusted parents, on disposable test
storage. The lifetime exclusive store lock prevents another cooperative writer.
The normal QEMU daemon does not enable this backend. The browser manager below
keeps save disabled until a successful explicit state read and complete preview.
Do not expose this development capability through a proxy or LAN.

Both methods require an administrator session and the configured Host/scheme.
GET accepts an absent Origin, but a supplied Origin must match. PUT requires
the exact Origin, one valid `X-PhantoWD-CSRF` header and one JSON Content-Type
(optionally UTF-8). Queries and content encodings are refused. PUT is bounded
to 524,800 bytes, including unknown-length bodies, and uses the strict combined
decoder. Authentication is rechecked after body parsing and before commit.
Reads/writes share one non-queuing slot; contention receives 503 and
`Retry-After: 1`, without blocking unrelated health requests. Kernel-stalled
filesystem calls are not made cancellable by HTTP timeouts or this gate.

GET returns schema 1, scope `development-stored-file-service-policy-only`,
`initialized` and `configuration`; absent state is explicitly false/null,
not an initialized empty policy. PUT submits the **complete next revision**:
all four revision fields must match, and current revision must equal next
minus one. Revision 1 initializes only an absent store. This is whole-document
compare-and-swap, not a partial update or an automatic last-writer-wins save.
Two submissions of the same revision cannot both commit; stale writes return
409 `service_configuration_conflict`. No credential is part of this document.

A successful PUT returns 200 with `saved: true` and the committed revision only
after file and directory sync complete. Read/save responses always report
`applied`, `runtime_validated` and `activation_available` as false. They never
mount storage, change accounts/permissions, start daemons or install exports.
Missing backend returns 503 `service_configuration_not_configured`; invalid
policy returns 422; oversized input returns 413. Corruption/I/O failure returns
503 `service_configuration_unavailable`, never an empty configuration. An
uncertain rename/sync returns 503 `service_configuration_reconciliation_required`
and poisons the store until explicit close/reopen and reconciliation. Paths,
raw storage errors and configuration contents are not echoed in errors.

After a timeout/lost reply, do not automatically retry: GET the stored revision
and reconcile the **full document** with the attempted change. A revision alone
does not identify which concurrent client's change committed. The UI supports
this reread; poisoned-store reopen and administrative recovery remain external
development operations, not UI controls. All responses are no-store.
Host tests and the two-boot QEMU fixture exercise real loopback HTTP/HTTPS,
authentication/CSRF refusals, stale-write refusal and store reopen. The fixture
uses a synthetic session and test certificate; it does not qualify credential
provisioning, power-loss durability, a product state volume or LAN exposure.

## Stored share-policy read contract

`GET /api/v1/shares/configuration` requires an administrator session and the
configured request Host/scheme. An Origin header, when present, must match;
same-origin browser GETs without Origin remain supported. Queries, bodies and
non-GET methods are refused. Responses are no-store and contain no credentials.
Filesystem UUIDs and share/user policy are management data available only to
the authenticated owner, not public diagnostics or logs.

The version-1 response has scope `stored-desired-share-policy-only`, an
`initialized` boolean and `configuration` (the complete share document, or
null when the configured store has never been initialized). Runtime validation
and activation availability are explicitly false. Missing backend returns 503
`share_configuration_not_configured`; corruption or I/O failure returns 503
`share_configuration_unavailable`, never an empty appliance configuration.
Neither error exposes paths or underlying storage details.
One storage read is active per handler; competing reads receive 503 with
Retry-After, while health checks can still run. Kernel-blocked I/O is not made
cancellable by this gate.

On Linux, optional `PHANTOWD_SHARE_STATE_DIR` must name an existing private
0700 local directory owned by the API user, under trusted parents, satisfying
the store contract. An explicitly invalid directory fails API startup; an unset
variable leaves this capability unavailable. There is no default path, mkdir,
automatic initialization or pending-state promotion. Startup validates and
syncs current state and takes the store's exclusive lock; GET only loads it.
The lock lasts for the API lifetime, so external writers must not edit this
directory behind it. Non-Linux builds reject an explicitly configured backend.

The default QEMU daemon does not set this variable. Its separate two-boot test
dispatches the real handler with a synthetic authenticated session and the
real store adapter against the persisted fixture. Host tests cover rejection,
backpressure, error redaction, encoded size and startup/lock behavior. The
dashboard can load this endpoint explicitly and display the revision, share
paths, expected volume UUIDs and desired SMB grants. Empty saved configuration,
uninitialized store, missing backend and failed/busy reads remain distinct.
It validates the response shape, bounds and references for display (the server
remains the policy validator), renders data as text, and clears old values on
retry, logout or authentication loss. A cancelled or superseded request cannot
repopulate cleared values. It does not load NFS policy, populate the independent
proposal form or imply effective access. The separate development save API
does not update this panel; schema migration, product state provisioning and
SMB/NFS activation remain separate work.

## Runtime and development boundaries

The Linux [qualified-mount guard](mountguard/README.md) retains a previously
verified mount using a unique mount ID and directory descriptors. It refuses
symlinks, nested mount traversal, replaced anchors and unexpected read-only
state. It also compares the mounted filesystem's kernel-reported UUID with
trusted desired policy. It does not discover unmounted media, establish global
UUID uniqueness or WD compatibility, or activate a share, and is not connected
to a privileged HTTP operation.
Its internal mounted-inventory helper reports conflicting UUIDs across the
explicitly inspected ext-family devices without mistaking bind aliases for
clones. This is not global discovery: omitted and unmounted media remain unknown,
and neither snapshot nor a conflict-free result authorizes service activation.

The [Samba preview renderer](smbconfig/README.md) translates desired policy
into deterministic share sections and required volume bindings. Its fixed
QEMU fixture is checked with the target's `testparm`. The preview endpoint
does not provision accounts, persist configuration or activate services.
The separate QEMU-only `--qemu-smb-test` fixture uses generated shares and
temporary Unix accounts to test actual read/write grants, ownership, excluded
users, bad credentials, Unix-mode denial and symlink refusal on the disposable
data volume. Its isolated smbd listens only on IPv4 loopback port 1445; the
normal API gains no account or service-control capability. Non-QEMU builds
refuse this flag, and the fixture also checks the exact emulated machine and
mounted synthetic data device. This is not a production volume resolver.

The separate [NFS policy preview](nfsconfig/README.md) defines explicit client
networks, access, security flavors and numeric ID squashing against an exact
volume revision. Its synthetic ARMv5 probe does not apply exports. NFS host/UID
rules do not inherit Samba grants, and the product still lacks native managed
export activation, NFSv4 provisioning and protected-transport qualification.
The separate guest-only NFS integration fixture can apply fixed generated
policies to a newly created virtual ext2 disk; it is not exposed through HTTP
and refuses non-Versatile PB machines. See the
[fast QEMU testing lane](../../support/QEMU-FAST-TESTS.md) and its limits.

- Default IPv4 loopback listener: `127.0.0.1:8080` **inside the guest**.
  Optional listener configuration is fail-closed: non-loopback binds require a
  TLS certificate/key pair and one exact HTTPS origin. TLS keys must be regular
  non-symlink files not accessible to group/other users; the certificate must be currently valid and
  match the origin host. TLS has a minimum version of 1.2. No proxy headers or
  certificate provisioning/renewal are implemented. The QEMU image does not
  opt into remote listening.
- `PHANTOWD_LISTEN_ADDR` defaults to `127.0.0.1:8080`. Remote use additionally
  requires `PHANTOWD_TLS_CERT_FILE`, `PHANTOWD_TLS_KEY_FILE`, and
  `PHANTOWD_PUBLIC_ORIGIN` (for example, `https://nas.example:8443`). These are
  configuration hooks only; the firmware does not provision certificates.
- Runs as the dedicated `phantowd` user; serving as root is rejected.
- `CGO_ENABLED=0`, ARMv5 `GOARM=5`. The isolated `passwordhash` package uses
  pinned, vendored `golang.org/x/crypto/argon2`; its BSD-3-Clause license ships
  with the image and its version appears in the CycloneDX SBOM.
- A first-admin setup/login flow now protects the diagnostic endpoints. It is
  still a QEMU-only prototype, not a deployable product account system. The
  initial password must be at least 15 Unicode code points and at most 1024
  UTF-8 bytes; the username is 1-32 ASCII letters, digits, `.`, `_`, or `-`.
- The account verifier is Argon2id PHC at m=19456 KiB, t=2, p=1. Public KDF
  calls share one process-wide slot; a caller waiting for the slot can cancel,
  but a running Argon2 operation cannot be interrupted. These provisional
  parameters have not been measured on the EX4 and must not be treated as
  hardware tuning.
- The API loads one versioned administrator record from
  `PHANTOWD_STATE_DIR/accounts.json`; the directory must be explicitly
  configured, already exist, and be private. There is intentionally no implicit
  `/var/lib` fallback until a product state-volume lifecycle is designed. Linux
  requires directory mode 0700 and file mode 0600. Setup uses an atomic
  no-replace file link. QEMU explicitly sets `/run/phantowd-state`, so the
  account survives an API-process restart but is erased by a guest reboot.
- Sessions are random, in-memory only, expire after 30 minutes, and are capped
  at eight. Cookies are HttpOnly and SameSite=Strict; logout requires an
  anti-CSRF header. A process-wide login limiter allows five attempts per
  minute. Secure/`__Host-` cookies are used for TLS requests. Mutating auth
  requests require the configured exact Origin and matching Host/scheme.
- QEMU alone compiles a `qemu`-tagged self-test with a disposable password so
  the guest can test setup, duplicate-setup rejection, login, denied access,
  CSRF-checked logout, and account reload after daemon restart. The self-test
  is not compiled in normal/product builds and its credential is not a default
  account. Do not expose the loopback development service to a LAN.
- The QEMU-only runtime check also creates a temporary ECDSA certificate and
  key, starts a separate ephemeral loopback HTTPS listener using the configured
  transport, completes first-admin setup and a CSRF-protected logout over TLS,
  verifies the Secure `__Host-` cookie, and rejects a mismatched Origin. Test
  credentials and keys live only in a temporary directory and are removed;
  this does not provision production certificates or qualify LAN exposure.
- Generated images include project, Go, x/crypto and x/sys license notices
  under `/usr/share/licenses/phantowd-api/`. Build output contains a CycloneDX
  SBOM plus Buildroot's legal manifest; manual redistribution review remains
  necessary.
- `GET /` serves embedded HTML, CSS, JavaScript and ghost SVG assets with a
  restrictive Content Security Policy and no-store caching. It presents the
  first-account/login screen before showing diagnostics. The browser uses
  `textContent` for observations. The optional development manager saves desired
  configuration only; it has no device/service-activation controls. This is not
  a full NAS management UI.
- Reads fixed `/proc` diagnostics and basic `/sys/class/block` metadata inside
  the QEMU guest. It never opens a block device, reads disk contents, runs a
  shell command, assembles or mounts storage, or performs reboot, firmware
  install or update operations. Configuration writes are limited to account
  setup and the explicitly enabled development policy backend described above.
- `flashable` and `hardware_validated` are always false; the target is explicitly
  `qemu-armv5`. These identifiers are not automatic hardware detection.

## Contract

| Request | Result |
|---|---|
| `GET /healthz` | Process-only liveness, not disk/thermal/device health |
| `GET /api/v1/auth/status` | Public first-setup/authenticated status; does not reveal the account name |
| `POST /api/v1/auth/setup` | One-time first-admin creation; strict configured-Origin and JSON validation |
| `POST /api/v1/auth/login` | Authenticate administrator; strict Origin, bounded request, generic credential error and five-per-minute process limit |
| `GET /api/v1/auth/session` | Authenticated session metadata and CSRF token |
| `POST /api/v1/auth/logout` | Revoke session; requires configured Origin and CSRF header |
| `POST /api/v1/file-services/preview` | Authenticated, Origin/CSRF-protected desired SMB/NFS preview; no save, runtime validation or activation |
| `GET /api/v1/shares/configuration` | Authenticated read of the optional original share-only store; not running-service state |
| `GET /api/v1/file-services/configuration` | Authenticated combined desired policy; development backend only, uninitialized state remains explicit |
| `PUT /api/v1/file-services/configuration` | Development-only, Origin/CSRF-protected full revision commit; never activation |
| `GET /api/v1/system` | Authenticated versioned JSON: observation time, kernel, architecture/GOARM, uptime, total/available memory, effective UID, development safety flags |
| `GET /api/v1/storage` | Authenticated, sorted, bounded kernel block-node observations from sysfs: name, major/minor, 512-byte-sector capacity, read-only/removable flags, partition number, and whole-disk `serial_status` / `wwn_status` when applicable |
| `GET /api/v1/arrays` | Authenticated, bounded Linux MD observations from `/proc/mdstat` and `/sys/class/block`: level, state, degraded/active counts, sync action/progress, and transient member names; partial sources never become an empty/healthy claim |
| `GET /api/v1/mounts` | Authenticated, bounded snapshot of filesystems already mounted in this process's namespace, from `/proc/self/mountinfo`; returns mount point, filesystem type, device major/minor, and the read-only mount flag while omitting source strings and raw options |
| Wrong method on a known route | `405`, route-specific `Allow` |
| Query or body on a read route | `400` |
| Unknown route | `404` |
| Missing, oversized, malformed or inconsistent proc data | `503`, generic diagnostic error without raw data or file paths |

Only `sys/kernel/osrelease`, `uptime`, and `meminfo` beneath `/proc` are read,
with a 64 KiB limit per file. `MemAvailable` is required; no invented fallback
is returned. The storage endpoint reads bounded attributes beneath
`/sys/class/block`, with a 32-entry ceiling. For whole-disk SCSI nodes it also
reads the kernel's read-only VPD page 0x80/0x83 sysfs files, bounded to 4096
bytes each. It returns only `serial_status` and `wwn_status` (`unavailable`,
`present`, `invalid`, `ambiguous`, or `unreadable`); raw serial/WWN values are
never returned. These states validate only observed SCSI VPD metadata and do
not establish a durable PhantoWD identity. Kernel names and major/minor numbers
remain transient observations. The block inventory does not collect
partition/filesystem UUIDs, bay mapping, SMART, or device health. The separate
array endpoint reads bounded `/proc/mdstat` text and MD sysfs metadata only; it
cross-checks array names, levels, member counts and member names when both
sources report them. Any mismatch produces partial inventory and unknown
health, never a healthy claim. “Healthy” means only a consistent operational
Linux MD state: it does not imply redundancy (for example, RAID0 and linear
arrays have none) or verified data integrity. These observers do not establish
WD-layout support or data integrity. The block and array observers open no
`/dev` node and read no disk contents; the array observer does not assemble,
mount, or repair arrays. The mounts endpoint reads only the kernel's
current-process mount table; it neither mounts nor unmounts anything, cannot
see unmounted disks, and omits mount source strings, root paths, and raw
options. These are on-demand kernel observations, not filesystem or
data-integrity checks; no periodic sampling is implemented yet.

The server limits active handlers to eight, request headers to 8 KiB (Go's
HTTP parser may permit implementation slop), and sets read/write/idle timeouts.
Auth JSON is capped at 2 KiB, rejects duplicate/unknown fields and trailing
values, and refuses content encodings. File-service preview JSON is capped at
524,544 bytes, with separate 256 KiB nested-policy limits and one active
preview per handler. It accepts neither content encoding nor query parameters.
See the [preview contract](fileservice/README.md) for errors and prerequisites.
This is a bounded development
prototype, not a security-reviewed LAN service. The QEMU guest binds only to
`127.0.0.1:8080`. The optional TLS/listener configuration is only a transport
safety primitive; it does not qualify the API for deployment on an EX4 or make
the QEMU listener remotely accessible. There is no first-boot hardware
pairing, password change/reset/recovery, MFA, persistent session, certificate
provisioning/renewal, production state-volume provisioning, or volume
migration/rollback.

Firmware source and test builds are developed and checked locally/QEMU and by
GitHub Actions. Intended user-facing distribution is through versioned GitHub
Releases; users are not expected to compile the source locally. Actions runs
and development artifacts are qualification outputs, not installable firmware
releases. No production release or safe in-device updater exists yet.

## Local tests

### SMB credential lifecycle boundary

The guarded ARMv5 QEMU fixture uses its own loopback Samba daemon, private
passdb, synthetic Unix accounts and disposable data disk. It rotates one
writer's password, requires the old credential to fail, disables the account,
requires a new connection to fail with ACCOUNT_DISABLED, and re-enables it
using only the rotated credential. An unrelated reader must still work while
the writer is disabled. Every access check starts a fresh client connection;
the server is not restarted between changes. Successful downloads, original
inode/content/mode, new-file ownership and byte-identical Unix account files
and share configuration are checked. Credentials are public fixture values,
passed through stdin/private files, never command-line passwords.

This is **not product account provisioning or active-session revocation**.
It does not prove passdb persistence across reboot, cross-store crash recovery,
Windows client behavior, ACL/migration compatibility or EX4 performance. The
dashboard administrator's Argon2 verifier, desired-policy user references,
Unix UID/GID identity and Samba passdb are separate authorities: saving a user
reference creates none of the others. A production account manager still needs
stable non-recycled IDs, private persistent passdb, bounded privileged actions,
reconciliation after partial failure, and explicit existing-session revocation.
Disabling SMB must not be presented as revoking NFS AUTH_SYS or other protocols.

### File-share proposal panel

The authenticated proposal form builds a standalone draft for one volume, one SMB
share/user grant and an optional NFS export/client rule. It uses the strict
[preview endpoint](fileservice/README.md), not a save/apply route. UUIDs are
operator-entered expectations, not discoveries; revisions are draft-local
version 1, not revisions loaded from the appliance. The Validate proposal button
does not load, merge or save current configuration. The separate manager can
populate these fields from a selected saved item and use them for an explicit
operation against the loaded revision, as described below. Effective permissions,
account lifecycle, product state and activation remain implementation work.

Access defaults to read-only; optional NFS defaults to all-squash with numeric
IDs 65534. The UI explains independent SMB/NFS permissions, AUTH_SYS trust and
Kerberos prerequisites. Success displays candidate text and unresolved runtime
requirements, never an effective-access or activated-service claim. Output is
rendered as text, not HTML. Edits/clear invalidate prior and in-flight previews;
logout/auth loss clears drafts. No local/session storage is used. Requests use
the existing session and CSRF protection, ignore duplicate submission, and
abort after ten seconds. The browser supplies the request Origin.

### Development configuration manager

A separate panel uses only the opt-in combined store; it never imports the
original share-only state. The workflow is explicit load, fill the existing
proposal form, preview an **addition to the whole saved policy**, review and
save. Existing shares/exports/grants remain unchanged. A matching filesystem
UUID reuses its volume reference, and a matching username reuses its account
reference; neither operation proves presence or provisions an account. New
project IDs are deterministic and avoid existing IDs. Duplicate share names
and export UUIDs are refused locally; the server validates the entire result,
including limits, overlap and policy compatibility, before a save is enabled.
All component revisions advance together.

After loading, a separate editor selects a saved SMB share or NFS export by
stable policy ID, not by display name or current list position. Selection
copies its volume/path into the form; choosing an existing user/CIDR rule
copies that rule's fields. Only the chosen operation consumes those fields:

| Operation | Changed | Preserved |
| --- | --- | --- |
| SMB properties | Name, volume reference, relative path | Share ID, every grant, all NFS policy |
| SMB grant add/update | One exact username's ro/rw grant; adds a user reference if needed | All other grants, share path, NFS policy |
| SMB grant remove | One exact username's grant | User reference, other grants, all NFS policy |
| SMB definition remove | Selected share definition | Files, users, volumes and every NFS export |
| Independent NFS add | New export UUID, volume/path and first client rule | All SMB shares and existing exports |
| NFS properties | Volume reference and relative path | Export UUID, every client rule, all SMB policy |
| NFS client add/update | One exact CIDR's access, squash, anonymous IDs and security flavor | Other client rules, export identity/path, SMB grants |
| NFS client remove | One exact CIDR rule | Other clients and all SMB policy |
| NFS definition remove | Selected export definition | Files, volumes, users and all SMB shares |

Changing a client network requires an explicit new rule/removal, not an
implicit rename of an old CIDR. Removing the last grant/client rule is refused;
the owner must choose definition removal instead. Unused user/volume references
are retained, not garbage-collected. Missing targets, mismatched protocol/action,
duplicate identities/names and no-change edits are refused locally. Remaining
schema/limit/overlap checks are authoritative on the server. No generated-ID
choice permits bypassing those checks. Edit operations preserve unrelated
objects, including existing multi-user and multi-client policy.

Changing a definition's volume/path moves no files. Its old protocol peer does
not follow automatically: an SMB path edit/removal does not change or revoke
NFS, and vice versa. The review names the affected object and operation and
shows the full resulting service text before an explicit revision commit.
Preserving a desired NFS export UUID across a path change is not evidence of
safe live filehandle continuity; a future activator must qualify rebind/revocation.
No service runtime is changed by these development controls.

The current complete document is available as text in an expandable section;
the candidate review shows resulting SMB/NFS text and the intended revision.
Changing/clearing form inputs invalidates the reviewed candidate. Any change
while obtaining a save session prevents PUT; after PUT begins the immutable
reviewed snapshot, not later form edits, is the attempted transaction. The
server still performs independent validation and compare-and-swap. There is no
automatic PUT, retry, merge, activation or local/session browser storage.

Any failed or unreadable PUT response blocks another save until an explicit
Load / reconcile. The full attempted document is compared with the new read,
ignoring object-key order, not using revision alone. A match confirms the
desired state is currently saved; a mismatch displays current state and asks
for a fresh review, without claiming the attempt never committed historically.
If reconciliation itself fails, saves remain blocked. Logout/auth loss clears
documents and aborts local requests; cancelling a request cannot undo a server
commit. A new session must reread state. Late responses cannot restore cleared
configuration. Network errors never include raw backend response contents.

DOM tests exercise addition/edit/removal isolation, stable-ID selection,
multi-user/client preservation, reference reuse, request/CSRF shape,
lost replies, conflicts, malformed responses and auth-loss cancellation. These
use mocked fetch responses; separate QEMU tests exercise the real API/store over
HTTP/HTTPS. ARMv5 smoke verifies embedded assets, not browser JavaScript
execution. Visual and assistive-technology testing remain required. The host
visual-fixture server intentionally reports this backend as unavailable and
does not emulate saves or validate policy.

### Test commands

From the repository root on Windows, with a local Go 1.26+ installation:

```powershell
.\support\test-api.ps1
.\support\build-qemu.ps1
```

The first command runs `go vet` and fixture-based tests offline and creates a
coverage report under ignored `artifacts/api-host-tests/`. Both PowerShell
entrypoints also run dependency-free dashboard DOM interaction checks for the
authenticated, unavailable-service, expired-session, cleared-data and policy
preview states (request shape, CSRF, errors, stale replies and safe rendering);
they do not replace visual browser or assistive-technology testing. The Go
tests also verify that the QEMU self-test's expected dashboard markers match
the embedded assets. The build command
also runs native Linux tests using Buildroot's hash-verified Go compiler and
tests the real ARMv5 binary inside QEMU. The compiler variant is explicitly
prebuilt; upstream Buildroot supplies its exact version and archive checksums.
Native Linux tests also run the race detector and fixed-iteration memory and
Linux MD status parser fuzz campaigns with two workers; the PHC parser has its
own fixed-iteration fuzz campaign. ARMv5 race instrumentation is not used.

For a host-browser layout preview, run `node support/dashboard-preview.mjs`.
It binds only to `127.0.0.1:18081` and serves clearly labelled synthetic
system, block-device, and software-RAID fixtures; it is not connected to the
NAS and is never packaged into firmware. If that port is occupied, choose
another unprivileged local port with `PHANTOWD_PREVIEW_PORT`.
This static fixture server does not implement policy validation or sessions;
the proposal form requires the real authenticated development API for that.

Guest initialization probes the GET endpoints and QEMU-only authentication
flow, verifies that QEMU's root block node appears through sysfs without being
opened, rejects unauthorized and malformed operations, validates non-root
identity and ARMv5 metadata, checks the embedded dashboard and static assets
over guest loopback, rejects mutating/query dashboard requests, and prints an
RSS sample with a 48 MiB ceiling. It then restarts only the API process and
verifies that the account reloads while sessions remain memory-only. A failure
prevents QEMU readiness. The RSS sample is a smoke-test measurement, not a
steady-state or real-EX4 benchmark.

QEMU uses a disposable disk snapshot and `restrict=on` with no host forwarding
or physical device passthrough. No NAS address or credential is required.

The Buildroot entrypoint cleans only the generated local-package directory,
rebuilds it, then regenerates the root filesystem so stamps cannot hide edits
and deleted source files cannot survive rsync. Dependencies remain cached.
Go license copying runs after compiler dependencies exist, including on fresh
parallel builds. Public CI uses the same build/test entrypoint. Hardware
validation, product TLS/account-state provisioning, a full management UI, storage services,
independent clean-build reproduction, manual SBOM/legal redistribution review,
and installer/update/rollback testing remain separate unfinished milestones.
