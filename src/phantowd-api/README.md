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

## M5.5a diagnostic snapshot lifecycle task contract

The browser's existing four read-only snapshot requests must share one bounded
single-flight generation. An authentication boundary (sign-out/password change,
unavailable status or unauthenticated status) aborts that generation and clears
observations immediately. Late successes, errors, body decoding and finalizers
from an invalidated generation must never repopulate values, overwrite a newer
session message or unlock a newer request. Aborting a browser read does not
prove that a server/kernel operation stopped. No request is retried automatically.

Use one controller and a finite 10-second client deadline for the snapshot,
including body decoding. Each domain still reports success/unavailability
independently; a timed-out domain has no retained old values. Reuse the existing
read endpoints/renderers and session flows: no new endpoint, privilege,
hardware polling, persistent job or service activation. Keep manual GPT and
policy operations independent and explicitly triggered.

Acceptance: deterministic tests execute the actual browser source with deferred
responses across logout/auth failure and a newer refresh, shared cancellation,
single-flight, finite timeout, late body decoding and independent partial
failure. Host/API and ARMv5 asset integration remain separate; DOM fixture
success is not real-browser accessibility or physical-device qualification.

Local evidence (2026-10-03), code `fab3b7e` / tree `60e04f9`: actual-source
logout regression fails twice before the fix, then the complete DOM suite and
eleven diagnostic lifecycle cases pass repeatedly. Windows API/UI/vet/tagged
tests and ARMv5 cross-compilation, pinned Linux full tagged vet/race, existing
feedback/fuzz contracts, actual ARMv5 embedded-asset smoke and clean two-boot
overlay pass. Original seven base hashes remain unchanged. No JavaScript is
executed by QEMU; these proofs do not replace real-browser/accessibility tests,
clean hosted qualification, product enrollment or physical EX4 validation.

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

### M3 mounted-root census task contract

Replace caller-selected mount anchors with a private read-only census derived
from the complete current-process mount table and complete sysfs/MD topology.
Consider block-backed ext2/3/4 filesystem-root mounts only; explicitly count
excluded process-root, subtree, unsupported-filesystem and zero-major entries.
Zero-major does not prove a non-block-backed filesystem. Unknown nonzero device
numbers, duplicate/stacked mountpoint ambiguity, inaccessible roots or incomplete
metadata refuse the entire census. Cap actual root observations at64.

Retain mountinfo's transient mount ID and filesystem-root internally so a
same-path/device remount or subtree change invalidates re-observation; keep
them out of existing JSON. These IDs are distinct from the statx unique mount
IDs used by mountguard and must never be compared as one namespace of IDs.
Use the existing fixed descriptor-relative mountguard observer twice, bracketed
by complete storage/MD and mount-table observations, then correlate each
observed UUID/device to the same validated topology. Refuse changes and partial
results; return an explicitly scoped, non-serializable private observation.

This is not complete physical-volume discovery, UUID uniqueness across unmounted
media/other namespaces, a logical VolumeID resolver, compatibility/health,
qualification or mount/import/activation authority. No block node or file data
is read, state written, privilege widened or product/API startup wired. Native
tests inject re-observation failures; the already-approved disposable QEMU MD
fixture exercises the fixed reader. No NAS or real disk operation is included.

Local evidence (2026-10-03): the complete Windows API/DOM/vet and ARMv5 test
cross-compilation pass. Pinned Linux whole tagged API vet/race, bounded existing
fuzz/contracts and actual ARMv5 standard smoke plus the two-boot state fixture
pass. The guest census observes the existing disposable read-only MD filesystem
and its two members, with process root explicitly excluded. Native tests cover
the64/65-root boundary, empty scope, orphan/overmounted paths, reused observer
buffers, mount/root/UUID/device-generation drift, unavailable metadata and
cancellation. Census JSON is refused. Mountinfo IDs and filesystem roots remain
private; existing snapshot comparison now detects their changes.

Seven frozen source/support hashes and seven original base-artifact hashes were
independently checked after the terminal local run. The current cached image,
two fixed volumes and bounded auto-removed RAM scratch were reused; no new
persistent image, volume or output exists. This is an overlay qualification,
not a clean new firmware/SBOM, hosted feature result or physical EX4 validation.
The observation is point-in-time and limited to one process mount namespace;
it does not establish global use, UUID uniqueness on unmounted media, a durable
VolumeID, compatibility, health, a retained lease or activation authority.

### M3.2h explicit mounted-census freshness task contract

Add an internal Linux read-only recheck of a previously complete mounted-ext
census. Validate the entire retained observation before performing new root
observations, then use the fixed complete collector, not a caller-selected
subset. Compare coverage, full mount table, disk generations/VPD/topology,
MD bindings and independent filesystem UUID/device/unique-mount observations.
Collection timestamps are not identity. An invalid previous observation,
unavailable metadata, cancellation or any changed observation returns only the
existing redacted incomplete error; no partial positive result is returned.

This operation has no intent/result journal or persistent transition: it
compares two complete point-in-time observations. It does not retain handles,
make review sticky, monitor automatically or guarantee stability after return.
The caller must not concurrently mutate the private previous snapshot. Reuse
existing collectors, validators and comparators; the injected root observer
remains an in-process test seam, never request input. No public API, persistent
VolumeID registry, mount qualification, Owner/planner authority, mount/import,
service activation, new privilege or NAS operation is included.

Acceptance: native Linux tests must refuse corrupt prior evidence before root
I/O and detect drift in unclaimed/excluded scope as well as observed roots;
cover cancellation, metadata failure, empty scope, ordering, timestamps and the
64-root budget. Reuse the existing disposable QEMU MD mount/member fixture for
an actual fixed-reader recheck and explicit mandatory marker, without another
boot, backing disk or persistent Docker resource. Physical EX4, durable
identity, global-use accounting and recovery gates remain open.

### M3.2f scoped desired-volume observation task contract

Add one private, side-effect-free review joining a validated desired share
policy to the complete mounted-ext census. Group by current kernel device,
retaining every mount-root alias rather than selecting a pathname. Distinct
devices with one UUID remain ambiguous; one device with multiple root aliases
is one observed object. Report not-observed/observed/ambiguous **in this scope**,
explicit alias/object counts and incomplete physical-disk identity evidence.
An observed singleton must never become globally unique, persistently adopted,
compatible, healthy, writable or activation-ready. Keep unclaimed observed
objects explicit even when desired policy contains no volumes.

Validate the complete census/topology/alias relationships before joining any
desired subset; malformed or partial observations return no review. Retain
desired revision and logical VolumeID only as policy references, never derive
them from UUID, bay, kernel name or path. Bound the work by existing16 desired
volumes and64 scoped roots; deterministic output must not depend on policy or
mount-table order. Results refuse JSON and cannot construct mountowner or
planner qualification. No I/O, persistent registry, new HTTP, mount, import,
state write, privilege or product wiring. Test host cases for aliases/clones,
missing/unclaimed objects, incomplete disk evidence and malformed input, then
reuse the existing disposable MD guest observation without extra storage jobs.

Local evidence (2026-10-03): full Windows API/DOM/vet and ARMv5 test compilation
pass. A new native regression first reproduces circular validation accepting
changed derived UUID/unique mount IDs. The collector now independently retains
its owned root metadata and complete MD bindings; the review rebuilds from
those original observations, not from the identities being checked. Whole
pinned Linux tagged API vet/race, existing bounded fuzz/contracts, actual ARMv5
standard smoke and clean two-boot overlay then pass on the corrected source.
The actual guest checks one observed MD object against desired policy and
accounts for every other unclaimed object; aliases/clones and16/64 limits are
native synthetic tests, not new guest clone experiments.

Independent post-terminal checks confirm six frozen runtime/test/support
hashes and seven unchanged original base artifacts. No surviving project
builder or new persistent image/volume/output. This is cached local overlay
evidence, not hosted feature CI, clean-build/SBOM or physical qualification.
The review does not create an Owner, planner-ready storage snapshot, retained
lease, persistent ID or compatibility decision. Observed/not-observed always
means within this declared namespace scope; no global presence/absence claim.

### Manual GPT metadata observation

The development dashboard offers one separate, explicit
`POST /api/v1/storage/gpt-observation`. It requires the current administrator
session, exact configured Origin, one valid `X-PhantoWD-CSRF` header, and an
empty request with no query or content type. It is never called by page load or
the ordinary `GET /api/v1/storage` refresh. The route asks the local storage
broker for the fixed `observe-gpt` operation; callers cannot select a disk,
path, command, or subset. HTTP and broker gates allow only one GPT observation
at a time, while a second broker worker keeps normal inventory independent.

The broker may inspect only the first-sector partition map and valid GPT
headers/entry metadata on its complete eligible read-only whole-disk candidate
set. It does not run filesystem-signature probing, read partition contents or
file data, assemble, mount, import, repair, or write. GPT disk GUIDs, PARTUUIDs,
partition geometry, kernel names and paths remain broker-private. The response
contains only bounded aggregate candidate/GPT/partition counts, coverage,
duplicate counts, and fixed limitations. MBR/DOS, other partition schemes and
candidates without a valid GPT table remain unsupported coverage gaps; a
singleton is not proof of global uniqueness. Failures produce no partial
result. The operation has a 50-second request bound, but a kernel-stalled
uninterruptible block I/O may outlive cancellation. This development-only
observation is not EX4/product qualification and grants no storage authority.
The host/API suite and generated regular-image C tests pass locally; ARMv5
API-test cross-compilation and a target-style helper link against the cached
Buildroot sysroot/libblkid pass. A smoke-only local ARMv5 QEMU overlay also
passes the explicit authenticated POST through the guest broker against two
distinct read-only synthetic GPT clones, verifies duplicate GUID/PARTUUID
classification, and checks the aggregate-only HTTP response. It reuses the
cached kernel/packages and a disposable rootfs copy. Subsequent full local
Buildroot/package integration and hosted baseline checks include these
observations and the separate two-boot fixture; see
[implementation status](../../IMPLEMENTATION-STATUS.md) for exact evidence.
Independent clean release qualification and EX4 compatibility remain separate.

### Internal MD v1.0 metadata reader (QEMU-only)

The `mdmetadata` package contains a bounded parser for one generic Linux MD
metadata 1.0 superblock at the end of a caller-selected 512-byte-sector
partition range. Its Linux block adapter accepts a caller-owned O_RDONLY
whole-disk descriptor and rechecks block type, major/minor, `diskseq`, capacity
and logical sector size before and after the read. Its pure component-set
correlator additionally requires canonical array/member fingerprints, matching
partition bindings, matching array fields/component sizes/events, unique member
identities and roles, and complete active-role coverage before reporting only
generic `metadata-consistent`. It opens no path and never assembles, mounts,
imports, repairs or writes. Parser and correlator are exercised only by the
disposable ARMv5 QEMU fixture. The fixed `observe-md-v1.0` broker operation is
connected only in `qemu && linux` builds: it starts from complete trusted
discovery, correlates validated GPT partitions and reads only declared Linux
RAID members before returning a redacted summary. Non-QEMU builds return
unavailable without reading disks. There is no MD HTTP endpoint, automatic
scan or product activation. See [mdmetadata](mdmetadata/README.md).

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

The internal [mount owner](internal/mountowner/README.md) is an M3.4 lifecycle
prototype. Its real bind-mount driver and trusted qualifier exist only in the
disposable ARMv5 QEMU fixture. Linux host tests and the local ARMv5 QEMU overlay
exercise one-use qualification, lease gating, identity-change revocation and
review-required handling of uncertain mount/unmount outcomes. It is not wired
to product startup, the storage broker, or any HTTP/RPC operation; no physical
disk or NAS is in scope.

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
  requires an owned directory mode 0700 and regular single-link file mode 0600.
  The transactional Linux backend retains an exclusive cooperative lifetime
  lock. Setup commits v2/revision 1 only to absent state; exact prototype-v1
  accounts remain readable without content rewrites. Do not run old writers
  on this directory. QEMU explicitly sets `/run/phantowd-state`, so the
  account survives an API-process restart but is erased by a guest reboot.
  Non-Linux binaries refuse this backend; Windows HTTP/TLS tests use explicitly
  injected memory-only fixtures, not a weaker production persistence fallback.
- Account checks reload validated state. Login rechecks its snapshot after KDF
  work; issuance performs a final account check under the adapter lock.
  Missing previously configured state, corruption, unsafe storage or uncertain
  setup latches unavailability until process restart/reconciliation. Existing
  sessions then fail authorization and cannot retrieve CSRF/session metadata;
  enrollment is not reopened. Restoring a file cannot revive that process.
  There is no automated repair/reset. Already-authorized work is not cancelled.
- Sessions are random, in-memory only, expire after 30 minutes, and are capped
  at eight. Cookies are HttpOnly and SameSite=Strict; logout requires an
  anti-CSRF header. A process-wide login limiter allows five attempts per
  minute. Secure/`__Host-` cookies are used for TLS requests. Mutating auth
  requests require the configured exact Origin and matching Host/scheme.
- Global panel sign-out validates its invoking session and CSRF atomically,
  clears all sessions in this API process and changes an opaque issuance
  generation. Setup/login capture that generation before credential work:
  an overlapping old login cannot publish a new session after revocation.
  Replaying the revoked request cannot invalidate later fresh sessions. This
  does not cancel requests/jobs already authorized, change credentials, revoke
  SMB/NFS access or coordinate multiple API processes. The dashboard clears
  drafts, prevents duplicate requests and does not retry an uncertain outcome.
  The [administrator transaction store](admincredentials/README.md) now backs
  running Linux authentication. The separate password-change endpoint below
  verifies the current password and coordinates replacement/session revocation.
  Reset, recovery and durable ownership/bootstrap authority remain unimplemented.
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
  the QEMU guest. Whole-disk observations require a nonzero unique kernel
  `diskseq`; the collector rereads block and partition metadata, including VPD
  identity status, and the block-node name set before returning, refusing any
  observed inconsistency. This reduces mixed observations but is not an atomic
  hotplug snapshot. `diskseq` is transient for one kernel lifetime, is not
  returned by the API and is not disk identity.
  Internal comparisons across separate in-memory inventories include a
  domain-separated SHA-256 equality digest of each valid VPD value so an
  identity change cannot hide behind an unchanged `present` status. Neither
  raw values nor these digests are serialized or treated as stable identity.
  The HTTP/API process never opens a block device. A storage request instead
  contacts a fixed local broker channel; the dedicated non-root broker obtains
  the complete internal inventory, opens eligible whole-disk nodes read-only,
  closes every descriptor, and returns only a bounded/redacted snapshot. The
  current path issues no block-data reads, shell commands, assembly, mounts,
  reboot, firmware install or update operations.
  Configuration writes are limited to account setup and the explicitly enabled
  development policy backend described above.
- The broker's fixed-path opener accepts only the collector's kernel names and
  generation tuples, safely opens beneath fixed `/dev` read-only/no-follow, and
  binds descriptors to major/minor and `diskseq` using `BLKGETDISKSEQ`. Device
  nodes must be root-owned, group-owned by `phantowd-storage-read`, and exactly
  mode `0440`; the API account is not a member of that group. The broker runs
  as a separate non-root account, requires `no_new_privs`, rejects effective,
  permitted or inheritable capabilities, and allows no supplementary group
  other than the read-only device group. It accepts no caller-supplied path,
  name, command or partial selection; the API sends no request payload or file
  descriptors. The bounded Unix-socket response authenticates peer credentials
  in both directions. This establishes only the implemented read-only
  point-in-time inventory boundary; it is not mount/import authorization. See
  the [probe contract](volumeprobe/README.md).
- The private `completeObservedBlockDeviceSet` bridge accepts only the
  collector's in-memory schema-v2 inventory and emits every whole-disk
  name/generation tuple; it accepts no caller-selected names. The internal
  `discoverTrustedStorageWith` coordinator excludes visible mounts, virtual
  nodes, MD/device-mapper stacks and removable devices, then opens the full
  candidate set read-only and rechecks sysfs, mount and swap observations.
  Active/unreadable swap state or any snapshot change makes the whole result
  unavailable and closes every opened descriptor. Ambiguous VPD identities are
  preserved as ambiguous, not promoted to unique. This is a point-in-time
  preflight: before opening any candidate, every mountinfo entry with a
  nonzero device major must map to exactly one node in the complete sysfs block
  inventory. An unmapped nonzero device number makes the assessment unavailable;
  major-zero pseudo-filesystems remain uncorrelated. This still does not prove
  global userspace or mount-namespace exclusivity. Mount attribution is limited
  to this process's namespace and the observed partition/holder/slave graph.
  Mounted Btrfs, Bcachefs and ZFS currently make discovery fail closed because
  their full multi-device backing set is not established here. Other filesystem stacks,
  stable identity, bay mapping, compatibility and mount authority also remain
  unresolved. Exact-head ARMv5 QEMU run
  [36364383677](https://github.com/PhantoNull/phantowd-ex4/actions/runs/36364383677)
  passed for PR #42's tested head `7254555`; it exercised the broker and
  hotplug-permission assertions in the disposable guest. This is not EX4 board
  or production device-rule qualification. The QEMU SysV profile starts mdev
  before the broker and API, applies mode `0440` only to whole-disk `sd[a-g]`
  nodes needed by its six-candidate fixture (plus the mounted root disk), and
  tests a synthetic `sdd` hotplug.
  The separate udev rule currently covers `sd[a-d]` provisionally; other init
  systems and EX4 device naming are not yet qualified. The broker's mount view
  is only its own namespace and does not exclude other userspace block consumers.
  Serialized snapshots are rejected because private completion markers and
  generations are not serialized.
- A further internal GPT-only observer correlates the complete parser results
  with the complete generation-bound sysfs partition set by partition number
  and exact start/size. It classifies disk-GUID and PARTUUID collisions
  independently only within the observed GPT-candidate subset; unsupported
  MBR and no-table candidates remain coverage gaps, and a singleton is not a
  global uniqueness claim. The parsed GPT partition type GUID is also retained
  privately as a future layout-policy input, not a compatibility verdict. A
  small allowlisted classifier maps known EFI/Linux GPT type GUIDs to generic
  declaration hints (`efi-system`, `linux-data`, `linux-raid-member`,
  `linux-swap`, or `linux-lvm`); unknown/vendor GUIDs remain `unknown`. These
  hints describe only the GPT declaration, not partition contents, WD role, or
  import compatibility. IDs, type GUIDs and classifications are excluded
  from JSON. Before collision classification, the internal aggregator also
  revalidates that disk GUID, PARTUUID and type GUID values are canonical,
  nonzero lowercase UUIDs, and that each generic hint matches its type GUID;
  malformed or inconsistent bindings fail closed.
  Host fixtures exercise a complete two-candidate cloned-GPT observation with
  aligned synthetic sysfs children. A separate smoke-only ARMv5 overlay tests
  the collision classifier with an in-memory clone pair, not an additional
  guest disk. Neither path adds a persistent ID, HTTP field, compatibility
  decision, mount or import path. See `ROADMAP.md` for current limits.
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
| `POST /api/v1/auth/logout-all` | Atomically revoke all panel sessions and earlier in-flight session issuance; requires one session cookie, one CSRF header, configured Origin and no input |
| `POST /api/v1/auth/password` | Verify current password, commit a different new password and revoke every panel session; requires the configured Origin, one session cookie and one CSRF header |
| `POST /api/v1/file-services/preview` | Authenticated, Origin/CSRF-protected desired SMB/NFS preview; no save, runtime validation or activation |
| `GET /api/v1/shares/configuration` | Authenticated read of the optional original share-only store; not running-service state |
| `GET /api/v1/file-services/configuration` | Authenticated combined desired policy; development backend only, uninitialized state remains explicit |
| `PUT /api/v1/file-services/configuration` | Development-only, Origin/CSRF-protected full revision commit; never activation |
| `GET /api/v1/system` | Authenticated versioned JSON: observation time, kernel, architecture/GOARM, uptime, total/available memory, effective UID, development safety flags |
| `GET /api/v1/storage` | Authenticated, sorted, bounded kernel block-node observations, schema v2: name, major/minor, 512-byte-sector capacity, read-only/removable flags, partition number, transient parent name/major/minor for partitions, and `serial_status` / `wwn_status` for non-partition block nodes |
| Incomplete or inconsistent storage inventory | `503 storage_unavailable`; no partial observations, raw identifiers or sysfs paths |
| `GET /api/v1/arrays` | Authenticated, bounded Linux MD observations from `/proc/mdstat` and `/sys/class/block`: level, state, degraded/active counts, sync action/progress, and transient member names; partial sources never become an empty/healthy claim |
| `GET /api/v1/mounts` | Authenticated, bounded snapshot of filesystems already mounted in this process's namespace, from `/proc/self/mountinfo`; returns mount point, filesystem type, device major/minor, and the read-only mount flag while omitting source strings and raw options |
| Wrong method on a known route | `405`, route-specific `Allow` |
| Query or body on a read route | `400` |
| Unknown route | `404` |
| Missing, oversized, malformed or inconsistent proc data | `503`, generic diagnostic error without raw data or file paths |

Only `sys/kernel/osrelease`, `uptime`, and `meminfo` beneath `/proc` are read,
with a 64 KiB limit per file. `MemAvailable` is required; no invented fallback
is returned. The storage endpoint reads bounded attributes for at most 32 names
enumerated under `/sys/class/block`, and reads relation directories only under
their validated canonical `/sys/devices` targets. For non-partition block nodes
it also reads the kernel's read-only VPD page 0x80/0x83 sysfs files, bounded to
4096 bytes each. It returns only `serial_status` and `wwn_status` (`unavailable`,
`present`, `invalid`, `ambiguous`, or `unreadable`); raw serial/WWN values are
never returned. Duplicate valid serials or NAA WWNs among the non-partition
block nodes visible in this snapshot are marked `ambiguous` on every matching
entry. The sysfs category does not prove one-to-one physical-disk topology and
does not resolve aliases or multipath paths. These states validate only observed
SCSI VPD metadata and do not establish a durable PhantoWD
identity. Kernel names and major/minor numbers remain transient observations.
It re-reads fixed metadata, including parsed whole-disk VPD identity, before
publication and checks the node-name set last. Any required-attribute read or
parse error, or observed inconsistency, rejects the entire snapshot; the
collector returns no partial observation and the HTTP route reports only
generic `503 storage_unavailable`. An unavailable/unreadable VPD page remains
an explicit identity status, not a unique-identity claim.
Each `/sys/class/block` link target is bounded, validated as a relative path
inside `/devices/`, and re-read as part of the consistency check. Every
enumerated partition must resolve to exactly one enumerated whole-disk parent.
Schema v2 exposes that transient relation as `parent_name`, `parent_major`, and
`parent_minor` on partition entries only. These are current kernel names and
device numbers, not stable identity; the parent's disk sequence is validated
internally but not returned. No absolute sysfs path is exposed. Missing,
ambiguous or changed parent topology rejects the complete snapshot. The
collector also reads bounded sysfs `holders` links for each block node and
`slaves` links for each whole block node, resolves both against the complete
inventory and requires reciprocal relationships. That transient graph is
re-read before publication and remains omitted from schema v2; missing,
unobserved, non-reciprocal or changed links reject the complete snapshot. The
mount-assessment fixture follows partition parents and transitive slave
relationships so a visible MD/device-mapper mount can be
associated with its backing disk. Generated host tests cover a synthetic
disk-to-partition-to-MD-to-device-mapper chain and a multi-member MD mount.
The QEMU-only fixture creates a real RAID1 from two generated virtual disks,
formats it with a synthetic ext2 UUID, mounts it read-only, verifies both
backing disks are attributed (and an unrelated disk is not), then ordinarily
unmounts and stops the array. Only the QEMU profile includes MD RAID1, mdadm
and e2fsprogs for this test. The backing files and guest block writes are
disposable and snapshot-isolated. This still does not instantiate a guest
device-mapper chain, prove global unmounted state or exclusive access, or
qualify production discovery; exact-head CI for the fixture is pending. In
Linux v6.18, a
partition gets a `holders` directory while the whole gendisk gets both
`holders` and `slaves`; the block layer documents the reciprocal link contract
in [`partitions/core.c`](https://github.com/torvalds/linux/blob/v6.18/block/partitions/core.c#L2258-L2277),
[`genhd.c`](https://github.com/torvalds/linux/blob/v6.18/block/genhd.c#L3039-L3058),
and [`holder.c`](https://github.com/torvalds/linux/blob/v6.18/block/holder.c#L548-L579).
The block inventory does not collect partition/filesystem UUIDs, bay mapping,
SMART, or device health. The separate array endpoint reads bounded
`/proc/mdstat` text and MD sysfs metadata only; it
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
Setup/login JSON is capped at 2 KiB, rejects duplicate/unknown fields and trailing
values, and refuses content encodings. Password-change JSON has the separate
16 KiB bound described below. File-service preview JSON is capped at
524,544 bytes, with separate 256 KiB nested-policy limits and one active
preview per handler. It accepts neither content encoding nor query parameters.
See the [preview contract](fileservice/README.md) for errors and prerequisites.
This is a bounded development
prototype, not a security-reviewed LAN service. The QEMU guest binds only to
`127.0.0.1:8080`. The optional TLS/listener configuration is only a transport
safety primitive; it does not qualify the API for deployment on an EX4 or make
the QEMU listener remotely accessible. There is no first-boot hardware
pairing, password reset/recovery, MFA, persistent session, certificate
provisioning/renewal, production state-volume provisioning, or volume
migration/rollback.

## Administrator password change

`POST /api/v1/auth/password` accepts only `current_password` and `new_password`.
It requires the configured Host/scheme/Origin, exactly one live session cookie,
one CSRF header and one JSON Content-Type (optional UTF-8 charset). Query strings,
content encodings, unknown/duplicate/non-exact field names, nulls, invalid UTF-8,
unpaired surrogate escapes, excess nesting and trailing JSON are rejected. The
16 KiB envelope permits JSON escaping of both 1024-byte password limits. The
new password must be valid UTF-8, at least 15 code points and different from the
submitted current password. Neither values nor verifiers enter responses/logs.

One password transaction is admitted at a time, without a KDF queue for other
password changes. Competing attempts receive 503 with Retry-After 1; a separate
process-wide five-attempt/minute limit returns 429 with Retry-After 60. Global
KDF memory/concurrency limits still apply. Current-password verification and new
hash derivation precede a locked exact-snapshot/context check. Session/CSRF are
then revalidated atomically with revoking all sessions/issuance epochs, before
the revision-checked durable commit. Session issuance uses the same lock order.
An overlapping old login cannot retain authorization across this boundary.

Success returns 200 with `password_changed`, `reauthentication_required` and
`all_panel_sessions_revoked` true, and clears the invoking cookie. The user
must sign in again. Wrong current password returns 401 without revocation;
invalid new password returns 422; a precommit revision conflict returns 409.
Storage failure after revocation keeps sessions revoked and quarantines account
access. An uncertain commit returns 503 `password_change_reconciliation_required`.
Cancellation checked before commit does not undo a commit already in progress.
Already-authorized requests/jobs and SMB/NFS credentials/sessions are unaffected.

The collapsed form confirms the new value locally, clears password fields on
submission/authentication loss, prevents duplicate submission and bounds its
session/POST request to ten seconds. A lost, malformed or uncertain response
hides authenticated data and is never retried automatically. Explicit sign-in
reconciliation must establish which password committed; inaccessible credential
storage requires inspection/recovery, not another setup or forced reset.
DOM, host refusal/concurrency/error tests, real ARMv5 HTTPS and independent
two-boot handler tests cover this flow. Visual/accessibility qualification,
ownership/bootstrap, certificate lifecycle and recovery are still release gates.

Firmware source and test builds are developed and checked locally/QEMU and by
GitHub Actions. Intended user-facing distribution is through versioned GitHub
Releases; users are not expected to compile the source locally. Actions runs
and development artifacts are qualification outputs, not installable firmware
releases. No production release or safe in-device updater exists yet.

## Local tests

### Native service identity registry

The [SMB credential integration gate](SMB-CREDENTIAL-LIFECYCLE.md) documents an
important pinned-Samba boundary: ordinary password replacement can re-enable a
disabled account, while combining the disable option suppresses password setting.
A local Buildroot patch prototype adds a root-only, stdin-only
`smbpasswd --set-password-disabled` path for accounts already disabled; it has
passed the full local Buildroot ARMv5 QEMU authentication fixture and exact-head
hosted ARMv5 QEMU and Stage B3 checks. PR #46 merged it to `develop` as
`33df1ed`. The fixture verifies the disabled-state transition, denial of the
old credential, the root-only/stdin guards and unchanged Unix account files.
The separate [M2.4 credential coordinator](internal/smbprovision/README.md) now
journals absent -> created-disabled -> credential-set-disabled -> enabled,
with enablement a separate revision-checked action. One trusted adapter is
bound when `Owner` opens; operation calls cannot replace it. Host/race/fuzz
checks, Linux package tests and the full local Buildroot ARMv5 QEMU smoke pass,
including real Samba fixture authentication denied before enable and accepted
after same-SID confirmation. QEMU uses a disposable user and private `smb.conf`;
the fixed executor validates that already-pinned configuration descriptor with
`testparm` before it can be bound to an Owner. Missing or invalid configuration
is rejected without creating Owner state or modifying the config. Product
service startup/configuration, HTTP authorization and operator review handling
remain unwired, and no HTTP account API is exposed. The config inode
remains pinned for the Owner lifetime, pathname replacement cannot retarget the
executor, and owner shutdown closes that executor once.

The [native identity authority](identityowner/README.md) now owns one configured
reservation ledger and its journals under a lifetime lease. It serializes typed
allocation/creation, freezes allocation behind incomplete work and refuses
orphaned cross-document state after interruption. The guarded ARMv5 channel now
uses that owner. Complete imported/offline ownership discovery, qualified state,
explicit recovery, credential transitions and deployed listener/panel wiring
remain required. Explicit enable is implemented only through the internal
Owner-bound method and fixture-only v2 channel; no HTTP credential endpoint or
product account-management service is provided by the M2.4 slice.
The QEMU-selftest profile now separately boots a root Owner service against
guest-local fixture state and verifies protected-socket authorization, process
restart and drain. This does not change the M2.4 product integration status.
The current-source ARMv5 smoke also round-trips the Owner registry's desired
service-account state under the lifetime lease, while proving that the native
identity journal remains immutable and no Samba child journal, authentication
mutation, RPC/HTTP action or service activation occurs. This remains an internal
library/test behavior, not a product account-management surface.

The [local identity channel](identityrpc/README.md) now connects an actually
unprivileged ARMv5 fixture child to the root-owned journal/executor using
kernel-verified Unix-socket peers. Native identity version 1 accepts only
status or one revision-checked step. The separate SMB version-2 frame carries a
bounded password only as raw bytes for the typed `set-password-disabled`
operation, and a credential-free `enable` action that requires a separate
revision and prior password confirmation; the Owner-bound backend is never
selected by request input. Missing replies are never retried automatically. Its optional
protected listener supplies bounded acceptance, cooperative pathname ownership,
exact stale-socket recovery and worker drain before authority closure; the ARMv5
fixture now uses it. A shared router resolves existing accounts only after peer
and request validation, pins one operation across each request and checks its
post-step account binding. The ARMv5 scenario creates a second identity while
verifying that the first journal remains unchanged. This library does not deploy a product service or supply
authority ownership, operation creation, production Samba integration or a
panel account endpoint.

The [typed Linux identity executor](identityexec/README.md) now connects the
journal to fixed BusyBox group/user creation in the guarded ARMv5 fixture.
It pins the firmware ELF, binds one disabled identity, rechecks local state,
supervises bounded commands and accepts no arbitrary command/path/password.
The generated guest verifies locked Unix login, nologin and no home creation.
This is not yet a deployed privileged service or a panel account-creation endpoint;
global writer authority, durable state and recovery remain integration gates.

The [serviceaccounts registry](serviceaccounts/README.md) now provides strict
native UID/private-GID reservations, disabled-by-default creation, permanent
retired identities, revision-checked transitions and exact share-user binding.
A Linux atomic store exposes only typed transitions, preventing accidental
tombstone erasure through arbitrary document replacement. It is not connected
to the HTTP/UI or live Unix/Samba authorities. Legacy import, identity discovery,
credential reconciliation and actual provisioning remain separate work.
The [local Unix observer](unixidentity/README.md) supplies bounded exclusions
and exact/partial/conflict assessment; only its guarded QEMU fixture connects
allocation to a temporary real Unix user/group. Matching local records never
authorize account adoption or prove complete NSS/credential state.
Its Linux reader now pins/rechecks owned non-writable regular account files and
requires a files-only identity NSS configuration; all-writer serialization and
credential/provisioning integration remain open.

The [native identity creation coordinator](identityprovision/README.md) now
records durable group/user command intentions and observed confirmations for one
disabled reservation. Resumed intentions require review instead of command
replay; existing identities are never auto-adopted. Host process-exit/failure
tests and a fixed ARMv5 backend exercise this path. It is not a production
privileged executor, global account lock, credential manager or recovery UI.

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

A separate two-boot ARMv5 fixture now retains Unix account files, the native
identity ledger and Samba private/state databases on a generated ext2 disk.
Each kernel gets a fresh root snapshot; only the first phase creates users and
sets/rotates the public test password. The second must recover the same disabled
account before any credential mutation. Explicit re-enable then accepts the
retained new password, refuses the old one, reads unchanged original data and
writes with the original UID/private GID. Unix file hashes and original file
inode/content/mode/ownership must remain unchanged. No users or credentials are
recreated in the verification phase. Private lock/cache/PID state is volatile;
the daemon is stopped and mounts released before the clean reboot. The
fixture-specific shutdown waits for both direct-parent `Wait` and absence of
its foreground process group within bounded deadlines. Parent exit alone is
not successful cleanup; forced termination or uncertain group settlement fails
the fixture. Native subprocess regressions cover an adopted child holding a
regular-file directory descriptor and a cooperative child that closes after
its parent exits. This is not containment of children that escape the group,
a production Samba Owner, or proof of the intermittent state-unmount cause.

The local M2.5 QEMU fixture now exercises an Owner-journaled `Disable` that
blocks new Samba authentication and requests account-scoped revocation of
existing sessions, verifying their absence before success. Uncertain outcomes
enter review without replay; revocation can interrupt transfers or writes. This
is not product account provisioning or deployed session revocation. Clean-reboot
persistence is verified only in the separate isolated fixture, not a product
state layout. Neither scenario proves cross-store crash recovery, Windows client
behavior, ACL/migration compatibility, EX4 performance, open-file-handle
behavior or durable reconnect semantics. The dashboard administrator's Argon2
verifier, desired-policy user references, Unix UID/GID identity and Samba passdb
are separate authorities: saving a user reference creates none of the others.
Production still needs stable non-recycled IDs, private persistent passdb,
bounded privileged actions, reconciliation after partial failure, and product
startup/authorization/recovery integration for the tested revocation path.
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

#### Desired change-review task contract

Cross-protocol advisory extension: after that same complete preview, compare
lexical SMB/NFS folder relationships on each policy VolumeID in the loaded
baseline and candidate. Identify exact share/export IDs, equal/ancestor paths
and whether the pair remains, appears or disappears. This does not resolve
filesystem aliases or prove effective access; removing an SMB definition/grant
does not revoke NFS, and NFS client changes do not revoke SMB. Show exact
baseline/candidate pair counts and at most 64 deterministic pair details with
an explicit omitted-detail count. This presentation limit is not an activation
or Save admission rule. Reuse the existing request and text-only table style;
clear all advisory data with the existing draft/auth lifecycle. No endpoint,
additional I/O, authority, daemon operation or policy mutation is introduced.
Test equal/root/nested and segment-boundary paths, distinct VolumeIDs, pair
removal, order invariance, limits, literal markup and late-response clearing.

Extension evidence (2026-10-03, code `29d4d10`): complete DOM/Windows tests,
pinned Linux whole tagged API vet/race, three repetitions of the seven-boundary
SIGKILL store campaign, bounded network fuzz/contracts and actual ARMv5 standard
smoke plus clean two-boot overlay pass on one frozen source. The advisory
fixture counts128x128 pairs while retaining64 details and still admits a
complete otherwise-valid desired review; a disjoint baseline/candidate fixture
counts32768 pairs without retaining that pair set. Auth-loss/late replies and
literal markup do not restore/inject advisory content. This is not measured
browser memory/performance, effective filesystem access, browser execution,
new clean firmware/SBOM, hosted acceptance or EX4 qualification. Existing
kernel/packages/probe and fixed build resources are unchanged.

After the existing complete server preview succeeds, show a bounded semantic
before/after comparison against the explicitly loaded baseline. Compare stable
policy IDs, exact SMB user references and exact NFS client CIDRs, never list
positions or rendered daemon text. Cover volume/user references, share/export
definitions, SMB grants and every NFS mapping/security field. Ignore object/
collection ordering and revision-only changes; never present them as access
changes. Missing/added entries remain explicit. Maximum 512 changed entries;
refuse an incomplete review rather than truncate and enable Save. The existing
server validators and revisioned save/reconciliation remain authoritative.

Render only text into semantic table cells; no policy value becomes HTML.
Clear the review with candidate invalidation, logout/auth loss and failed
preview. A fresh preview is required after an edit; late responses cannot
resurrect a discarded comparison. Do not create another endpoint, validator,
browser storage, request, automatic save or activation path. This compares
desired policy, not effective access, credentials, running services or files.
Host DOM fixtures must cover every edit family, order invariance, limits,
text-only rendering and lifecycle clearing. Browser/assistive-technology and
ARMv5 asset integration are separate qualification gates.

Local evidence (2026-10-03): the initial DOM feature regression refuses the
missing comparison function, then the complete suite passes with all edit
families, field-by-field NFS mapping/security, additions/removals, reorder/
revision invariance, exact 512/513-entry boundaries, literal markup and
auth-loss/draft-clearing assertions. Windows API/UI/vet/tagged tests and ARMv5
cross-compilation pass. Pinned Linux complete tagged vet/race, existing bounded
fuzz/feedback contracts and actual ARMv5 standard/two-boot overlay pass using
unchanged kernel/packages/probe. This checks embedded asset integration, not
browser JavaScript execution, visual/accessibility behavior, a clean new
firmware/SBOM or hosted/EX4 qualification. No new persistent build resource.

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

### Private health census prerequisite

`smart_census.go` derives a complete private sysfs sample and a deterministic
non-virtual whole-leaf view using the existing schema-v2 collector/validator.
It does not reuse the import/mount eligibility filter: mounted disks and members
of active MD arrays still require health monitoring. Removable/read-only flags
and missing, invalid or ambiguous VPD remain explicit observations, not command
eligibility. Partitions and logical/virtual nodes remain in the full census,
but are not emitted as independent whole-leaf observations.

Both samples and derived views are validated before whole-inventory comparison;
generation, topology, private VPD evidence and unrelated-node changes refuse
equality. Empty complete samples differ from incomplete/zero samples. Census
types reject JSON. Synchronous sysfs reads have context checkpoints, not a
promise of interruptible I/O or an atomic hotplug snapshot.

Host tests and the existing ARMv5 smoke cover a mounted root, ambiguous VPD and
two active disposable MD members. The private census opens no device and admits
no `smartcollect.SourceAdmitted`, command, ioctl or stable history identity.
It is not yet connected to the synthetic producer replay or product startup;
retained device/runtime provenance, transport qualification and command
  boundaries remain separate. No HTTP endpoint or recurring scan is added.

A separate Linux-only [private descriptor witness](internal/smartdevice/README.md)
retains and rechecks an already-open read-only block FD using fstat/access flags
and BLKGETDISKSEQ. It opens no path, reads no content and admits no SMART command.
Native race/refusal/no-leak and actual disposable ARMv5 MD-member tests pass;
this is not a complete provider, report attribution, transport authorization or
production wiring. The sysfs-only census above remains device-open-free.

The private Linux `smartCensusWitnessSet` now composes these two prerequisites.
Its trusted constructor receives a fixed sysfs reader and borrowed read-only
block files, requiring exactly one generation-matched source per whole leaf.
Partial, extra, duplicate and non-block sources are refused; partial retention
is rolled back without closing caller files. It retains independent duplicates
and compares the complete census before and after rechecking every descriptor.
Any observation uncertainty permanently enters review, retaining pins until
explicit Close; uncertain release cannot be retried into success. Copies,
concurrent operations and JSON are refused. Cancellation before admission has
no effect; sysfs reads/ioctls remain synchronous, not forcibly interruptible.

Native Linux race/refusal tests include late-census uncertainty. The existing
ARMv5 active-MD fixture verifies all seven whole leaves, reordered complete
input, partial-retain rollback without leaked block FDs, independent ownership
after caller Close, retained review pins after an injected reader failure, and
explicit release. The fixed test reader implements the full ReadLinkFS contract;
its failure injection is not physical hotplug. A synthetic invalid-owner test
does not reproduce an actual kernel close error. This bridge opens no path,
reads no contents, exposes no disk IDs/FDs, starts no child and authorizes no
SMART command. It remains unconnected to product startup/capture, report
attribution, transport/wake policy, stable history identity or HTTP.

### Desired network policy prerequisite

[Internal networkpolicy](internal/networkpolicy/README.md) validates a bounded
schema-1 desired document for two logical slots, dual-stack addressing, routes,
hostname and DNS. It rejects known static conflicts and incoherent gateways;
it does not normalize addresses, resolve DNS or invoke a network operation.
Host/ARMv5 fixtures test /16, aliases, scoped IPv6 link-local gateways, dynamic
DNS, strict JSON and negative cases in the existing guest boot. Logical slots
are not physical identity proof. Persistent state, actual interface admission,
runtime conflict observation, trial/confirmation/rollback and API/UI integration
remain open; no management-network change is enabled.

[Private networkinventory](internal/networkinventory/README.md) separately
collects bounded complete link/address/configured-route/IP-rule/nexthop-object
dumps from the current Linux namespace,
checking kernel reply provenance/completion and matching two observations. It
retains address flags/scope/peers privately, refuses JSON and exposes counts only.
Native UID1000/zero-capability and actual ARMv5 kernel observations pass; the
standard root guest fixture does not qualify non-root ARM privileges. The
namespace pin lasts only for collection; Recheck is not an interface generation
lease, event monitor or Owner recovery. Factory slot identity, DAD/external
conflict/route admission and product collector startup remain unimplemented.
Object/group IDs and gateways remain private; missing references refuse the
whole result. Ordered group/inline ECMP members are preserved, not digest-sorted.
Resilient groups without bucket observations, FDB and encapsulation remain
unresolved. The guest separately checks generated nonempty weighted groups;
that is not proof of live nonempty kernel groups or route usability.

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
