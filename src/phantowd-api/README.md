# Development diagnostics API

This is the first product-owned Go package, not a complete management plane.
It is included only in the non-flashable QEMU development configuration and
contains an embedded, read-only browser dashboard over its diagnostic API.

The [share configuration package](shareconfig/README.md) validates the first
desired-policy schema for volumes, file-service users and share grants. It is
exercised with synthetic fixtures in the QEMU self-test; no HTTP configuration
endpoint or service activation is implemented yet. The Linux-only
[share store](sharestore/README.md) adds validated revision transactions and
failure handling, exercised only in temporary host/QEMU directories. The
firmware does not yet provision persistent product configuration storage.

The [Samba preview renderer](smbconfig/README.md) translates desired policy
into deterministic share sections and required volume bindings. Its fixed
QEMU fixture is checked with the target's `testparm`. This is not an HTTP
configuration endpoint, account provisioner or service activation path.

The separate [NFS policy preview](nfsconfig/README.md) defines explicit client
networks, access, security flavors and numeric ID squashing against an exact
volume revision. Its synthetic ARMv5 probe does not apply exports. NFS host/UID
rules do not inherit Samba grants, and the product still lacks native managed
export activation, NFSv4 provisioning and protected-transport qualification.

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
  `textContent` for observations and has no device or configuration mutation
  controls. This is not a full NAS management UI.
- Reads fixed `/proc` diagnostics and basic `/sys/class/block` metadata inside
  the QEMU guest. It never opens a block device, reads disk contents, runs a
  shell command, assembles or mounts storage, or performs configuration writes,
  reboot, firmware install, or update operations.
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
| `GET /api/v1/system` | Authenticated versioned JSON: observation time, kernel, architecture/GOARM, uptime, total/available memory, effective UID, development safety flags |
| `GET /api/v1/storage` | Authenticated, sorted, bounded kernel block-node observations from sysfs: name, major/minor, 512-byte-sector capacity, read-only/removable flags, partition number, and whole-disk `serial_status` / `wwn_status` when applicable |
| `GET /api/v1/arrays` | Authenticated, bounded Linux MD observations from `/proc/mdstat` and `/sys/class/block`: level, state, degraded/active counts, sync action/progress, and transient member names; partial sources never become an empty/healthy claim |
| `GET /api/v1/mounts` | Authenticated, bounded snapshot of filesystems already mounted in this process's namespace, from `/proc/self/mountinfo`; returns mount point, filesystem type, device major/minor, and the read-only mount flag while omitting source strings and raw options |
| Non-GET on a known route | `405`, `Allow: GET` |
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
values, and refuses content encodings. This is a bounded development
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

From the repository root on Windows, with a local Go 1.26+ installation:

```powershell
.\support\test-api.ps1
.\support\build-qemu.ps1
```

The first command runs `go vet` and fixture-based tests offline and creates a
coverage report under ignored `artifacts/api-host-tests/`. Both PowerShell
entrypoints also run dependency-free dashboard DOM interaction checks for the
authenticated, unavailable-service, expired-session, and cleared-data states;
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
