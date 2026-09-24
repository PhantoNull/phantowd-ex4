# Development diagnostics API

This is the first product-owned Go package, not a complete management plane.
It is included only in the non-flashable QEMU development configuration.

- Fixed IPv4 loopback listener: `127.0.0.1:8080` **inside the guest**.
- Runs as the dedicated `phantowd` user; serving as root is rejected.
- Standard library only, `CGO_ENABLED=0`, ARMv5 `GOARM=5`.
- Generated images include project and Go license notices under
  `/usr/share/licenses/phantowd-api/`; full SBOM/legal-info is still pending.
- No authentication or TLS yet: do not expose it to a LAN or forward its port.
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
| `GET /api/v1/system` | Versioned JSON: observation time, kernel, architecture/GOARM, uptime, total/available memory, effective UID, development safety flags |
| `GET /api/v1/storage` | Sorted, bounded kernel block-node observations from sysfs: name, major/minor, 512-byte-sector capacity, read-only/removable flags, partition number, and whole-disk `serial_status` / `wwn_status` when applicable |
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
remain transient observations. The endpoint does not collect
partition/filesystem UUIDs, RAID membership, bay mapping, SMART, or device
health, and does not prove that a WD layout is supported. It opens no `/dev`
node and reads no disk contents. This is deliberately not a legacy-kernel
compatibility package. Observations are sampled on demand, not periodically
cached yet; no potentially drive-waking source is queried.

The server limits active handlers to eight, request headers to 8 KiB (Go's
HTTP parser may permit implementation slop), and sets read/write/idle timeouts.
This is a bounded development prototype, not a security-reviewed LAN service.

## Local tests

From the repository root on Windows, with a local Go 1.24+ installation:

```powershell
.\support\test-api.ps1
.\support\build-qemu.ps1
```

The first command runs `go vet` and fixture-based tests offline and creates a
coverage report under ignored `artifacts/api-host-tests/`. The build command
also runs native Linux tests using Buildroot's hash-verified Go compiler and
tests the real ARMv5 binary inside QEMU. The compiler variant is explicitly
prebuilt; upstream Buildroot supplies its exact version and archive checksums.
Native Linux tests also run the race detector and a five-second memory-parser
fuzz campaign with two workers; ARMv5 race instrumentation is not used.

Guest initialization probes all three GET endpoints, verifies that QEMU's
root block node appears through sysfs without being opened, rejects
POST/query/unknown operations, validates non-root identity and ARMv5 metadata,
and prints an RSS sample with a 48 MiB ceiling. A failure prevents QEMU
readiness. The RSS sample is a smoke-test measurement, not a steady-state or
real-EX4 benchmark.

QEMU uses a disposable disk snapshot and `restrict=on` with no host forwarding
or physical device passthrough. No NAS address or credential is required.

The Buildroot entrypoint cleans only the generated local-package directory,
rebuilds it, then regenerates the root filesystem so stamps cannot hide edits
and deleted source files cannot survive rsync. Dependencies remain cached.
Go license copying runs after compiler dependencies exist, including on fresh
parallel builds. Public CI uses the same build/test entrypoint. Hardware validation,
TLS/authentication, GUI, storage services, independent clean-build reproduction,
SBOM/legal-info delivery, and installer/update/rollback testing remain separate
unfinished milestones.
