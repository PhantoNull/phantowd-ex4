# Experimental cached-build host lifecycle guard

`support/build-qemu.ps1 -CachedOnly -HostLifecycleGuard` opts into a host-side
Docker controller. **It is not the default:** fake-process qualification is
not proof of a healthy real Docker lifecycle. Do not use it to adopt, retry or
clean up an older unguarded job. Retire that job independently first.

The controller keeps the existing image/two volumes, initialization and write
checks, 40 GiB headroom rule, non-root resource profile and inner timeout of
1,800 seconds plus 30-second kill grace. It never builds/pulls images, creates
volumes, prunes, restarts Docker, supplies physical devices or publishes ports.
The ordinary uncached build is unchanged. The old cached mode still lacks a
host startup bound; do not mistake its inner timer for one.

## Bounds and identity

| Phase | Host policy |
| --- | --- |
| Metadata/preflight CLI | 5 seconds per command, then up to 2 seconds for direct CLI settlement |
| Startup | 60 seconds until running is first observed or the original CLI exits |
| Running validation | 1,830 seconds from first running observation; the independent inner 1,800+30 limit is unchanged |
| Polling | Serialized, 1-second interval; a deadline can be observed after the current bounded query/poll completes |
| Auto-removal handoff | After a settled ordinary metadata refusal, up to 2 seconds for the original run CLI to exit; success still requires exit zero and explicit exact-ID absence |
| Failure/cancellation | Settle the original CLI; stop only a matching owned container with Docker's 10-second grace and a 15-second host command bound |
| Remaining cleanup | Bounded metadata and non-forced removal, followed by an explicit absence observation |

These are subprocess/wait bounds, not a guarantee against a stalled host kernel,
filesystem syscall or suspended machine. They do not extend guest/worker tests.
The maximum includes bounded in-flight queries, settlement and cleanup; startup
and running limits are not one whole-command wall-clock timeout.

Each request records a random name/label, source path, host/client PIDs, original
full container ID and lifecycle events under `artifacts/cached-qemu-runs/`.
No shell interprets Docker arguments. Before stop/removal, an inspection must
match the original full ID, generated name and label. Removal is never forced.
Killing a Docker CLI is not container retirement. A successful validation also
requires successful original CLI exit and an explicit exact-ID absence result.
An unsuccessful validation remains unsuccessful even if cleanup succeeds.

An exclusive `artifacts/.cached-qemu-active.json` prevents another guarded run
from the same checkout. It is released only after settled preflight-only refusal
or verified retirement with all observed clients settled. Unproven retirement
after missing IDs, changed ownership, failed observations or uncertain cleanup
preserves the guard and source context. Reports contain no automatic repair or
replay instructions. Reconcile
the original job before manually releasing a retained guard; never delete it
merely because a timeout elapsed. Separate checkouts share caches: they still
require external serialization. Keep Docker context/daemon and inputs stable.

## Host-only regression tests

```powershell
node support/tests/test-cached-qemu-runner.mjs
.\support\tests\test-cached-qemu-wrapper.ps1
```

The Node test launches only local fake child processes and deletes only its own
new temporary tree. Nineteen cases cover success, auto-removal before CLI exit,
validation failure, all four
preflight refusals, preflight timeout/output overflow, created-not-running, missing
ID, bad ownership/metadata, metadata/stop/removal/retirement stalls, missing automatic
removal and cancellation. The wrapper test checks opt-in delegation, unchanged
default profile/preflight and no retries. They do not run a Docker daemon or QEMU.
The test's whole-run bound is derived from all allowed phase/query/settlement
budgets, not an arbitrary ten-second cap. Diagnostics report elapsed/derived
milliseconds. No product, guest or worker deadline is relaxed by that test oracle.

Before default adoption: qualify the actual Docker argument/CID/label lifecycle,
normal auto-removal, host cancellation and failure settlement, late daemon replies,
unsettled host-client cases and retained-source reconciliation. A real external
Docker startup stall is still unresolved; synthetic tests do not diagnose or fix
the daemon, mount or networking cause. Windows/PowerShell and hosted Linux
qualifications must remain separately attributable. See [M0.1a](../ROADMAP.md#m0-engineering-baseline-and-test-reliability).
