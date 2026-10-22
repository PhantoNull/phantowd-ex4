# Independent clean-build diagnostics

`reproducibility.yml` builds the exact selected commit twice, without a compiler
cache or shared workspace. Outputs remain research / compile-only / flashable=no.
The existing allowlist and byte comparator are unchanged. Matching outputs do
not qualify installation, recovery, hardware or licensing completeness.

The diagnostic lane uses five sequential steps in each unique build volume:

| Phase | Build boundary | Inner wall-clock ceiling |
| --- | --- | --- |
| toolchain | Source verification, original host preflight, explicit toolchain | 40 min |
| kernel | Existing kernel-input checks and the Linux target | 20 min |
| userspace | Buildroot `target-finalize` (selected packages and host finalization) | 60 min |
| rootfs | Original default make, metadata/license/probe checks | 15 min |
| boot | Original smoke, reboot, runtime and complete service fixtures; export | 45 min |

These are diagnostic ceilings, not performance claims or an additive allocation.
The **whole job remains limited to 120 minutes**, including setup and exports.
An inner timeout runs in the container before the Actions step ceiling. Each
failure names the phase, original exit status, elapsed time and ceiling; no retry,
proof omission, original fixture deadline relaxation or repair is introduced.
The qualified hosted run 39835254944 spans 30 min 12 s from rootfs table
generation (19:28:54Z) to the final fixture result (19:59:06Z); the boot ceiling
leaves diagnostic margin rather than treating that single observation as a
performance guarantee. It is not a change to any individual guest deadline.
The ordinary QEMU lane still uses the original single invocation. A phased cold
build must pass before this diagnostic flow can be called qualified.

`Compare independent outputs` retains its 10-minute whole-job budget: first and
second downloads each have a 3-minute ceiling, then comparison has an inner
90-second timeout under a 2-minute step. Local comparison of two copies of the
existing 11-file, 99,151,997-byte qualified set took 0.584 seconds at one CPU.
This supports the CPU/I/O comparator budget only: it is **not** independent-build
equality or evidence about hosted artifact-download latency. Record the actual
successful hosted download/comparison durations before claiming that whole-job
budget qualified. Failure logs are retained separately for one day, not compared
as image outputs. No rescue inputs, proprietary binaries or physical devices
are used by this diagnostic flow.
