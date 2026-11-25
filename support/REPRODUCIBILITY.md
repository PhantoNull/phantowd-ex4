# Independent clean-build diagnostics

`reproducibility.yml` builds the exact selected commit twice, without a compiler
cache or shared workspace. Outputs remain research / compile-only / flashable=no.
The existing allowlist and byte comparator are unchanged. Matching outputs do
not qualify installation, recovery, hardware or licensing completeness.

The diagnostic lane uses five sequential steps in each unique build volume:

| Phase | Build boundary | Inner wall-clock ceiling |
| --- | --- | --- |
| toolchain | Source verification, original host preflight, explicit toolchain | 60 min |
| kernel | Existing kernel-input checks and the Linux target | 20 min |
| userspace | Buildroot `target-finalize` (selected packages and host finalization) | 60 min |
| rootfs | Original default make, metadata/license/probe checks | 15 min |
| boot | Original smoke, reboot, runtime and complete service fixtures; export | 45 min |

These are diagnostic ceilings, not performance claims or an additive allocation.
The **whole job is limited to 150 minutes**, including setup and exports.
The toolchain Actions step is limited to 62 minutes, allowing its inner
60-minute timeout and 10-second termination grace to report the original error.
An inner timeout runs in the container before the Actions step ceiling. Each
failure names the phase, original exit status, elapsed time and ceiling; no retry,
proof omission, original fixture deadline relaxation or repair is introduced.
The qualified hosted run 39835254944 spans 30 min 12 s from rootfs table
generation (19:28:54Z) to the final fixture result (19:59:06Z); the boot ceiling
leaves diagnostic margin rather than treating that single observation as a
performance guarantee. It is not a change to any individual guest deadline.
The ordinary QEMU lane still uses the original single invocation. A phased cold
build must pass before this diagnostic flow can be called qualified.


## Toolchain ceiling evidence

Hosted step elapsed times in seconds on 2026-11-11:

| Run / clean leg | Toolchain | Kernel | Userspace | Rootfs | Boot |
| --- | ---: | ---: | ---: | ---: | ---: |
| [42934455097](https://github.com/PhantoNull/phantowd-ex4/actions/runs/42934455097) / one, success | 2355 | 473 | 1934 | 70 | 1969 |
| Same run / two, success | 2230 | 435 | 1870 | 70 | 1951 |
| [42991501876](https://github.com/PhantoNull/phantowd-ex4/actions/runs/42991501876) / one, success | 2349 | 456 | 1955 | 71 | 1972 |
| Same run / two, failure | 2400 | skipped | skipped | skipped | skipped |
| [43072794935](https://github.com/PhantoNull/phantowd-ex4/actions/runs/43072794935) / two, failure | 2400 | skipped | skipped | skipped | skipped |

Both failures report status 124 at the inner 2400-second ceiling while
host-gcc-final 13.4.0 is compiling. The 42-minute Actions step and 120-minute
job have time remaining at that failure. Two successful toolchain samples
finish within a minute of that old inner ceiling.

With the other measured phase maxima totaling about 75 minutes, a 60-minute
toolchain allowance plus setup can exceed the former 120-minute job limit.
The 150-minute job gives that measured path bounded headroom. Other phase
limits, clean-workspace isolation and comparison policy retain their contracts.
Both clean legs and the comparison must pass twice on the same changed head
before this ceiling adjustment is qualified.


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
