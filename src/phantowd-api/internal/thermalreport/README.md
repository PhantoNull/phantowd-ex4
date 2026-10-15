# Internal thermal observation evaluation

M7.3e prerequisite, not a cooling controller. `Evaluate` is a bounded, pure
in-memory projection of a caller-declared roster and samples. Normal product
startup does not call it. It opens no device, path or socket, invokes no process,
reads no clock and sends no command. No HTTP, persistence, polling or history.

The trusted future provider must establish the complete hardware roster,
generation binding, monotonic clock origin, units, calibration and intervals.
Caller-supplied generations and `Qualified` flags are **not evidence of those
properties**, stable device IDs, credentials or device authority. An eight-source
limit bounds evaluation; it does not certify complete EX4 hardware coverage.
No provider is implemented or qualified here.

`Evaluate(sources, samples, now, maxAge)` preserves roster order and distinguishes:

- missing observation;
- identity/generation mismatch;
- invalid/future timestamp;
- stale observation, including the exact `age >= maxAge` boundary;
- explicit unavailable, read failure or disk-sleep report;
- unqualified/raw input;
- outside the caller-declared measurement interval;
- current observation at the supplied evaluation instant.

The original capture status remains separate when generation/time checks take
precedence. Missing status is zero, not an implicit successful read. Sleeping is
accepted only for disk sources and never supplies a current temperature. Neither
a sleep request nor the legacy bitmap qualifies the future provider's claim.

`Reading.Value` returns a number only for `Current`. A genuine zero or negative
temperature can be current; zero RPM can also be current **without implying a
healthy or spinning fan**. Raw values are always unqualified and never converted.
There are no default TTLs, safe operating thresholds, brand-name adjustments,
nominal RPM substitutions or last-good-as-current fallbacks. Measurement range
qualification is not thermal policy: an accepted value can be dangerously hot.

Source IDs are bounded logical labels, not paths/bays or persistent identities.
Duplicate/unknown IDs, incompatible units, malformed statuses/ranges and oversized
rosters fail as a whole with a fixed error and no partial report. Input slices
must not change during evaluation. Returned immutable readings do not alias
input or returned slices. Reports/readings reject JSON in either direction.

All durations use one caller-established monotonic origin. Age subtracts only
after checking `0 <= capturedAt <= now`, without deadline-addition overflow.
An immutable report is a **point-in-time snapshot**: keeping it does not advance
its age. The consumer must evaluate again against trusted current time before
use. `AllReportedCurrent` refers only to that declared roster/instant, not safe
cooling, complete census, controller liveness, a retained lease or permission to
reduce the fan, start a workload or shut down.

Host tests cover explicit faults, exact age/range boundaries, extreme durations,
roster validation, private/copy behavior and fixed-count fuzzing. The existing
standard ARMv5 self-test also evaluates invented sources/times/qualification,
with no new I/O or guest boot. Its marker is required by `qemu-smoke.sh`.
Cross-compilation alone is not guest execution; consult implementation status
for the exact checks actually run on a checkpoint.

Next: qualify actual sensor/tach input, raw count/window/calibration provenance
and source lifecycle before composing a thermal supervisor. No command codec,
actuator, regulator, safe response, shutdown transaction or NAS test is authorized
by this component. See [legacy evidence and remaining gates](../../../../board/wd/ex4/THERMAL-RESEARCH.md).
