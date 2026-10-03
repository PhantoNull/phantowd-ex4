# Internal generation-bound SMART collection coordinator

M8.5b prerequisite, **synthetic host/ARMv5 fixtures only**. This package runs
no process, opens no path/device, sends no ioctl and installs no service. Normal
startup does not call it; there is no HTTP/RPC, scheduler, history or persistent
write. It does not grant the metadata broker SMART authority.

`New` fixes one trusted backend, a transient major/minor/diskseq tuple, a nonzero
complete-census token and a 1..30 second cooperative operation budget. It neither
performs I/O nor accepts a replacement backend/target/options at collection.
The token is not a stable disk/volume ID, credential or self-authenticating proof.
The future trusted provider must supply complete, unambiguous whole-disk
eligibility and retain the correct generation-bound descriptor. No such physical
provider or least-privilege command boundary is implemented by this coordinator.

Collection admits only one operation, with no queue or detached worker. It
refuses value copies of its constructor-issued handle, preventing a copy from
forking close/review state while retaining the same backend. It
observes the exact source before capture, requires the backend to have no active
process, captures once, verifies settled ownership, parses with `smartreport`
and re-observes the exact source before publication. Missing/incomplete/ambiguous
or changed source permanently quarantines the instance; restoration cannot
resume it. Signals, timeouts, cancellation, non-8-bit exits, oversized output and
malformed reports return no sample, never a reassuring partial success.

The backend is trusted in-process infrastructure, not HTTP input or an arbitrary
callback supplied per operation. `Capture` must own and reap its exact child,
pin executable/runtime/options/device, stream-bound output and enforce its
deadline. Returned buffers transfer exclusively to the coordinator until return.
The coordinator checks stdout<=64KiB/stderr<=4KiB **after return**; this is an
acceptance bound, not proof that the backend limits allocation or kernel stalls.
Context deadlines require backend cooperation; no goroutine pretends to cancel
an uninterruptible device operation. State-machine tests use fakes. A separate
opt-in `smartcapture` adapter uses the actual `processowner.NewCapture` and
generic-only static producer in the existing ARM926 replay boot: fixed regular
stdin, independent pins, genuine ordinary exit, stream-bounded stdout/stderr,
settled process verification and seven report projections. An additional
source-change case discards the genuine report and keeps review after restoration.
Its source census/generation is explicitly invented; the adapter is test-only,
not a device backend, authenticated runtime, isolated root or product service.

After accepted capture, settled ownership is checked with a separate bounded
one-second verification context, even when collection was canceled. Uncertain
process cleanup quarantines and retains the backend reference. `Close` cannot
race active collection, signals/stops nothing and releases that reference only
after explicit settled verification. It does not close the backend's device/code
descriptors: their lifecycle remains with the trusted provider, which must not
mutate/close them while attached. A later explicit Close may verify absence;
it never retries capture, sends signals or clears review.

Samples retain only immutable parser projection and transient generation. They
cannot be serialized; report bytes, stderr, backend errors, names/serials/WWNs,
paths and census token do not escape. Reported pass remains reported pass, not
disk/data/RAID health. Partial reported failure and historical flags remain
separate. There is no boot-persistent age or historical identity claim.

Next qualify the isolated fixed-command/runtime and actual trusted device provider.
The regular-stdin replay proves process/exit/cleanup behavior for this synthetic
fixture only; it does not establish physical ATA transport or ioctl authority.
Only after collection/standby qualification add history, alerts, jobs and UI.
Physical disks, thermal/recovery, self-test mutation and product activation
remain separately gated. Host state-machine evidence is not device provenance.
