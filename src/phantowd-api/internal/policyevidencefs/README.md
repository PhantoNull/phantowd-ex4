<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Retained policy-operation observation — experimental M1.3b.3

Linux-only private collector over the fixed experimental layout below. It
supplies the existing pure matcher with actual bounded file reads under retained
original locks. It is not product boot wiring, a second store, journal writer,
recovery engine, durable quarantine, consumer lease or service admission.
No NAS installation path, physical medium or writer protocol is selected.

The QEMU fixture now obtains intent/base/candidate data from the separate private
preparer and compares its candidate with an actual temporary Store commit. The
receipt used for matcher cases remains invented fixture data, never a preparation
result or proof of a durable operation. No observer runtime behavior is changed.

```text
trusted-state-root/
  policy/
    nas-services.json       # optional current coherent NAS policy
    .nas-services.pending   # optional metadata-only evidence; always review
  operations/
    intent.json             # optional private schema1 operation record
    receipt.json            # optional private schema1 local-confirmation record
```

## Lifetime contract

`Open(ctx, root, expectedInstallationID)` captures trusted in-process inputs;
neither HTTP nor an operation supplies role names, ownership, codec or backend.
Parents, provisioning, a suitable local filesystem and cooperating writers are
external prerequisites. The expected ID is an assertion, not provenance or
protection against cloned/restored state. The experimental layout is not an
approved product state bundle or complete future publication namespace.

Retain owned0700 root/policy/operations directories and their exclusive flocks
in that order. The **actual policy-directory flock** excludes the existing Store;
a root/sibling flock alone cannot do so. Require complete unique kernel mount
identity (`STATX_MNT_ID_UNIQUE`), no fallback to a recyclable ID or inode/device
equality. Open descendants with `openat2` no-symlink/no-magic-link/no-cross-mount
resolution. Independently recheck the original absolute root path against the
held root and unique mount; a path witness never replaces the original lock.
Trusted ancestors must remain stable; this is not an all-history namespace monitor.

Completely census the bounded fixed names. Retain original owned0600 single-link
regular current/record objects, with no-atime/nonblocking/read-only opens. Zero
and excessive present documents refuse; failed reads never become absent.
Use bounded read-at chunks and compare held/named identities before and after
the pure match. Retain directory AND file mutation watches: any event, loss or
overflow refuses further observations. Pending publication is metadata-only;
no bytes are read, promoted, deleted or adopted when it exists.

`Observe` serializes complete fresh reads, clears owned temporary byte buffers
best-effort, and returns only the existing redacted diagnosis. Every kind grants
**no action**, including matching local confirmation. Cancellation before admission
does not poison the lifetime; drift, in-flight cancellation/read uncertainty or
invalid content latches review. Errors contain only fixed classes and standard
`ctx.Err()`, never private cause text. Byte/chunk limits cannot interrupt a blocked
kernel filesystem call. Copies/zero handles refuse; formatting and generic JSON
do not transfer or disclose authority. Malicious in-process code/root is excluded.

`Close` serves no consumers. First uncertainty is terminal: preserve remaining
originals and metadata, never retry a raw descriptor. A failed close does not
prove that its kernel lock survived. Uncertain constructor cleanup may return
a nonnil reviewed handle **with an error** to preserve unattempted originals;
callers must not treat that as a successful open. No instance state is a durable
quarantine or proof of earlier fsync returns, browser receipt or first enrollment.

## Verification and remaining gates

The WSL kernel used for native checks lacks unique mount identity: it verifies
unsupported refusal, not the positive filesystem lifecycle. Positive unit cases
are explicitly skipped there, not counted as passed. Native Windows does not
execute this Linux-only package. Separate actual ARMv5 Linux6.18 QEMU fixtures
exercise all six diagnoses using a nonempty three-protocol policy, repeated
actual-Store exclusion and lock release, stable FD counts, four self-bind mount
substitutions, nine unsafe layouts, pending/write-close/cancel/read/watch faults,
private/copied handles,12 concurrent reads and controlled close uncertainty.
Injected faults are not physical EIO or kernel-close qualification.

The standard guest requires two exact filesystem receipts across API restart;
host controls reject missing/one/duplicate/lookalike receipts. The observer is
read-only, but its QEMU fixture creates/disposes synthetic tmpfs files, takes
self-bind mounts and probes the actual Store only on those temporary files.
No new guest stage, persistent image/volume, HTTP route or NAS operation is added.

Still required: complete constructor/read/close/watcher fault and race campaigns,
explicit atime/content/ownership/bounds qualification on supported media,
independent writer-process and namespace history tests, product namespace and
filesystem/provisioning decisions, one-attempt publication, reconciliation and
complete boot admission. See the [design](../policyevidence/COLLECTOR-DESIGN.md)
and [recovery requirements](../revisionstore/RECOVERY-DESIGN.md). This prototype
does not satisfy those later gates or make the firmware installable.
