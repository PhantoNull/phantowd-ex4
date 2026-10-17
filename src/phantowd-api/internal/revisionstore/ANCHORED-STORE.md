<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Experimental anchored Store prerequisite

`OpenAnchoredWithCodec` is an internal Linux constructor for a **trusted fixed
child** of a borrowed original parent directory. It is not a transaction Owner,
record publisher, recovery engine, bootstrap decision or service authority.
No product caller or HTTP endpoint uses it. Existing path-based adapters keep
their original behavior, including their separate reopening/sync semantics.

## Contract

- The caller retains the original parent until every child Store is closed;
  never close it concurrently with Store operations. No parent descriptor is
  adopted, duplicated or closed by this constructor.
- Open a new child descriptor with `openat2` beneath/no-symlink/no-magic-link/
  no-cross-mount resolution. Retain its **actual exclusive directory flock**.
  Require owned0700 directories and the existing owned0600, single-link, bounded
  regular current-file rules. Missing kernel support refuses; no weak fallback.
- Opening validates but never initializes, fsyncs, rewrites or removes evidence.
  A complete bounded fresh census allows only the optional current document.
  Pending and unknown entries refuse, including when introduced after opening.
- `LoadExact` observes a bounded original file, compares held/named metadata
  before and after reading, validates the codec, and returns newly owned exact
  bytes plus the decoded snapshot. No re-encoding or sync establishes success.
  Strict reads use no-atime opens. Failures return no partial data/value.
- Checks compare the borrowed parent, held child and a fresh confined child
  witness; loss of this binding or census completeness latches uncertainty.
  Removing an offending fixture entry does not revive that instance.
- Any error after a strict mutation attempt starts, even pre-rename `ErrIO`,
  prevents subsequent reads/commits through that instance. It never deletes a
  pending entry. Pre-effect invalid revision/schema refusal need not poison it.
  Successful commits may advance again: **this is not one logical operation's
  single-attempt guard**. A future coordinator must supply that stronger fence.

## Deliberate limits

Trusted stable ancestors, exclusive provisioning, cooperating writers and a
suitable local filesystem remain external prerequisites. This constructor does
not qualify the parent's absolute pathname, unique root mount identity, history
of changes between checks, consumer exclusion, installation provenance or the
origin/confirmation of valid current contents. It has no retained file watch or
original-current lifetime across calls. It does not replace the separate
[read-only evidence collector](../policyevidencefs/README.md).

Uncertainty is in-memory, not durable quarantine. Reopening cannot prove earlier
fsync results, browser receipt or permission to retry/reconcile. Constructor and
Close fault coverage remains incomplete; no retention of a kernel lock after an
uncertain close is promised. Generic error wording is not a recovery instruction.
The selected product direction is current policy plus per-operation bundles.
This primitive does not freeze that format, select a physical state medium or
provide the complete product transaction/recovery Owner.

## Verification scope

Native Linux controls exercise actual child-lock exclusion, exact whitespace and
defensive bytes, no-atime metadata, pending/unknown preservation, replacement or
borrowed-parent closure, late-entry refusal for all three operations, successful
revision advances and pre-effect revision refusal. Deterministic callbacks inject
partial/short writes, file sync, close, rename and directory-sync errors and
verify no retry. These are synthetic failures, not physical I/O/close guarantees.

The QEMU-only evidence fixture additionally uses this constructor on fresh tmpfs
files: real coherent NAS-policy commit/readback parity, actual legacy Store Busy,
late pending preservation and sticky refusal after fixture-only restoration.
It remains part of the existing standard smoke, not a new stage or product hook.
Neither these tests nor their file/directory fsyncs qualify power loss, EX4 storage,
a complete intent/policy/receipt transaction or a deployable firmware release.
