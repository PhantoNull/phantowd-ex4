# Host release verification boundary

## Strict manifest and bounded payload task contract (before implementation)

1. **Input/authority:** exact signed manifest bytes, already capped at64KiB;
   fixed schema1 root/artifact field spellings and required structure. The
   caller supplies the separate trusted key and exact target/channel. Reject
   case aliases, duplicates, null, malformed UTF-8/surrogates and wrong shapes;
   never infer trust from GitHub metadata or syntactic acceptance.
2. **Transition:** structural validation produces no partial VerifiedManifest.
   Preserve all signature/key/schema/target/channel/version/tag/hash gates.
   Regular payload reads are bounded by signed size plus one detection byte;
   reject changed opened size before hashing and short/long/drifting reads.
3. **Failure:** malformed signed input never reaches payload I/O or temporary
   GitHub payload staging. Structural diagnostics do not echo input fields or
   values. Read uncertainty does not retry or grant installation authority.
4. **Boundary:** existing host verifier and its GitHub caller only. No manifest
   schema, CLI option, trust-root, persistent rollback policy, device installer,
   firmware build, target privilege or hardware operation is introduced.
5. **Acceptance:** regression first demonstrates signed case-alias acceptance;
   strict root/artifact shape and encoding cases plus positive escaped-name
   controls, bounded read seam and real temporary files, actual HTTP fixture
   request counters. Run whole Windows host vet/tests and pinned Linux host
   vet/race before publication. No QEMU rebuild is required for host-only code.

## Evidence and remaining authority

The signed case-alias regression fails twice on the previous implementation:
Go accepts root/artifact case aliases and case-variant duplicate fields. The
fixed schema scanner rejects these before producing a VerifiedManifest; no
signature bypass is claimed. Complete Windows host vet/unit and pinned Go1.26.6
Linux whole host vet/race pass. Actual HTTP fixtures refuse seven malformed
signed variants after one manifest/signature request each and zero payload
requests. Positive escaped-key/whitespace controls still verify complete bytes.
Tests cover every root/artifact required/null field, bounded lists, wrong shapes,
duplicate escaped names, encoding, trailing/deep/oversized input and redaction.
A continuously producing reader is stopped at signed size plus one; existing
regular-file payload, size/hash, symlink and missing-file checks remain in force.

No schema/signing/trust-root/CLI change or device writer is introduced. A valid
report remains point-in-time integrity evidence with installation/hardware
authority false. Product trust provisioning, retained staged bytes, persistent
rollback policy, target transaction and recovery remain unimplemented.
