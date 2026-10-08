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

The earlier parser correction introduced no schema/signing/trust-root/CLI
change or device writer. A valid
report remains point-in-time integrity evidence with installation/hardware
authority false. Product trust provisioning, retained staged bytes, persistent
rollback policy, target transaction and recovery remain unimplemented.

## Unsigned metadata producer — M10.2c

`BuildUnsignedManifest` and the host `build-release-manifest` command prepare
deterministic existing schema1 JSON from explicit declarations, payload names/
roles and a caller-supplied raw public key. They accept no private key, do not
sign and create no VerifiedManifest or installation authority. Caller source
commit, component versions, model and exact revisions are declarations, not
provenance or qualified compatibility. No defaults infer board compatibility.

Reuse all semantic/structural validators and bounded regular-payload hashing.
Admit at most16 explicit payloads/revisions, 1 GiB/member, 2 GiB/whole set and
64 KiB encoded JSON. Validate declarations/encoding before payload access;
preflight the complete size set and updated encoded size before any hash read.
Reject nonregular/symlink/missing/empty files, observed identity/metadata/root
drift and incomplete results. Sort copied revision/payload lists, measure every
size/digest, and emit complete bytes only after all checks. Read failures do not
retry; input payloads are never written. Observations do not exclude privileged
in-place writes, prove original build inputs or provide retained staging.

Actual CLI regression first reports the command absent, then passes. Existing
verifier round-trips fixture-only signatures over exact output while keeping
installation/hardware authority false. Windows whole toolkit vet/tests and
pinned Go1.26.8 Linux whole toolkit vet/tests plus producer/CLI race-count3 pass.
Actual Linux FIFO/directory-symlink refusal and kernel open/access observation
prove over-budget whole-set refusal before payload opens, with a positive read
control. Sparse disposable files allocate no GiB of data. No runtime API, guest,
firmware build, signing job, trust provision, release publication or device
transaction is qualified by these host-only tests.
