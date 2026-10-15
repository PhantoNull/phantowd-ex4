# Host GitHub release inspection

`Inspect` checks one exact public release tag. It never installs firmware or
accesses a device. GitHub is the transport, not a cryptographic trust anchor:
the caller supplies the Ed25519 public key and exact model/revision/channel.
See the [toolkit commands](../README.md) and
[signed-manifest boundary](../releaseverify/README.md).

## API metadata boundary

Before requesting any asset, the bounded API response must be an object with
exact decoded names and non-null typed values for `id`, `tag_name`, `draft`,
`prerelease`, `immutable` and `assets`. Each asset requires `id`, `name`, `size`,
`url` and `state`. Duplicate fields at those object levels and case aliases of
consumed fields are refused. Valid JSON escaping of a canonical name is accepted;
escaped duplicates remain duplicates. Known string values cannot rely on Unicode
replacement after surrogate repair. The received document must be valid UTF-8.

Additional GitHub fields remain supported, including nested author/uploader
objects and Unicode descriptions. Their contents are ignored, not recursively
qualified as application metadata. The response stays capped at 1 MiB and the
asset list at 18 entries; the list bound is checked before typed decoding.
Missing publication flags never become reassuring default `false` observations.
Semantic ID/state/tag/channel/immutable and exact asset-URL checks still follow.

Only then fetch the bounded manifest and detached signature. Exact-byte
signature, target, channel, signed tag and optional installer-version checks
precede payload staging/download. Payload size/hash verification, private
temporary-directory cleanup, redirect restrictions and signed-query redaction
remain unchanged. Neither API metadata nor a successful host verification
authorizes installation, establishes physical compatibility or provisions trust.

Optional `Options.RequireUpgradeFrom` adds a strictly-newer-version prerequisite
against a caller-supplied current version. Invalid nonempty syntax fails before
any HTTP; empty preserves the existing behavior. After the gates above, equal/
older signed versions return `upgrade_prerequisite` and refuse before payload
requests or creation of the temporary staging directory. Newer versions still
require every payload hash. This is exposed by the host CLI's opt-in
`--require-upgrade` with `--current-version`, not a device anti-rollback policy.

## Public transport errors

Request and response-body read failures use a fixed public error message,
including manifest, detached-signature and payload streams after redirects.
An underlying reader may include the signed download URL in its error; that
cause must not appear in `Error()` output. `errors.Is`/`errors.As` still expose
the original cause to trusted code, so do not separately log the unwrapped
cause publicly. Redaction does not turn a failed download into verification,
trigger a retry or change existing byte limits, synchronization or cleanup.

## Tests

From the repository root, `support/test-lab-tools.ps1` runs the complete offline
toolkit checks. HTTP/TLS tests use local synthetic fixtures; no public firmware
or NAS is requested. They count requests to prove malformed API metadata stops
before manifest/signature/payload downloads, and retain positive signature/hash
and extensible-metadata controls. `FuzzDecodeReleaseMetadata` exercises bounded
structural decoding only, not cryptography or a device transaction.

Body-read regressions use real local HTTP/TLS redirects, then inject one
URL-bearing error at the external reader boundary after reading one byte.
They verify redaction, retained cancellation/cause, one read/close, no later
asset request or verification success, and an empty temporary staging parent.
Whole Windows toolkit vet/tests, pinned Linux Go 1.26.8 whole toolkit
vet/tests/race and the GitHub reader's race-count3 pass locally. This synthetic
fault does not prove that a particular real GitHub outage leaks credentials;
no public download or device operation is part of these tests.
