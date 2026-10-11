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

## Tests

From the repository root, `support/test-lab-tools.ps1` runs the complete offline
toolkit checks. HTTP/TLS tests use local synthetic fixtures; no public firmware
or NAS is requested. They count requests to prove malformed API metadata stops
before manifest/signature/payload downloads, and retain positive signature/hash
and extensible-metadata controls. `FuzzDecodeReleaseMetadata` exercises bounded
structural decoding only, not cryptography or a device transaction.
