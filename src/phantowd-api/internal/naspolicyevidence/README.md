<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Private NAS operation evidence

`Inspect` compares complete in-process observations with the fixed NAS decoder
and SHA-256 of exact current bytes. Nil records mean known absence; incomplete
collection returns unavailable. Invalid/unsupported policy remains distinct.
Records are flat strict JSON, schema1, at most4096bytes; IDs are nonzero128-bit
lowercase hex, revisions positive/consecutive, digests canonical SHA-256 hex.

Only a redacted classification returns. Matching records do not prove origin,
historical sync, client acknowledgement, absent base bytes, pristine state or
permission. Hashes are not authentication. No file I/O, writer, replay, admission,
HTTP, service or device operation exists here. Callers must not mutate inputs
concurrently. [Collector/writer prerequisites](../revisionstore/RECOVERY-DESIGN.md).
