# Share configuration model

`shareconfig` defines the first version of the product's desired file-sharing
policy. It validates volume references, file-service users, relative share
paths and explicit `ro`/`rw` grants. It is not yet exposed through the HTTP API
or persisted, and it does not create users, mount volumes or configure services.

Volume IDs refer to expected canonical filesystem UUIDs, never bay numbers or
kernel device paths. The future runtime resolver must prove that a matching
volume is present, unique and qualified. UUID text in configuration alone does
not establish ownership, device health or migration compatibility.

All fields are required. Empty top-level arrays are valid; a configured share
requires at least one grant. Unknown, duplicate, differently cased, missing or
null fields are rejected, as are dangling references and conflicting grants.
The JSON document is limited to 256 KiB, 16 volumes, 128 users and 128 shares.
An empty configuration can represent an unconfigured appliance. Revision zero
is invalid; revisions will support store-level optimistic concurrency later.

Share paths are relative to their volume. `.` explicitly selects the volume
root. Lexical validation rejects absolute paths, traversal and control bytes;
it cannot establish filesystem containment. The future privileged layer must
resolve symlinks/mount boundaries safely and refuse a missing volume before
opening paths. Overlapping shares and ACL inheritance need runtime policy
before service activation. No service configuration renderer exists here yet.

File-service account names initially use a bounded lowercase POSIX subset;
share names use a bounded printable ASCII subset, excluding reserved service
names and configuration delimiters. This restriction is an initial schema
choice; international display names can be added through a reviewed revision.
Credentials, guest access, network settings, NFS client mappings and migration
instructions are deliberately outside this first share-policy document.
