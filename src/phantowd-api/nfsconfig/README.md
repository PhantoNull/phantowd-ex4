# Desired NFS export policy

This package validates a separate version-1 NFS policy against an exact
[shared volume-configuration revision](../shareconfig/README.md) and builds a
candidate exports table. It does not call `exportfs`, write `/etc/exports`,
mount anything or start an NFS server. There is no NFS policy store or HTTP
configuration endpoint yet.

## Schema and validation

All fields are required. The document contains `format`, `schema_version`,
its own `revision`, the referenced `volume_revision`, and `exports`. Each
export has a unique stable UUID `id` (used as its NFS fsid), `volume_id`,
`relative_path` and one or more `clients`. Each client explicitly supplies:

| Field | Supported values |
| --- | --- |
| `network` | Canonical IPv4/IPv6 CIDR, including /32 or /128 for a single host |
| `access` | `ro` or `rw` |
| `squash` | `root` or `all`; no unsquashed-root mode |
| `anonymous_uid`, `anonymous_gid` | Positive 32-bit numeric IDs, excluding the all-ones sentinel |
| `security` | One explicit flavor: `sys`, `krb5`, `krb5i` or `krb5p` |

Unknown, duplicate, differently cased, null or missing fields are refused,
as are malformed Unicode escapes that would silently change a path. Limits
are 256 KiB JSON, 128 exports and 64 client rules per export. Empty exports
is a valid unconfigured policy. A stale shared-volume revision is refused.

The policy rejects unrestricted /0 rules, wildcards, DNS/netgroup selectors,
multicast/reserved IPv4 ranges, mapped IPv6 forms, noncanonical prefixes and
overlapping client rules. Export paths must be relative and non-overlapping
on each volume. UUID fsids exclude the special NFSv4 root/0 identity. The
future store must preserve fsid bindings across revisions, not recycle an ID
for an unrelated export or filesystem.

## Rendering and access boundaries

The deterministic preview uses the same UUID-based mount-anchor proposal as
Samba and emits explicit `sync`, reserved-source-port policy, root squashing,
anonymous IDs, security flavor, fsid, no-cross-mount and mountpoint guard.
Spaces, quotes and comment characters in paths use octal escaping.
Whole-volume exports use `no_subtree_check`; subdirectory candidates use
`subtree_check`, whose rename/filehandle behavior still needs qualification.

The mountpoint guard prevents an unmounted anchor from being exported, but it
does not establish that the **correct** filesystem is mounted there. A future
activator must independently verify identity, mount/path/symlink containment,
POSIX permissions and absence of nested-export surprises. No protection here
qualifies arbitrary legacy disks or data-loss behavior.

NFS numeric identities and host access rules are not Samba account grants.
`root_squash` only remaps root; it does not distrust all identities claimed by
an AUTH_SYS client. `all_squash` maps every request to the selected account.
The activator must validate these IDs against provisioned storage identities,
reject system-account collisions and account for actual filesystem ACLs.

The preview flags AUTH_SYS use and Kerberos prerequisites explicitly. `sys`
provides no cryptographic authentication/encryption and needs a trusted or
separately protected network. `krb5p` requires a working KDC, service keys,
identity mapping and target support; merely rendering it does not provision
Kerberos. There is no implicit fallback to `sys`. RPC-with-TLS/mTLS remains
unimplemented and requires separate kernel/userspace/certificate integration.

These choices follow the upstream
[`exports(5)` contract](https://man7.org/linux/man-pages/man5/exports.5.html).

## Evidence and next work

Host unit/fuzz tests exercise strict decoding, access/mapping rules, IPv4/IPv6,
escaping, stale revisions, duplicate/overlapping rules, stable rendering and
caller-state isolation. The QEMU-only probe checks these synthetic contracts
on ARMv5; it does not install the candidate or validate it with `exportfs`.

Real target-parser and authenticated/denied-client tests, persistent policy
transactions, protected transport, service supervision, mount-loss handling
and cross-protocol ACL tests remain required. This table does not select NFS
protocol versions or create an NFSv4 pseudoroot. The existing guest service
still tests only NFSv3/TCP; qualified NFSv4.x support remains a product goal.
