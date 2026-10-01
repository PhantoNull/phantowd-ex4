# Authenticated file-service preview

The package also defines a distinct versioned combined desired configuration
for the [atomic SMB/NFS store](../fileservicestore/README.md). That format is
not the preview request below; it requires one common transaction revision.
Neither API save nor service activation is enabled by defining that format.

`POST /api/v1/file-services/preview` validates desired SMB/NFS policy and returns
candidate configuration text. It does not save a revision, inspect storage,
run a parser or service, create users, mount disks, or authorize activation.
The embedded browser dashboard provides a standalone one-share proposal form
for this route. It does not load existing policy, save revisions or apply it.

## Request

An existing administrator session, the exact configured `Origin` (and matching
request host/transport), and one valid `X-PhantoWD-CSRF` header are required.
Obtain the session token through `GET /api/v1/auth/session` after login. Use
`Content-Type: application/json`, optionally with `charset=utf-8`. Queries,
content encodings, other media parameters and duplicate required headers are
rejected. Authentication and header checks precede body parsing.

The body contains exactly two required, non-null members: `shares` uses the
[share schema](../shareconfig/README.md); `nfs` uses the
[NFS schema](../nfsconfig/README.md), referencing the exact share revision.
For example, an unconfigured appliance can be previewed with:

```json
{
  "shares": {
    "format": "phantowd-share-config",
    "schema_version": 1,
    "revision": 1,
    "volumes": [],
    "users": [],
    "shares": []
  },
  "nfs": {
    "format": "phantowd-nfs-policy",
    "schema_version": 1,
    "revision": 1,
    "volume_revision": 1,
    "exports": []
  }
}
```

The whole body is limited to 524,544 bytes (512 KiB plus 256 envelope bytes),
including for chunked requests. Each nested policy retains its 256 KiB limit
and strict field, Unicode and structural validation. Duplicate, unknown,
case-aliased envelope members and trailing documents are rejected.

## Response and boundary

Success returns schema version 1 with `scope: "desired-policy-only"`, the
structured `samba` and `nfs` previews, and a `requirements` array. These flags
are always false: `persisted`, `applied`, `runtime_validated`, and
`activation_available`. Even an empty or syntactically valid configuration
cannot become an activation request through this endpoint.

Requirements name unresolved runtime volume identity, path/mount containment,
Unix accounts/effective access, durable configuration and service lifecycle.
Combined SMB/NFS configurations also require cross-protocol access review.
When a share and export use the same logical volume and their configured
relative paths are equal or ancestor/descendant paths, the preview adds
`cross_protocol_path_overlap` for focused review. This is a lexical warning,
not path canonicalization: symlinks, hard links, bind mounts, runtime aliases
and effective permissions remain unresolved. The general cross-protocol review
requirement is retained, and the warning never blocks, saves or activates policy.
AUTH_SYS network trust and Kerberos provisioning are flagged when applicable;
Samba grants do not restrict NFS clients. Logical `VolumeID` mount anchors
are proposals; the expected filesystem UUID is not verified by this preview
and does not prove that the backing filesystem is present or safe to use.

Errors return a generic `error` code without echoing submitted policy:

| Status | Meaning |
|---|---|
| 400 | Invalid envelope, media type, headers or body read |
| 401 | Missing, invalid or unconfigured authentication |
| 403 | Origin or CSRF check failed |
| 405 | Wrong method; `Allow: POST` |
| 413 | Request exceeds byte ceiling |
| 422 | Invalid share/NFS policy or unsupported Samba rendering |
| 503 | Existing global request gate or single-preview gate is busy |

The preview gate does not queue bodies and returns `Retry-After: 1` when busy.
It operates inside the existing eight-request server gate and read/write
timeouts. Responses are `no-store`. This is still a loopback development API,
not a security-reviewed LAN management service.

## Verification

Unit tests cover envelope/policy rejection, revision consistency, auth, Origin,
CSRF, known/unknown-length request ceilings and preview backpressure. The pure
decoder has a bounded fuzz campaign. QEMU tests exercise a nonempty preview
over HTTP and HTTPS, including missing CSRF, foreign Origin and stale volume
revisions. Those tests do not establish arbitrary runtime permissions,
hardware compatibility or production service activation.

## Internal M4.1 plan prototype

The separate [internal candidate-plan package](../internal/fileserviceplan/README.md)
is a fixture-only step toward M4.1. It compiles combined desired policy against
identity and storage snapshots, binds the candidate to policy/active/identity/
storage revisions and the identity evidence fingerprint, and refuses stale
observations. A Linux-only adapter now obtains identity evidence from
`identityowner.Owner`; the disposable ARMv5 QEMU Owner fixture exercises it
using an empty policy and synthetic empty storage, and checks that a registry
change invalidates the old candidate. There is still no production storage
roster provider. A separate synthetic combined-plan QEMU fixture validates
candidates with `testparm`/`exportfs`; this is not validation against a product
mount. The non-empty Owner/mount-owner NFS candidate also has a distinct
target-`exportfs` accept/withdraw round trip in the disposable ARMv5 guest,
which verifies the candidate against one actual synthetic mount tuple. No
daemon configuration is persisted and no product service is started/reloaded.
Plans and evidence snapshots cannot be marshaled/unmarshaled as JSON and have
no apply method. The package is not called by an HTTP route or product runtime
owner. See the package's
[implementation and limits](../internal/fileserviceplan/README.md) and
[M4 roadmap](../../../ROADMAP.md#m4-supervised-smb-and-nfs).

The current-source ARMv5 QEMU follow-up also builds a separate NFS-only,
read-only candidate from the disposable Owner's identity/local UID/GID snapshot
and the mount-owner fixed-roster snapshot of one synthetic ext2 volume. The
collector locks/revalidates every owner in its declared roster and returns no
partial snapshot; the planner binds the roster fingerprint into freshness. It
rejects altered identity or storage evidence without Samba enrollment or export
activation. This does not supply the missing production roster source or prove
complete appliance storage inventory.

The target parser fixture briefly loads that candidate into the disposable
guest's export table, validates the parsed rule and exact restoration of the
baseline after withdrawal. This is parser integration only, not product
activation or an export installed by the planner.
