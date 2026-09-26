# Authenticated file-service preview

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
AUTH_SYS network trust and Kerberos provisioning are flagged when applicable;
Samba grants do not restrict NFS clients. UUID mount anchors are proposals,
not evidence that the expected filesystem is present or safe to use.

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
