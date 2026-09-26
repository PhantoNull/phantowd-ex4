# Samba share-policy preview

`Build` converts a validated [share configuration](../shareconfig/README.md)
into deterministic share sections and a structured permission preview.
It does not read files, create accounts, mount storage or start/reload Samba.
The authenticated [preview API](../fileservice/README.md) exposes the candidate
without applying it. Browser controls are not implemented yet.

## Contract

- The preview retains the desired revision and required volume IDs/UUIDs.
  Proposed mount anchors are `/srv/phantowd/volumes/<filesystem-uuid>`:
  independent of bay enumeration, but **not yet provisioned or verified**.
- Only referenced volumes appear in the requirements. Collections and grant
  lists are sorted, without modifying the caller's configuration.
- `valid users` contains exactly the explicitly granted local account names;
  `read list` contains ro grants and `write list` contains rw grants. All
  shares default read-only, with guest access disabled. No `force user`,
  `force group`, account mapping or administrative-user bypass is generated.
- Symlink following and wide links are disabled. Creation masks limit files
  to 0660 and directories to 0770; they do not create or grant POSIX ACLs.
- Macro syntax (`%`), quotes, configuration delimiters/comments and ambiguous
  path whitespace are refused rather than escaped. The base model permits
  some names that cannot yet be represented by this Samba renderer; migration
  must report those limitations, not rename paths or silently omit shares.
- Lexically overlapping shares on a volume are refused until an explicit ACL
  policy exists. Distinct UUIDs in JSON do not prove distinct physical mounts.

The access lists describe the Samba policy ceiling, **not effective access**.
Linux permissions/ACLs, account provisioning and authentication still apply.
Before activation, the service layer must verify each unique filesystem's
mount identity, path/symlink/nested-mount containment and effective POSIX ACLs;
it must prevent writes into a system-directory fallback if a volume disappears.
Credentials and administrator accounts remain separate from share grants.

The returned text contains share sections only. The future service supervisor
must supply and validate the complete global security/network/state profile,
retain last-known-good configuration and coordinate volume loss and restart.
The preview is not an activation authorization, even if `testparm` accepts it.

## Validation

Unit tests check deterministic output, ro/rw/denied users, identity retention,
empty/root policies, no caller mutation, unsafe interpolation and overlapping
paths. A bounded fuzz campaign exercises decoding and preview generation.

The QEMU self-test writes a fixed temporary candidate and queries the target's
`testparm` for the rendered access lists, path and safety options. It does not
launch another Samba daemon or replace the guest's existing smoke share.
The host test skips explicitly when `/usr/bin/testparm` is unavailable; the
actual ARMv5 smoke must execute it and emit its required readiness marker.

An optional host parser container is defined in
[`smb-parser-tests.Dockerfile`](../../../support/docker/smb-parser-tests.Dockerfile).
It uses the same pinned Debian base/snapshot as the build environment, runs as
UID 65534 and contains only host test tools, never firmware packages. From the
repository root, build the test binary (Go 1.26 or newer required) and image:

```sh
cd src/phantowd-api
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -mod=vendor -tags=qemu -c -o ../../artifacts/phantowd-api-linux.test .
cd ../..
docker build -f support/docker/smb-parser-tests.Dockerfile -t phantowd/smb-parser-tests:bookworm-20260925 .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 64 --tmpfs /tmp:rw,nosuid,nodev,size=32m --mount "type=bind,source=$PWD/artifacts,target=/tests,readonly" phantowd/smb-parser-tests:bookworm-20260925
```

The Debian parser check is complementary; it does not replace target-version
verification, authenticated SMB transfer tests or EX4 qualification.
Parameter semantics are documented in the official
[Samba configuration manual](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html).
