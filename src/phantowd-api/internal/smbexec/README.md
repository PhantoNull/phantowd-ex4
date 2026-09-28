# Internal trusted Samba passdb executor

This Linux-only internal package implements the fixed command adapter for
M2.4 first enrollment. It is not a service, HTTP/RPC endpoint, or account
manager. The caller must be the root-side `identityowner.Owner`; it binds one
executor when the owner opens and holds the existing owner lock around every
observation, journal transition, and mutation.

## Command boundary

- Executables are fixed absolute paths: `/usr/bin/pdbedit` and
  `/usr/bin/smbpasswd`.
- The startup-supplied Samba configuration path is not request data. It must be
  absolute, non-symlinked, a root-owned regular file, not group/other writable,
  and no larger than 1 MiB. The child receives it through an inherited file
  descriptor (`/proc/self/fd/3`), not a client-selected path. The executor pins
that opened inode until `Owner.Close`; later replacement of the path cannot
retarget an operation. The `Owner` takes ownership of the executor at open and
closes it after operations drain, or immediately if open fails.
- Child environment is restricted to a fixed `PATH` and `LC_ALL=C`. Commands
  have a ten-second deadline; observation output is capped at 1 MiB. Mutation
  output and stderr are discarded, and errors are redacted.
- `Observe` lists passdb metadata with `pdbedit -L -v -s`, then returns only the
  exact requested Unix name, owner-supplied UID/GID, SID, and disabled bit.
  Missing or ambiguous/malformed target records fail closed. Password hashes
  and the full command output are not exposed.
- `CreateDisabled` invokes `smbpasswd -a -d` with no password input. It has no
  enable command. The parent journal verifies that the new entry is present
  and disabled before recording confirmation.
- `SetPasswordDisabled` invokes the pinned
  `smbpasswd -s --set-password-disabled` extension. Password bytes are sent
  only as the two expected stdin lines; they are absent from argv, environment,
  diagnostics, and the journal. The parent verifies the same SID remains
  disabled before recording success.

The executor does not create Unix accounts, enable Samba accounts, implement
replacement/retirement, repair pre-existing state, retry an uncertain command,
or serve client protocols. A missing reply or uncertain result remains a
`review-required` operation under `smbprovision`.

## Verification and remaining integration

Root-run Go/race tests exercise fixed arguments, exact-record parsing,
configuration checks and path-replacement resistance, stdin-only secret
delivery, output clearing, and redacted failures. The ARMv5 QEMU fixture runs this same executor against a
disposable Samba passdb and private test configuration. This verifies the
adapter on the pinned Buildroot guest; it does not qualify the real EX4 Samba
configuration/passdb location, concurrent non-cooperating root writers,
power-loss durability, or an installed firmware service.

The executor is not wired to product service startup. Before that, the project
must choose and provision the persistent Samba configuration/passdb paths,
define ownership and startup ordering, connect the fixture-only internal v2
channel to product startup and HTTP authorization, and define operator handling
for review-required state. No HTTP credential endpoint or automatic enable path
exists in this slice.
