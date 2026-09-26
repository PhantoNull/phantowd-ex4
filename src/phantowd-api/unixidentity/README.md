# Supplied local Unix identity observations

`Parse` reads bounded caller-supplied passwd/group streams and returns an opaque,
immutable observation. It does not open files, query NSS, read shadow or invoke
commands. Password, GECOS, home and shell fields are discarded; retained names
are copied so they cannot retain a password-bearing input string. This is not
a secure-memory-erasure guarantee. Errors never echo input or reader messages.

Input follows the local [passwd](https://man7.org/linux/man-pages/man5/passwd.5.html)
and [group](https://man7.org/linux/man-pages/man5/group.5.html) field layouts.
The parser deliberately accepts a conservative subset: exact field counts,
bounded ASCII names, decimal uint32 identities excluding the all-ones sentinel,
UTF-8 documents, no control characters other than LF, and no NIS +/- entries.
Blank/comment lines are allowed; empty/comment-only documents are refused.
Limits per input are 1 MiB, 4096 records and 16 KiB per line. Malformed, missing-field,
duplicate-name or I/O-failed inputs discard the entire observation. Duplicate
numeric identities are retained as evidence, never collapsed into one user.

`Reservations` supplies independent sorted native-registry exclusions, including
both namespaces, user/group names, primary GIDs absent from the group file and
orphan member names. It does not include file ownership or remote directory
identities. The registry still reserves retired identities and checks both
numeric namespaces when allocating a new UID/private GID.

`Assess` compares one valid native private-group account against the supplied
records, independently of desired enabled/disabled state:

| Result | Meaning within supplied files |
| --- | --- |
| absent-from-supplied-files | No matching or conflicting identity/membership was observed |
| partial-local-identity | Only the expected user or private group exists |
| matching-local-identity | Exact username/UID/primary GID and private group match |
| conflicting-local-identity | Name/number mismatch or alias, other users in the private group, or unexpected supplementary membership |

Case-folded names do not silently match an exact native identity. Other users'
primary-GID use counts as private-group membership even without a group member
list. Missing/invalid observations are errors, never absence. The zero Snapshot
cannot allocate or assess. Membership in an unrelated group is not automatically
removed, and partial state is not automatically repaired.

Even a matching result does **not** prove project ownership, authorize adoption,
verify a login lock/Samba password, or allow service activation. Local files may
not represent the full NSS view. The future privileged owner must establish
trusted file provenance, a coherent locked snapshot and files-only NSS (or
explicitly supported other authorities), recheck before mutations, account for
imported/offline ownership, and handle partial failures. Those integration and
recovery requirements remain open; no production caller enables mutations.

Host tests and fuzzing use synthetic streams. A separately guarded QEMU fixture
reads the guest files, derives exclusions while other temporary SMB users exist,
reserves an identity, creates its private group and observes partial state,
creates its no-login/no-home Unix user and verifies exact identity, then refuses
a mismatched expectation and duplicate name. It removes only that fixture user
and group afterward and requires an absent post-cleanup observation. The pinned
BusyBox `deluser` also removes its same-named group; the fixture avoids a second
blind deletion and never ignores generic command failures. This is not a generic
provisioning helper, persistent Unix account integration, Samba credential
provisioning or EX4 qualification.
