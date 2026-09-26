# Supplied local Unix identity observations

`Parse` reads bounded caller-supplied passwd/group streams and returns an opaque,
immutable observation. It does not open files, query NSS, read shadow or invoke
commands. Password, GECOS, home and shell fields are discarded; retained names
are copied so they cannot retain a password-bearing input string. This is not
a secure-memory-erasure guarantee. Errors never echo input or reader messages.

## Verified local reader (Linux)

`ReadLocal(directory, ownerUID)` pins exactly `passwd`, `group` and
`nsswitch.conf` under an explicitly supplied trusted directory. It refuses
symlinks in the directory path or children, child mount crossings, non-regular
files, hardlinks, unexpected ownership, group/other write bits and special mode
bits. `openat2` protections are mandatory, with no weaker fallback. Special
objects are first classified using O_PATH, so FIFO/device contents are never
opened for I/O. Verified regular files are reopened through their retained
`/proc/self/fd` references, not replaceable directory names.

All three metadata baselines are captured before reading. After parsing, the
reader checks retained objects, named entries and the directory anchor again:
device/inode, ownership, mode, link count, size and modification/change times.
An observed change or error discards the whole snapshot. This is a bounded
observation window, **not an atomic cross-file transaction or authorization
lease**. It does not detect changes made after return or qualify a malicious
privileged writer. Trusted parent directories and serialization of all account
writers remain caller obligations. Kernel filesystem I/O may block and needs
supervision in the eventual privileged executor. No retries occur implicitly.

`FilesOnlyNSS` requires exactly one `passwd: files` and `group: files` entry;
an optional `initgroups` entry must also contain only `files`. Duplicate/case-
variant identity entries, remote/compat/systemd sources, action clauses and
malformed or oversized input are refused. Other databases, such as DNS, are not
restricted. This validates the selected identity configuration, not a daemon's
cached NSS state or its password-verification source. Shadow is never read.
See the [NSS format](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html).

The guarded ARMv5 fixture now uses this reader for every observation of guest
`/etc`, including its post-cleanup check. Host tests use private temporary
directories and deterministically replace/rewrite/chmod/remove files and replace
the directory between content reads and final checks. None of these tests opens
or modifies production account databases.

## Supplied-document parser and assessment

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
not represent the full NSS view. The verified Linux reader adds source and
files-only configuration checks, but the future privileged owner must establish
a coherent locked snapshot and qualified daemon identity resolution,
recheck before mutations, account for
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
