<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Internal service launcher prototype

M4.4 native Linux launcher for **non-root userspace children**, not kernel NFS
control, a container runtime, a public CLI/API, or product activation. No setuid
installation. A trusted privileged owner must pin its executable, validate and
construct the whole service root, retain storage leases, supervise readiness
and stop the process group before releasing those leases.

The internal version-1 interface receives a native static ELF on read-only FD 3
and a restricted root directory on `O_PATH|O_DIRECTORY` FD 4. Arguments are
`v1 UID GID GROUPS -- ARGV0 [ARGS...]`; IDs are reserved 1000–60000, groups are
sorted and unique, or `-` for none. No caller path is opened for execution.
The executable must be root-owned, executable, non-group/other-writable,
without setuid/setgid or file capabilities. The root must be root-owned,
non-group/other-writable and not the original `/`. These checks **do not prove
that the root contains only approved grants**; that is the future owner's job.

stdin is read-only `/dev/null`, stdout/stderr are owner pipes. The caller starts
one child as its process-group leader. The launcher unshares the mount
namespace, makes propagation recursively private, enters the pinned root and
resets cwd to `/`. It closes FD 4 and every higher inherited descriptor, marks
the executable close-on-exec, clears keep-caps/ambient/bounding/effective/
permitted/inheritable capabilities, sets exact real/effective/saved credentials
and groups, verifies `no_new_privs`, and `execveat`s the pinned ELF. PID/PGID do
not change. Inherited ignored/blocked signal handling is reset before exec.
Any error refuses execution; no weaker fallback or retry exists.
The environment is only `PATH` and `LC_ALL`; umask is `0077`.

Initial scope deliberately excludes dynamic interpreters, service-specific
runtime manifests, per-service ACL provisioning, device/network/PID isolation,
seccomp, daemon integration and kernel-side exports. `chroot` plus a private
mount namespace is not a security boundary for a privileged process; this
prototype requires zero capabilities, non-root saved IDs and no inherited
filesystem handles. Network/process privileges still follow the service UID.
It is not connected to `processowner`, `ServiceRuntime`, product init or HTTP.

Tests use host refusal cases and a static disposable ARMv5 probe in QEMU, never
real disks or the NAS. The QEMU fixture prepares a private tmpfs root and one
read-only synthetic share; it must prove original/sibling paths and leaked FDs
are inaccessible, writes return `EROFS`, privileges are zero and supervision
keeps the same PID/PGID. See `support/tests/test-qemu-service-launcher.sh`.
Passing this fixture is not SMB/NFS or EX4 qualification.

Local validation on 2026-10-02 passed the host refusal suite and the actual
ARMv5 fixture, including seven refusal cases: missing ELF descriptor, original
host root, duplicate groups, non-ELF executable, setuid executable, writable
root, and a child that is not its process-group leader. The positive probe
also verifies inherited blocked/ignored `SIGTERM` does not prevent a clean
stop. Run `support/test-service-launcher.ps1` with existing pinned cache/base
inputs; no image or persistent volume is created. This is an overlay test,
not a clean product build, service integration or hardware qualification.
