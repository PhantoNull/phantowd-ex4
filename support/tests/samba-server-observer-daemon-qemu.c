/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dedicated QEMU daemon entry. No caller-selected args/profile/program. */
#if !defined(PHANTOWD_SAMBA_OBSERVER_DAEMON_FIXTURE) || PHANTOWD_SAMBA_OBSERVER_DAEMON_FIXTURE != 1
#error "Disposable QEMU fixture only"
#endif
#include "samba-server-observer-bootstrap-boundary.h"

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || observer_enter_root_qemu()) return fail();
    fputs("PHANTOWD_SERVER_OBSERVER_DAEMON_READY inputs=15 endpoint_fd=3 originals_closed=true caps=00000000000000db nnp=true scope=qemu-only\n", stderr);
    fflush(stderr);
    char *arguments[] = {"smbd", "-F", "--no-process-group", "-s",
        "/etc/samba/smb.conf", "-l", "/state", "--debug-stdout", NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve("/usr/sbin/smbd", arguments, environment);
    return fail();
}
