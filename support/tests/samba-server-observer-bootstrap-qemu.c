/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dedicated fixed QEMU context probe, NOT an active Samba launcher. */
#ifndef PHANTOWD_SAMBA_OBSERVER_CONTEXT_FIXTURE
#error "Disposable QEMU fixture only"
#endif
#include "samba-server-observer-bootstrap-boundary.h"

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || observer_enter_root_qemu()) return fail();
    fputs("PHANTOWD_SERVER_OBSERVER_CONTEXT_READY inputs=15 endpoint_fd=3 originals_closed=true caps=00000000000000db nnp=true scope=qemu-only\n", stderr);
    fflush(stderr);
    char *arguments[] = {"phantowd-server-observer-context-probe", NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve("/usr/sbin/phantowd-server-observer-context-probe", arguments, environment);
    return fail();
}
