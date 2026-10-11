/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Fixed disposable capture entry. No additional input FD/profile/privilege. */
#if !defined(PHANTOWD_SAMBA_CAPTURE_BOOTSTRAP_FIXTURE) || PHANTOWD_SAMBA_CAPTURE_BOOTSTRAP_FIXTURE != 1
#error "Disposable QEMU fixture only"
#endif
#include "samba-server-observer-bootstrap-boundary.h"

/* Public synthetic test credential, never an operator secret. The only writes
 * are to the already retained private tmpfs passdb. A child in our original
 * process group consumes a fresh pipe; it never inherits the observer socket.
 * No shell, argv secret, retry, alternate account or external listener. */
static int initialize_account(void)
{
    struct stat existing;
    if (lstat("/state/private/passdb.tdb", &existing) != -1 || errno != ENOENT) return -1;
    int input[2];
    if (pipe2(input, O_CLOEXEC)) return -1;
    unsigned char payload[] = "qemu-capture-only\nqemu-capture-only\n";
    ssize_t written = write(input[1], payload, sizeof(payload) - 1);
    volatile unsigned char *wipe = payload;
    for (size_t i = 0; i < sizeof(payload); ++i) wipe[i] = 0;
    if (written != (ssize_t)sizeof(payload) - 1 || close(input[1])) {
        close(input[0]); return -1;
    }
    pid_t child = fork();
    if (child < 0) { close(input[0]); return -1; }
    if (!child) {
        if (dup2(input[0], 0) != 0 || syscall(SYS_close_range, 3U, ~0U, 0)) _Exit(1);
        char *arguments[] = {"smbpasswd", "-c", "/etc/samba/smb.conf", "-s", "-a", "nobody", NULL};
        char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
        execve("/usr/bin/smbpasswd", arguments, environment);
        _Exit(1);
    }
    if (close(input[0])) return -1;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || observer_enter_root_qemu()) return fail();
    struct observer_endpoint before, after;
    struct ucred creator = {.pid = getppid(), .uid = 0, .gid = 0};
    if (observer_sender_snapshot(3, creator, &before) || initialize_account() ||
        observer_sender_snapshot(3, creator, &after) || !observer_endpoint_equal(&before, &after)) return fail();
    for (int fd = 4; fd <= 64; ++fd) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return fail();
    }
    fputs("PHANTOWD_SERVER_OBSERVER_DAEMON_READY inputs=15 endpoint_fd=3 originals_closed=true caps=00000000000000db nnp=true scope=qemu-only\n", stderr);
    fflush(stderr);
    char *arguments[] = {"smbd", "-F", "--no-process-group", "-s", "/etc/samba/smb.conf", "-l", "/state", "--debug-stdout", NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve("/usr/sbin/smbd", arguments, environment);
    return fail();
}
