/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Test-only parent/probe. No Samba process, owner lease or disk import. */
#define main phantowd_legacy_fixture_unused_entry
#include "samba-root-launcher-fixture.c"
#undef main
#include "samba-server-observer-endpoint.h"
#include <poll.h>
#include <stdlib.h>

static int probe_context(void)
{
    struct observer_endpoint sender;
    struct ucred creator = {.pid = getppid(), .uid = 0, .gid = 0};
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct capabilities[2] = {{0}, {0}};
    struct statfs rootfs;
    if (getuid() || geteuid() || getgid() || getegid() || getgroups(0, NULL) != 0 ||
        getpgrp() != getpid() || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, capabilities) ||
        capabilities[0].effective != allowed || capabilities[0].permitted != allowed ||
        capabilities[0].inheritable || capabilities[1].effective ||
        capabilities[1].permitted || capabilities[1].inheritable ||
        statfs("/", &rootfs) || rootfs.f_type != TMPFS_MAGIC ||
        !(rootfs.f_flags & ST_RDONLY) ||
        observer_sender_snapshot(3, creator, &sender))
        return fail();
    for (int cap = 0; cap <= CAP_LAST_CAP; ++cap) {
        int expected = cap < 32 && (allowed & (1U << cap)) ? 1 : 0;
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != expected ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
            return fail();
    }
    /* close_range in the bootstrap closes all 4+. These additional checks
     * observe the inherited inputs/previously poisoned descriptor numbers. */
    for (int fd = 4; fd <= 128; ++fd)
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return fail();
    const char *denied[] = {"/proc", "/dev", "/run"};
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i)
        if (access(denied[i], F_OK) != -1 || errno != ENOENT) return fail();
    if (send(3, &sender.cookie, sizeof(sender.cookie), MSG_DONTWAIT | MSG_NOSIGNAL) !=
        sizeof(sender.cookie))
        return fail();
    return 0;
}

#ifndef PHANTOWD_OBSERVER_PROBE
static int controller(void)
{
    const char *paths[] = {
        "/usr/sbin/phantowd-server-observer-bootstrap",
        "/run/phantowd-native-samba-root/etc",
        "/run/phantowd-native-samba-root/etc/passwd",
        "/run/phantowd-native-samba-root/etc/group",
        "/run/phantowd-native-samba-root/etc/nsswitch.conf",
        "/run/phantowd-native-samba-root/etc/samba/smb.conf",
        "/run/phantowd-native-samba-state",
        "/run/phantowd-native-samba-state/private",
        "/run/phantowd-native-samba-state/lock",
        "/run/phantowd-native-samba-state/state",
        "/run/phantowd-native-samba-state/cache",
        "/run/phantowd-native-samba-state/pid",
        "/run/phantowd-native-samba-state/rpc",
        "/run/observer-readonly", "/run/observer-writable"
    };
    int inputs[15], saved[16], pair[2], pipes[2], null_input;
    int code = open("/run/phantowd-samba-code", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int probe = open("/run/phantowd-samba-code/usr/sbin/phantowd-server-observer-context-probe", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat originals[16], current, original_receiver, original_code, original_probe;
    if (code < 0 || probe < 0 || fstat(code, &original_code) || fstat(probe, &original_probe) ||
        original_code.st_mode != (S_IFDIR | 0755) || original_code.st_uid || original_code.st_gid ||
        original_probe.st_mode != (S_IFREG | 0555) || original_probe.st_uid || original_probe.st_gid)
        return fail();
    for (int i = 0; i < 15; ++i) {
        int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
        if (i == 1 || (i >= 6 && i < 13)) flags |= O_DIRECTORY;
        if (i >= 13) flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
        inputs[i] = open(paths[i], flags);
        if (inputs[i] < 0 || fstat(inputs[i], &originals[i])) return fail();
    }
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) ||
        pipe2(pipes, O_CLOEXEC) ||
        (null_input = open("/dev/null", O_RDONLY | O_CLOEXEC)) < 0)
        return fail();
    int enabled = 1;
    if (setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) ||
        fstat(pair[1], &originals[15]) || fstat(pair[0], &original_receiver))
        return fail();
    struct ucred creator = {.pid = getpid(), .uid = 0, .gid = 0};
    /* Snapshot a temporary inheritable duplicate, not the controller's original. */
    int inspect = fcntl(pair[1], F_DUPFD, 100);
    struct observer_endpoint sender;
    if (inspect < 0 || observer_sender_snapshot(inspect, creator, &sender) || close(inspect))
        return fail();
    pid_t child = fork();
    if (child < 0) return fail();
    if (!child) {
        if (setpgid(0, 0)) _exit(1);
        /* Preserve originals above the fixed ABI before any dup2 can overwrite
         * another original. Caller copies do not carry authority by themselves. */
        for (int i = 0; i < 16; ++i) {
            saved[i] = fcntl(i < 15 ? inputs[i] : pair[1], F_DUPFD_CLOEXEC, 100);
            if (saved[i] < 100) _exit(1);
        }
        if (dup2(null_input, 0) != 0 || dup2(pipes[1], 1) != 1 ||
            dup2(pipes[1], 2) != 2) _exit(1);
        for (int i = 0; i < 16; ++i)
            if (dup2(saved[i], 3 + i) != 3 + i) _exit(1);
        if (syscall(SYS_close_range, 19U, ~0U, 0)) _exit(1);
        char *arguments[] = {"phantowd-server-observer-bootstrap", NULL};
        char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
        fexecve(3, arguments, environment);
        _exit(1);
    }
    if (close(pipes[1])) return fail();
    struct pollfd ready = {.fd = pair[0], .events = POLLIN};
    int success = poll(&ready, 1, 5000) == 1 && ready.revents == POLLIN;
    uint64_t cookie = 0;
    char control[CMSG_SPACE(sizeof(struct ucred))] = {0};
    struct iovec data = {.iov_base = &cookie, .iov_len = sizeof(cookie)};
    struct msghdr message = {.msg_iov = &data, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    if (success) {
        ssize_t count = recvmsg(pair[0], &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        struct cmsghdr *credentials = CMSG_FIRSTHDR(&message);
        struct ucred actual = {0};
        if (credentials && credentials->cmsg_len == CMSG_LEN(sizeof(actual)))
            memcpy(&actual, CMSG_DATA(credentials), sizeof(actual));
        /* Linux returns the requested ancillary CLOEXEC flag even when only
         * credentials arrive. Refuse all other flags, including truncation. */
        success = count == sizeof(cookie) && message.msg_flags == MSG_CMSG_CLOEXEC &&
            credentials && credentials->cmsg_level == SOL_SOCKET &&
            credentials->cmsg_type == SCM_CREDENTIALS &&
            credentials->cmsg_len == CMSG_LEN(sizeof(actual)) &&
            !CMSG_NXTHDR(&message, credentials) &&
            actual.pid == child && !actual.uid && !actual.gid && cookie == sender.cookie;
    }
    /* Bound settlement separately, preserving originals until waitpid succeeds. */
    int status = 0, settled = 0;
    for (int i = 0; i < 200; ++i) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) { settled = 1; break; }
        if (result < 0) break;
        struct timespec delay = {.tv_nsec = 10000000};
        nanosleep(&delay, NULL);
    }
    if (!settled) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
        settled = waitpid(child, &status, 0) == child;
        success = 0;
    }
    if (!settled) return fail(); /* Do not release unverified references. */
    if (kill(-child, 0) != -1 || errno != ESRCH) return fail();
    success = success && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    char output[1024];
    ssize_t count = read(pipes[0], output, sizeof(output));
    const char expected[] = "PHANTOWD_SERVER_OBSERVER_CONTEXT_READY inputs=15 endpoint_fd=3 originals_closed=true caps=00000000000000db nnp=true scope=qemu-only\n";
    success = success && count == sizeof(expected) - 1 &&
        !memcmp(output, expected, sizeof(expected) - 1);
    for (int i = 0; i < 16; ++i) {
        int fd = i < 15 ? inputs[i] : pair[1];
        if (fstat(fd, &current) || current.st_dev != originals[i].st_dev ||
            current.st_ino != originals[i].st_ino) success = 0;
    }
    inspect = fcntl(pair[1], F_DUPFD, 100);
    struct observer_endpoint final;
    if (inspect < 0 || observer_sender_snapshot(inspect, creator, &final) ||
        !observer_endpoint_equal(&sender, &final)) success = 0;
    if (inspect >= 0 && close(inspect)) success = 0;
    if (fstat(pair[0], &current) || current.st_dev != original_receiver.st_dev ||
        current.st_ino != original_receiver.st_ino) success = 0;
    if (fstat(code, &current) || current.st_dev != original_code.st_dev ||
        current.st_ino != original_code.st_ino) success = 0;
    if (fstat(probe, &current) || current.st_dev != original_probe.st_dev ||
        current.st_ino != original_probe.st_ino) success = 0;
    for (int i = 0; i < 15; ++i) if (close(inputs[i])) success = 0;
    if (close(pair[0]) || close(pair[1]) || close(pipes[0]) || close(null_input) ||
        close(code) || close(probe)) success = 0;
    if (!success) return fail();
    puts("PHANTOWD_SERVER_OBSERVER_CONTEXT_PROOF original_sender=true kernel_child_credentials=true sole_endpoint=true isolated_root=true original_inputs_after_stop=true scope=qemu-only");
    return 0;
}
#endif

int main(int argc, char **argv)
{
    (void)argv;
#ifdef PHANTOWD_OBSERVER_PROBE
    return argc == 1 ? probe_context() : fail();
#else
    if (argc != 1 || guard()) return fail();
    return controller();
#endif
}
