/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dedicated ARM-only synthetic boundary test. NOT libsmbclient, SMB, a
 * production Owner, manifest admission, or pending-I/O qualification. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

static int model_matches(void)
{
    char model[32] = {0};
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    ssize_t count = read(fd, model, sizeof(model));
    int closed = close(fd);
    return !closed && count == sizeof("ARM Versatile PB") &&
        !memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB"));
}

static int probe(void)
{
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    struct statvfs root;
    if (!model_matches() || getpid() <= 1 || getpgrp() != getpid() ||
        getresuid(&real_uid, &effective_uid, &saved_uid) ||
        getresgid(&real_gid, &effective_gid, &saved_gid) ||
        real_uid != 65534 || effective_uid != 65534 || saved_uid != 65534 ||
        real_gid != 65534 || effective_gid != 65534 || saved_gid != 65534 ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, caps) || caps[0].effective || caps[0].permitted || caps[0].inheritable ||
        caps[1].effective || caps[1].permitted || caps[1].inheritable ||
        statvfs("/", &root) || (root.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
            (ST_RDONLY | ST_NOSUID | ST_NODEV)) return 1;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int bounded = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bounded < 0) { if (errno != EINVAL || cap <= CAP_LAST_CAP) return 1; break; }
        if (bounded || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0)) return 1;
    }
    for (int fd = 4; fd <= 64; ++fd)
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 1;
    const char *absent[] = {"/proc", "/dev", "/run", "/state", "/shares"};
    struct stat info;
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); ++i)
        if (!lstat(absent[i], &info) || errno != ENOENT) return 1;
    int created = open("/forbidden", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (created != -1 || (errno != EROFS && errno != EACCES)) return 1;
    char byte;
    if (read(3, &byte, 1) != 1 || byte != 'S' || read(3, &byte, 1) != 0 || close(3)) return 1;
    puts("PHANTOWD_PENDING_BOUNDARY_PROBE_READY");
    if (fflush(stdout) || read(0, &byte, 1) != 1 || byte != 'C') return 1;
    return 0;
}

static int pin(const char *path, int flags)
{
    int input = open(path, flags | O_CLOEXEC | O_NOFOLLOW);
    if (input < 0) return -1;
    int retained = fcntl(input, F_DUPFD_CLOEXEC, 16);
    if (close(input)) return -1;
    return retained;
}

static int same_inode(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int run_case(int root, int client, int launcher, int opaque, int failure)
{
    int channels[4][2];
    for (int i = 0; i < 4; ++i) {
        int raw[2];
        if (pipe(raw)) return 1;
        for (int end = 0; end < 2; ++end) {
            channels[i][end] = fcntl(raw[end], F_DUPFD_CLOEXEC, 16);
            if (channels[i][end] < 16 || close(raw[end])) return 1;
        }
    }
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        if (setpgid(0, 0)) _Exit(1);
        for (int i = 0; i < 4; ++i)
            if (dup2(channels[i][i == 0 || i == 3 ? 0 : 1], i) != i) _Exit(1);
        if (dup2(failure == 3 ? opaque : root, 4) != 4 ||
            dup2(failure == 2 ? root : client, 5) != 5 ||
            (failure == 1 && dup2(root, 0) != 0)) _Exit(1);
        char *args[] = {"phantowd-pending-write-launcher", NULL};
        char *environment[] = {"LC_ALL=C", NULL};
        syscall(SYS_execveat, launcher, "", args, environment, AT_EMPTY_PATH);
        _Exit(1);
    }
    for (int i = 0; i < 4; ++i)
        if (close(channels[i][i == 0 || i == 3 ? 0 : 1])) return 1;
    if ((!failure && write(channels[3][1], "S", 1) != 1) || close(channels[3][1])) return 1;
    if (!failure) {
        char output[80] = {0}; size_t used = 0;
        while (used < sizeof(output) - 1) {
            if (read(channels[1][0], output + used, 1) != 1) return 1;
            if (output[used++] == '\n') break;
        }
        if (strcmp(output, "PHANTOWD_PENDING_BOUNDARY_PROBE_READY\n")) return 1;
        char namespace_path[64];
        snprintf(namespace_path, sizeof(namespace_path), "/proc/%ld/ns/mnt", (long)child);
        struct stat parent, isolated;
        if (stat("/proc/self/ns/mnt", &parent) || stat(namespace_path, &isolated) || same_inode(&parent, &isolated) ||
            write(channels[0][1], "C", 1) != 1) return 1;
    }
    if (close(channels[0][1])) return 1;
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != (failure ? 1 : 0)) return 1;
    /* Observed absence, not just a leader wait. Originals are still retained. */
    if (kill(-child, 0) != -1 || errno != ESRCH) return 1;
    for (int i = 1; i <= 2; ++i) if (close(channels[i][0])) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
#if !defined(__arm__)
    (void)argc;
    return 1;
#else
    if (argc != 1 || !model_matches()) return 1;
    if (getuid() == 65534) return probe();
    if (getuid() || geteuid() || getgid() || getegid()) return 1;
    alarm(20); /* Disposable test deadline, not service orchestration. */
    int root = pin("/run/phantowd-pending-client-input", O_RDONLY | O_DIRECTORY);
    int client = pin("/run/phantowd-pending-client-input/fixture/pending-write", O_RDONLY);
    int launcher = pin("/usr/sbin/phantowd-pending-write-launcher", O_RDONLY);
    int opaque = pin("/run/phantowd-pending-client-input", O_PATH | O_DIRECTORY);
    struct stat original_root, original_client, destination, actual;
    if (root < 16 || client < 16 || launcher < 16 || opaque < 16 ||
        fstat(root, &original_root) || fstat(client, &original_client) ||
        stat("/run/phantowd-pending-client-root", &destination)) return 1;
    /* Negative descriptor handoffs first; healthy clone/exec last. */
    for (int failure = 3; failure >= 0; --failure) {
        if (run_case(root, client, launcher, opaque, failure) ||
            stat("/run/phantowd-pending-client-input", &actual) || !same_inode(&original_root, &actual) ||
            stat("/run/phantowd-pending-client-root", &actual) || !same_inode(&destination, &actual) ||
            fstat(client, &actual) || !same_inode(&original_client, &actual)) return 1;
    }
    if (close(root) || close(client) || close(launcher) || close(opaque)) return 1;
    puts("PHANTOWD_PENDING_LAUNCHER_BOUNDARY_DONE private_namespace=true readonly_root=true caps_zero=true ids_65534=true nnp=true pipe_control=true original_exec=true refusals=3 stopped_reaped=true originals_closed_after_stop=true smb=false scope=qemu-only");
    return 0;
#endif
}
