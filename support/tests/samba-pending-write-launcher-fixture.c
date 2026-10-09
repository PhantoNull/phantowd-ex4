/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dedicated disposable QEMU handoff, not installed or wired to a guest.
 * This is NOT an Owner or a manifest verifier. Before spawning this fixed
 * process, trusted composition must inspect/retain the COMPLETE immutable
 * root (code, loader, config, model), this helper and the client, then recheck
 * admission. Keep originals until verified group settlement and closure.
 * ABI: 0 control/read pipe, 1/2 independent output/write pipes, 3 secret/read
 * pipe, 4 original complete RO tmpfs root/read directory, 5 original client.
 * No caller-selected operation/path/account/profile and no pathname fallback.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

static const char target[] = "/run/phantowd-pending-client-root";
static const char program[] = "fixture/pending-write";

static int same_object(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
        left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
        left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
        left->st_size == right->st_size &&
        left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
        left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
        left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int readonly_descriptor(int fd, int directory, struct stat *info)
{
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 || (flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH) ||
        !!(flags & O_DIRECTORY) != directory || fstat(fd, info) ||
        (info->st_mode & S_IFMT) != (directory ? S_IFDIR : S_IFREG) ? -1 : 0;
}

static int pipe_context(void)
{
    if (getpid() <= 1 || getpgrp() != getpid()) return -1;
    struct stat objects[4];
    for (int fd = 0; fd < 4; ++fd) {
        struct statfs fs;
        int flags = fcntl(fd, F_GETFL);
        int access = fd == 0 || fd == 3 ? O_RDONLY : O_WRONLY;
        if (flags < 0 || (flags & O_ACCMODE) != access || (flags & O_NONBLOCK) ||
            fstat(fd, &objects[fd]) || !S_ISFIFO(objects[fd].st_mode) ||
            fstatfs(fd, &fs) || fs.f_type != PIPEFS_MAGIC) return -1;
        for (int prior = 0; prior < fd; ++prior)
            if (objects[fd].st_dev == objects[prior].st_dev &&
                objects[fd].st_ino == objects[prior].st_ino) return -1;
    }
    return 0;
}

static int guard(void)
{
#if !defined(__arm__)
    return -1;
#else
    char model[32] = {0};
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t count = read(fd, model, sizeof(model));
    int closed = close(fd);
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    return closed || count != sizeof("ARM Versatile PB") ||
        memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB")) ||
        getresuid(&real_uid, &effective_uid, &saved_uid) ||
        getresgid(&real_gid, &effective_gid, &saved_gid) ||
        real_uid || effective_uid || saved_uid || real_gid || effective_gid || saved_gid ? -1 : 0;
#endif
}

static int no_privileged_attributes(int fd)
{
    const char *attributes[] = {"system.posix_acl_access", "system.posix_acl_default", "security.capability"};
    for (size_t i = 0; i < sizeof(attributes) / sizeof(attributes[0]); ++i)
        if (fgetxattr(fd, attributes[i], NULL, 0) >= 0 ||
            (errno != ENODATA && errno != ENOTSUP)) return -1;
    return 0;
}

static int bound_program(int rootfd, const struct stat *expected)
{
    struct open_how how = {.flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS};
    int fd = syscall(SYS_openat2, rootfd, program, &how, sizeof(how));
    if (fd < 0) return -1;
    struct stat actual;
    int result = fstat(fd, &actual) || !same_object(expected, &actual);
    return close(fd) || result ? -1 : 0;
}

/* Shape/identity checks complement, NEVER replace, complete retained inspection.
 * A nonrecursive clone deliberately does not import undeclared child mounts. */
static int inputs(struct stat objects[2])
{
    struct statx identities[2];
    for (int i = 0; i < 2; ++i) {
        int fd = 4 + i;
        struct statfs fs;
        /* Match the existing StageQEMU/NewPlan immutable code contract. */
        mode_t mode = i ? S_IFREG | 0555 : S_IFDIR | 0755;
        unsigned long mask = ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC;
        unsigned long expected = ST_RDONLY | ST_NOSUID | ST_NODEV;
        if (readonly_descriptor(fd, !i, &objects[i]) || objects[i].st_mode != mode ||
            objects[i].st_uid || objects[i].st_gid ||
            (i && (objects[i].st_nlink != 1 || objects[i].st_size <= 0 || objects[i].st_size > 1024 * 1024)) ||
            fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC || (fs.f_flags & mask) != expected ||
            no_privileged_attributes(fd) ||
            statx(fd, "", AT_EMPTY_PATH | AT_NO_AUTOMOUNT, STATX_INO | STATX_MNT_ID, &identities[i]) ||
            (identities[i].stx_mask & (STATX_INO | STATX_MNT_ID)) != (STATX_INO | STATX_MNT_ID) ||
            !identities[i].stx_mnt_id || !(identities[i].stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) ||
            !!(identities[i].stx_attributes & STATX_ATTR_MOUNT_ROOT) != !i) return -1;
    }
    return identities[0].stx_mnt_id != identities[1].stx_mnt_id ||
        objects[0].st_dev != objects[1].st_dev || bound_program(4, &objects[1]) ? -1 : 0;
}

/* Fixed empty guest staging directory is only a DESTINATION. It never selects
 * executable/root content. Reopen in the new namespace, compare with original,
 * then attach through that descriptor (not a late destination path lookup). */
static int target_directory(struct stat *info)
{
    struct open_how how = {.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS};
    int fd = syscall(SYS_openat2, AT_FDCWD, target, &how, sizeof(how));
    if (fd < 0) return -1;
    struct statfs fs;
    if (fstat(fd, info) || info->st_mode != (S_IFDIR | 0700) || info->st_uid || info->st_gid ||
        fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC || (fs.f_flags & ST_RDONLY) ||
        no_privileged_attributes(fd)) { close(fd); return -1; }
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return -1; }
    int result = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { result = -1; break; }
    if (errno) result = -1;
    if (closedir(directory)) result = -1;
    return result;
}

static int isolate(const struct stat objects[2])
{
    struct stat destination, rechecked, actual;
    if (target_directory(&destination) ||
        (destination.st_dev == objects[0].st_dev && destination.st_ino == objects[0].st_ino)) return -1;
    /* Must happen BEFORE namespace separation; no pathname source fallback. */
    int clone = syscall(SYS_open_tree, 4, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
    if (clone < 0 || fstat(clone, &actual) || !same_object(&objects[0], &actual) ||
        unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        target_directory(&rechecked) || !same_object(&destination, &rechecked)) return -1;
    struct open_how how = {.flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS};
    int destination_fd = syscall(SYS_openat2, AT_FDCWD, target, &how, sizeof(how));
    if (destination_fd < 0 || fstat(destination_fd, &actual) || !same_object(&destination, &actual) ||
        syscall(SYS_move_mount, clone, "", destination_fd, "",
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) || close(destination_fd) ||
        fchdir(clone) || chroot(".") || chdir("/") || close(clone)) return -1;
    struct statvfs flags;
    if (stat("/", &actual) || !same_object(&objects[0], &actual) ||
        statvfs("/", &flags) ||
        (flags.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
            (ST_RDONLY | ST_NOSUID | ST_NODEV)) return -1;
    int cloned_root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (cloned_root < 0) return -1;
    int bound = fstat(5, &actual) || !same_object(&objects[1], &actual) ||
        bound_program(cloned_root, &objects[1]);
    if (close(cloned_root) || bound) return -1;
    const char *absent[] = {"/proc", "/dev", "/run", "/state", "/shares"};
    for (size_t i = 0; i < sizeof(absent) / sizeof(absent[0]); ++i)
        if (!lstat(absent[i], &actual) || errno != ENOENT) return -1;
    return 0;
}

static int drop_privileges(void)
{
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) || setgroups(0, NULL)) return -1;
    unsigned int last = 0;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int bounded = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bounded < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP) return -1;
            last = cap; break;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return -1;
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (!last || setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534) ||
        syscall(SYS_capset, &header, caps) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || syscall(SYS_capget, &header, caps) ||
        caps[0].effective || caps[0].permitted || caps[0].inheritable ||
        caps[1].effective || caps[1].permitted || caps[1].inheritable ||
        getuid() != 65534 || geteuid() != 65534 || getgid() != 65534 || getegid() != 65534 ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return -1;
    for (unsigned int cap = 0; cap < last; ++cap)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 0 ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    struct stat objects[2];
    if (argc != 1 || guard() || pipe_context() || inputs(objects) || isolate(objects)) goto refused;
    sigset_t empty;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&empty); sigemptyset(&action.sa_mask);
    if (sigprocmask(SIG_SETMASK, &empty, NULL)) goto refused;
    for (int signal = 1; signal < NSIG; ++signal)
        if (signal != SIGKILL && signal != SIGSTOP &&
            sigaction(signal, &action, NULL) && errno != EINVAL) goto refused;
    umask(077);
    if (close(4) || syscall(SYS_close_range, 6U, ~0U, 0) ||
        fcntl(5, F_SETFD, FD_CLOEXEC) || drop_privileges() || pipe_context()) goto refused;
    char *arguments[] = {"phantowd-smb-pending-write", NULL};
    char *environment[] = {"LC_ALL=C", NULL};
    /* Original PIE inode, never reopened for exec. Interpreter lookup is in
     * the cloned complete immutable root; closure/actual loading still require
     * containing Owner + guest qualification. This helper cannot grant them. */
    syscall(SYS_execveat, 5, "", arguments, environment, AT_EMPTY_PATH);
refused:
    fputs("PHANTOWD_SMB_WRITE_LAUNCHER_REFUSED scope=qemu-only\n", stderr);
    fflush(stderr);
    _Exit(1); /* Partial private views/descriptors die with this owned child. */
}
