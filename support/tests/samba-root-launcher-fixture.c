/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Disposable VersatilePB fixture only. Not a product privilege helper. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <endian.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/posix_acl_xattr.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static const char root[] = "/run/phantowd-samba-root";
static const char code_root[] = "/run/phantowd-samba-code";
/* Client impersonation and ordinary owner/group/metadata operations only.
 * In particular no SYS_ADMIN, SYS_CHROOT, PTRACE, SETPCAP or network admin. */
static const uint32_t allowed = (1U << CAP_CHOWN) | (1U << CAP_DAC_OVERRIDE) |
    (1U << CAP_FOWNER) | (1U << CAP_FSETID) | (1U << CAP_SETGID) |
    (1U << CAP_SETUID);

static int fail(void)
{
    fputs("PHANTOWD_SAMBA_ROOT_LAUNCH_REFUSED\n", stderr);
    return 1;
}

/* Separate fixed entry for an already-created Owner group. A standalone
 * caller is not silently converted into an owned server. Check before any
 * namespace, mount, root, capability or inherited-context mutation. */
static int owned_group_context(void)
{
    if (getpid() <= 1 || getpgrp() != getpid())
        return -1;
    for (int fd = 1; fd <= 2; ++fd) {
        struct stat info;
        struct statfs filesystem;
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || (flags & O_ACCMODE) != O_WRONLY ||
            fstat(fd, &info) || !S_ISFIFO(info.st_mode) ||
            fstatfs(fd, &filesystem) || filesystem.f_type != PIPEFS_MAGIC)
            return -1;
    }
    return 0;
}

static int guard(void)
{
#if !defined(__arm__)
    return -1;
#else
    char model[32] = {0};
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t count = read(fd, model, sizeof(model));
    close(fd);
    return count == sizeof("ARM Versatile PB") &&
        !memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB")) &&
        getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 ? 0 : -1;
#endif
}

static int grant(const char *source, const char *destination, int readonly)
{
    struct stat before, after;
    if (stat(source, &before) || !S_ISDIR(before.st_mode) ||
        mount(source, destination, NULL, MS_BIND, NULL) ||
        mount(NULL, destination, NULL, MS_BIND | MS_REMOUNT | MS_NOSUID |
              MS_NODEV | MS_NOEXEC | (readonly ? MS_RDONLY : 0), NULL) ||
        stat(destination, &after) || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino)
        return -1;
    struct statvfs flags;
    if (statvfs(destination, &flags) || !!(flags.f_flag & ST_RDONLY) != readonly)
        return -1;
    return 0;
}

/* Regression-only source-path replacement inside the private guest namespace.
 * A pathname-based state handoff must fail: the credentials remain only in
 * the original state object. This does not change the controller's namespace. */
static int state_inputs(void)
{
    struct stat objects[7];
    const char *attributes[] = {"system.posix_acl_access",
        "system.posix_acl_default", "security.capability"};
    for (int index = 0; index < 7; ++index) {
        int fd = 4 + index;
        int flags = fcntl(fd, F_GETFL);
        struct statfs fs;
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY ||
            (flags & O_PATH) || !(flags & O_DIRECTORY) ||
            fstat(fd, &objects[index]) || objects[index].st_mode != (S_IFDIR | 0700) ||
            objects[index].st_uid || objects[index].st_gid || fstatfs(fd, &fs) ||
            fs.f_type != TMPFS_MAGIC || (fs.f_flags & ST_RDONLY) ||
            objects[index].st_dev != objects[0].st_dev)
            return -1;
        for (int previous = 0; previous < index; ++previous)
            if (objects[index].st_ino == objects[previous].st_ino)
                return -1;
        for (size_t item = 0; item < sizeof(attributes) / sizeof(attributes[0]); ++item)
            if (fgetxattr(fd, attributes[item], NULL, 0) >= 0 ||
                (errno != ENODATA && errno != ENOTSUP))
                return -1;
    }
    return 0;
}

/* Linux rejects cloning a retained mount from a different non-anonymous
 * namespace. Clone every admitted FD while still in the controller's namespace,
 * then attach the detached clones in the child's private namespace. No source
 * pathname lookup or recursive submount import is allowed. Process exit drops
 * every unattached clone on a partial failure. */
static int state_clones(int clones[7])
{
    for (int index = 0; index < 7; ++index) {
        clones[index] = syscall(SYS_open_tree, 4 + index, "",
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
        if (clones[index] < 0)
            return -1;
    }
    return 0;
}

static int state_view(int handoff, int clones[7])
{
    if (!handoff)
        return grant("/run/phantowd-samba-state", "/run/phantowd-samba-root/state", 0);
    if (mount("tmpfs", "/run/phantowd-samba-state", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64k,mode=0700")) {
        return -1;
    }
    struct stat retained, masked;
    if (fstat(4, &retained) || stat("/run/phantowd-samba-state", &masked) ||
        (retained.st_dev == masked.st_dev && retained.st_ino == masked.st_ino))
        return -1;
    const char *roles[] = {"", "/private", "/lock", "/state", "/cache", "/pid", "/rpc"};
    for (int index = 0; index < 7; ++index) {
        char destination[96];
        snprintf(destination, sizeof(destination), "/run/phantowd-samba-root/state%s", roles[index]);
        struct stat original, actual;
        struct statvfs flags;
        if (fstat(4 + index, &original) ||
            syscall(SYS_move_mount, clones[index], "", AT_FDCWD, destination,
                    MOVE_MOUNT_F_EMPTY_PATH) || close(clones[index]) ||
            mount(NULL, destination, NULL, MS_BIND | MS_REMOUNT |
                  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
            stat(destination, &actual) || original.st_dev != actual.st_dev ||
            original.st_ino != actual.st_ino || statvfs(destination, &flags) ||
            (flags.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
                (ST_NOSUID | ST_NODEV | ST_NOEXEC)) {
            return -1;
        }
    }
    return 0;
}

/* Fixed fixture code views only. Unlike data grants, these must allow loading
 * executable code. Nothing is copied or added to the inspected code-only root.
 * The complete census still belongs to runtimebundle, not this mount helper. */
static int code_views(void)
{
    const char *sources[] = {"/run/phantowd-samba-code/lib",
                            "/run/phantowd-samba-code/usr"};
    const char *destinations[] = {"/run/phantowd-samba-root/lib",
                                 "/run/phantowd-samba-root/usr"};
    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); ++i) {
        struct stat before, after;
        struct statvfs flags;
        if (lstat(sources[i], &before) || !S_ISDIR(before.st_mode) ||
            before.st_uid || before.st_gid || (before.st_mode & 0022) ||
            lstat(destinations[i], &after) || !S_ISDIR(after.st_mode) ||
            after.st_uid || after.st_gid || (after.st_mode & 0022) ||
            mount(sources[i], destinations[i], NULL, MS_BIND, NULL) ||
            mount(NULL, destinations[i], NULL, MS_BIND | MS_REMOUNT |
                  MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) ||
            stat(destinations[i], &after) || before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino || statvfs(destinations[i], &flags) ||
            !(flags.f_flag & ST_RDONLY) || (flags.f_flag & ST_NOEXEC))
            return -1;
    }
    return 0;
}

static int restrict_capabilities(void)
{
    unsigned int last = 0;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) || setgroups(0, NULL))
        return -1;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP)
                return -1;
            last = cap;
            break;
        }
        if ((cap >= 32 || !(allowed & (1U << cap))) &&
            prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
            return -1;
    }
    if (!last || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    data[0].effective = allowed;
    data[0].permitted = allowed;
    if (syscall(SYS_capset, &header, data) || syscall(SYS_capget, &header, data) ||
        data[0].effective != allowed || data[0].permitted != allowed ||
        data[0].inheritable || data[1].effective || data[1].permitted ||
        data[1].inheritable)
        return -1;
    for (unsigned int cap = 0; cap < last; ++cap) {
        int expected = cap < 32 && !!(allowed & (1U << cap));
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != expected ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
            return -1;
    }
    return 0;
}

static int client_operation_allowed(const char *operation)
{
    const char *operations[] = {"ls", "put /run/upload created",
        "put /run/upload owned-created", "get owned-created /run/download",
        "put /run/upload owned-readonly-denied",
        "get created /run/download", "put /run/upload reader-denied",
        "put /run/upload readonly-denied", "get escape /run/escaped",
        "put /run/upload unix-denied", "put /run/upload created-é-β",
        "get created-é-β /run/download-unicode",
        "put /run/upload-stream created:fixture",
        "put /run/upload created:fixture",
        "get created:fixture /run/download-stream",
        "get acl-created /run/download-acl", "put /run/upload acl-created",
        "mkdir inherited/child",
        "put /run/upload inherited/child/data",
        "put /run/upload-stream inherited/child/data",
        "get inherited/child/data /run/download-inherited",
        "allinfo inherited/child/data",
        "mkdir inherited/reader-denied", "mkdir inherited/outsider-denied"};
    int matched = 0;
    for (size_t i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i)
        matched |= !strcmp(operation, operations[i]);
    return matched;
}

static int client(const char *user, const char *share, const char *operation)
{
    if ((strcmp(user, "qpwriter") && strcmp(user, "qpreader") &&
         strcmp(user, "qpoutsider") && strcmp(user, "qpwrong")) ||
        (strcmp(share, "ReadWrite") && strcmp(share, "KernelReadOnly") &&
         strcmp(share, "OriginalAnchor") && strcmp(share, "UnixDenied") &&
         strcmp(share, "PosixACL")) || !client_operation_allowed(operation))
        return fail();
    char auth[64], address[64];
    snprintf(auth, sizeof(auth), "/run/%s.auth", user);
    snprintf(address, sizeof(address), "//127.0.0.1/%s", share);
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start))
        return fail();
    pid_t pid = fork();
    if (pid < 0)
        return fail();
    if (!pid) {
        if (setsid() < 0)
            _exit(125);
        char *args[] = {"smbclient", "-t", "2", "-m", "SMB3_11", "-p",
            "1445", "-A", auth, address, "-c", (char *)operation, NULL};
        char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
        execve("/usr/bin/smbclient", args, environment);
        _exit(125);
    }
    for (;;) {
        int status;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 125;
        if (result < 0 && errno != EINTR)
            return fail();
        if (clock_gettime(CLOCK_MONOTONIC, &now) ||
            now.tv_sec - start.tv_sec >= 10) {
            /* One bounded disposable client group only, never an adopted PID. */
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return 124;
        }
        struct timespec delay = {0, 50000000};
        nanosleep(&delay, NULL);
    }
}

static int writer_identity(void)
{
    if (setgroups(0, NULL) || setgid(1800) || setuid(1801) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return fail();
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (syscall(SYS_capget, &header, caps) || caps[0].effective ||
        caps[0].permitted || caps[1].effective || caps[1].permitted)
        return fail();
    return 0;
}

/* Inspect only the generated code tree, before config/state/share grants.
 * The read-only bind exists only in this child namespace; no parent mount is
 * changed. Drop all bounding/ambient/effective authority before the Go probe. */
static int inspect_runtime_bundle_mode(const char *mode)
{
    if (unshare(CLONE_NEWNS) ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(code_root, code_root, NULL, MS_BIND, NULL) ||
        mount(NULL, code_root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID |
              MS_NODEV, NULL))
        return fail();
    if (mode && (mount(root, root, NULL, MS_BIND, NULL) || code_views() ||
        mount(NULL, root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID,
              NULL)))
        return fail();
    if (mode && !strcmp(mode, "composed-code-copy")) {
        /* A fresh fixed catalog copy with equal bytes/mode, different inode.
         * Poison only this child view; neither inspected tree nor parent mount
         * changes. Require the Go observer itself to reject this substitution. */
        const char original[] = "/run/phantowd-samba-code/usr/lib/gconv/gconv-modules";
        const char copied[] = "/run/phantowd-samba-root/fixture/copied-catalog";
        const char view[] = "/run/phantowd-samba-root/usr/lib/gconv/gconv-modules";
        int a = open(original, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        int b = open(copied, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat source_info, copy_info;
        unsigned char source_bytes[4097], copy_bytes[4097];
        if (a < 0 || b < 0 || fstat(a, &source_info) || fstat(b, &copy_info) ||
            !S_ISREG(source_info.st_mode) || !S_ISREG(copy_info.st_mode) ||
            source_info.st_size <= 0 || source_info.st_size > 4096 ||
            source_info.st_size != copy_info.st_size ||
            source_info.st_mode != copy_info.st_mode ||
            (source_info.st_dev == copy_info.st_dev &&
             source_info.st_ino == copy_info.st_ino) ||
            read(a, source_bytes, sizeof(source_bytes)) != source_info.st_size ||
            read(b, copy_bytes, sizeof(copy_bytes)) != copy_info.st_size ||
            memcmp(source_bytes, copy_bytes, source_info.st_size) ||
            close(a) || close(b) || mount(copied, view, NULL, MS_BIND, NULL) ||
            mount(NULL, view, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
                  MS_NOSUID | MS_NODEV, NULL))
            return fail();
        puts("PHANTOWD_SAMBA_ROOT_COPY_CONTROL_READY bytes=true mode=true different_inode=true scope=qemu-only");
        fflush(stdout);
    }
    int fd = open(code_root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || dup2(fd, 3) != 3 || fcntl(3, F_SETFD, 0) ||
        syscall(SYS_close_range, 4U, ~0U, 0) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        return fail();
    unsigned int last = 0;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP)
                return fail();
            last = cap;
            break;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
            return fail();
    }
    if (!last || writer_identity())
        return fail();
    char *args[] = {"qemu-runtime-bundle", mode ? "composed-code" : NULL, NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve("/usr/sbin/phantowd-runtime-bundle-probe", args, environment);
    return fail();
}

static int inspect_runtime_bundle(void)
{
    return inspect_runtime_bundle_mode(NULL);
}

/* Fixed root-only lifetime experiment. Keep the original writable tmpfs anchor
 * ONLY in this QEMU controller, for its one controlled metadata fault. Children
 * inherit neither anchor: the pinned launcher closes every escape descriptor.
 * This is not a product constructor or a new privilege profile. */
static int code_owner_fixture(void)
{
    int source = open(code_root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int writer = source < 0 ? -1 : fcntl(source, F_DUPFD_CLOEXEC, 5);
    if (source < 0 || writer < 0 || close(source) ||
        unshare(CLONE_NEWNS) ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(code_root, code_root, NULL, MS_BIND, NULL) ||
        mount(NULL, code_root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
              MS_NOSUID | MS_NODEV, NULL))
        return fail();
    int reader = open(code_root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (reader < 0 || dup2(reader, 3) != 3 || dup2(writer, 4) != 4 ||
        fcntl(3, F_SETFD, 0) || fcntl(4, F_SETFD, 0) ||
        syscall(SYS_close_range, 5U, ~0U, 0))
        return fail();
    char *args[] = {"qemu-runtime-bundle", "samba-code-owner", NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve("/usr/sbin/phantowd-runtime-bundle-probe", args, environment);
    return fail();
}

/* The writable config anchor stays only in the fixed test controller. Every
 * daemon still drops all escape descriptors. Code and immutable configuration
 * are separate mounts: only configuration is noexec. */
static int configuration_owner_fixture(void)
{
    const char config[] = "/run/phantowd-samba-root/etc";
    int source = open(config, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int writer = source < 0 ? -1 : fcntl(source, F_DUPFD_CLOEXEC, 6);
    if (source < 0 || writer < 0 || close(source) ||
        unshare(CLONE_NEWNS) ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(code_root, code_root, NULL, MS_BIND, NULL) ||
        mount(NULL, code_root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
              MS_NOSUID | MS_NODEV, NULL) ||
        mount(config, config, NULL, MS_BIND, NULL) ||
        mount(NULL, config, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
        return fail();
    source = open(code_root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int code = source < 0 ? -1 : fcntl(source, F_DUPFD_CLOEXEC, 6);
    if (source < 0 || code < 0 || close(source))
        return fail();
    source = open(config, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int reader = source < 0 ? -1 : fcntl(source, F_DUPFD_CLOEXEC, 6);
    if (source < 0 || reader < 0 || close(source) ||
        dup2(code, 3) != 3 || dup2(reader, 4) != 4 || dup2(writer, 5) != 5 ||
        fcntl(3, F_SETFD, 0) || fcntl(4, F_SETFD, 0) || fcntl(5, F_SETFD, 0) ||
        syscall(SYS_close_range, 6U, ~0U, 0))
        return fail();
    char *args[] = {"qemu-runtime-bundle", "samba-configuration-owner", NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve("/usr/sbin/phantowd-runtime-bundle-probe", args, environment);
    return fail();
}

struct fixed_acl {
    struct posix_acl_xattr_header header;
    struct posix_acl_xattr_entry entries[5];
};

static struct fixed_acl inherited_acl(unsigned int owner, unsigned int mask)
{
    struct fixed_acl acl = {
        .header = {.a_version = htole32(POSIX_ACL_XATTR_VERSION)},
        .entries = {
            {.e_tag = htole16(0x01), .e_perm = htole16(owner), .e_id = htole32(~0U)},
            {.e_tag = htole16(0x02), .e_perm = htole16(5), .e_id = htole32(1802)},
            {.e_tag = htole16(0x04), .e_perm = 0, .e_id = htole32(~0U)},
            {.e_tag = htole16(0x10), .e_perm = htole16(mask), .e_id = htole32(~0U)},
            {.e_tag = htole16(0x20), .e_perm = 0, .e_id = htole32(~0U)},
        },
    };
    return acl;
}

static int verify_acl(int fd, const char *name, const struct fixed_acl *expected)
{
    unsigned char bytes[sizeof(*expected) + 1];
    return fgetxattr(fd, name, bytes, sizeof(bytes)) != (ssize_t)sizeof(*expected) ||
        memcmp(bytes, expected, sizeof(*expected)) ? -1 : 0;
}

static int inherited_object(const char *path, int directory,
                            const struct fixed_acl *expected)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                  (directory ? O_DIRECTORY : 0));
    struct stat info;
    struct fixed_acl defaults = inherited_acl(7, 5);
    if (fd < 0 || fstat(fd, &info))
        return fail();
    if ((directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode)) ||
        info.st_uid != 1801 || info.st_gid != 1800 ||
        (info.st_mode & 07777) != (directory ? 02750 : 0640) ||
        verify_acl(fd, "system.posix_acl_access", expected))
        return fail();
    if (directory) {
        if (verify_acl(fd, "system.posix_acl_default", &defaults))
            return fail();
    } else {
        unsigned char bytes[sizeof(defaults) + 1];
        if (fgetxattr(fd, "system.posix_acl_default", bytes, sizeof(bytes)) != -1 ||
            errno != ENODATA)
            return fail();
    }
    return close(fd) ? fail() : 0;
}

static int inheritance_fixture(int prepare)
{
    const char path[] = "/run/phantowd-samba-source/approved/inherited";
    if (writer_identity())
        return fail();
    struct fixed_acl directory = inherited_acl(7, 5);
    struct fixed_acl file = inherited_acl(6, 4);
    if (prepare) {
        if (mkdir(path, 02770))
            return fail();
        int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 ||
            fsetxattr(fd, "system.posix_acl_access", &directory, sizeof(directory), 0) ||
            fsetxattr(fd, "system.posix_acl_default", &directory, sizeof(directory), 0) ||
            close(fd))
            return fail();
        return inherited_object(path, 1, &directory);
    }
    if (inherited_object(path, 1, &directory) ||
        inherited_object("/run/phantowd-samba-source/approved/inherited/child", 1, &directory) ||
        inherited_object("/run/phantowd-samba-source/approved/inherited/child/data", 0, &file))
        return fail();
    return 0;
}

static int acl_fixture(const char *operation)
{
    const char path[] = "/run/phantowd-samba-source/approved/acl-created";
    const char payload[] = "posix-acl-fixture\n";
    int prepare = !strcmp(operation, "acl-prepare");
    int grant_acl = !strcmp(operation, "acl-grant");
    int revoke_acl = !strcmp(operation, "acl-revoke");
    /* Metadata changes use the writer UID with zero effective/permitted caps. */
    if ((!prepare && !grant_acl && !revoke_acl) || writer_identity())
        return fail();
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC |
        (prepare ? O_CREAT | O_EXCL : 0), 0600);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        info.st_uid != 1801 || info.st_gid != 1800)
        return fail();
    if (prepare) {
        if (write(fd, payload, sizeof(payload) - 1) != (ssize_t)sizeof(payload) - 1 ||
            close(fd))
            return fail();
        return 0;
    }
    struct {
        struct posix_acl_xattr_header header;
        struct posix_acl_xattr_entry entries[5];
    } acl = {
        .header = {.a_version = htole32(POSIX_ACL_XATTR_VERSION)},
        .entries = {
            {.e_tag = htole16(0x01), .e_perm = htole16(6), .e_id = htole32(~0U)},
            {.e_tag = htole16(0x02), .e_perm = htole16(4), .e_id = htole32(1802)},
            {.e_tag = htole16(0x04), .e_perm = 0, .e_id = htole32(~0U)},
            {.e_tag = htole16(0x10), .e_perm = htole16(grant_acl ? 4 : 0),
             .e_id = htole32(~0U)},
            {.e_tag = htole16(0x20), .e_perm = 0, .e_id = htole32(~0U)},
        },
    };
    if (fsetxattr(fd, "system.posix_acl_access", &acl, sizeof(acl), 0)) {
        perror("fixture POSIX ACL fsetxattr");
        return fail();
    }
    unsigned char bytes[sizeof(acl) + 1];
    if (fgetxattr(fd, "system.posix_acl_access", bytes, sizeof(bytes)) !=
        (ssize_t)sizeof(acl) || memcmp(bytes, &acl, sizeof(acl)) || close(fd))
        return fail();
    return 0;
}

/* Poison only the disposable servers' inherited context. These
 * fixed original-namespace handles must not survive the existing boundary. */
static int poison_inherited_context(void)
{
    int directory = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int file = open("/run/phantowd-samba-source/ungranted",
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0 || directory >= 63 || file < 0 || file >= 63 ||
        dup2(directory, 63) != 63 || dup2(file, 64) != 64 ||
        fcntl(63, F_GETFD) != 0 || fcntl(64, F_GETFD) != 0 ||
        close(directory) || close(file))
        return -1;
    struct stat root_info, file_info;
    if (fstat(63, &root_info) || !S_ISDIR(root_info.st_mode) ||
        fstat(64, &file_info) || !S_ISREG(file_info.st_mode))
        return -1;
    sigset_t blocked, observed;
    struct sigaction ignored = {.sa_handler = SIG_IGN}, current;
    if (sigemptyset(&blocked) || sigaddset(&blocked, SIGTERM) ||
        sigaddset(&blocked, SIGHUP) || sigemptyset(&ignored.sa_mask) ||
        sigprocmask(SIG_SETMASK, &blocked, NULL) ||
        sigaction(SIGINT, &ignored, NULL) ||
        sigprocmask(SIG_BLOCK, NULL, &observed) ||
        sigismember(&observed, SIGTERM) != 1 ||
        sigismember(&observed, SIGHUP) != 1 ||
        sigaction(SIGINT, NULL, &current) || current.sa_handler != SIG_IGN)
        return -1;
    return 0;
}

static int verify_restored_context(void)
{
    if (fcntl(63, F_GETFD) != -1 || errno != EBADF ||
        fcntl(64, F_GETFD) != -1 || errno != EBADF)
        return -1;
    sigset_t current_mask;
    if (sigprocmask(SIG_BLOCK, NULL, &current_mask))
        return -1;
    for (int number = 1; number < NSIG; ++number) {
        if (sigismember(&current_mask, number) != 0)
            return -1;
    }
    const int altered[] = {SIGTERM, SIGHUP, SIGINT};
    for (size_t i = 0; i < sizeof(altered) / sizeof(altered[0]); ++i) {
        struct sigaction action;
        if (sigaction(altered[i], NULL, &action) || action.sa_handler != SIG_DFL)
            return -1;
    }
    return 0;
}

/* Fixed native configuration ABI, independent of the mutable-state profile.
 * Clone all four originals before leaving their mount namespace. Expected
 * document bytes/census remain the controller's protected admission contract. */
static int native_config_clones(int clones[4])
{
    struct stat objects[4];
    const char *attributes[] = {"system.posix_acl_access",
        "system.posix_acl_default", "security.capability"};
    for (int index = 0; index < 4; ++index) {
        int fd = 4 + index;
        int flags = fcntl(fd, F_GETFL);
        struct statfs fs;
        mode_t mode = index ? (S_IFREG | 0644) : (S_IFDIR | 0755);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH) ||
            !!(flags & O_DIRECTORY) != !index ||
            fstat(fd, &objects[index]) || objects[index].st_mode != mode ||
            objects[index].st_uid || objects[index].st_gid ||
            (index && (objects[index].st_nlink != 1 ||
                objects[index].st_size <= 0 || objects[index].st_size > 32768)) ||
            fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC ||
            (fs.f_flags & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
                (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC) ||
            objects[index].st_dev != objects[0].st_dev)
            return -1;
        for (int prior = 0; prior < index; ++prior)
            if (objects[index].st_ino == objects[prior].st_ino)
                return -1;
        for (size_t i = 0; i < sizeof(attributes) / sizeof(attributes[0]); ++i)
            if (fgetxattr(fd, attributes[i], NULL, 0) >= 0 ||
                (errno != ENODATA && errno != ENOTSUP))
                return -1;
        clones[index] = syscall(SYS_open_tree, fd, "",
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
        if (clones[index] < 0)
            return -1;
    }
    return 0;
}

static int native_config_view(int clones[4])
{
    const char config[] = "/run/phantowd-native-lookup/etc";
    struct stat original, masked;
    /* Poison only the child source pathname. A bind of that pathname cannot
     * provide any passwd/group entries. Never fall back to /proc/self/fd. */
    if (mount("tmpfs", config, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "size=64k,mode=0755") || fstat(4, &original) ||
        stat(config, &masked) ||
        (original.st_dev == masked.st_dev && original.st_ino == masked.st_ino))
        return -1;
    const char *roles[] = {"", "/passwd", "/group", "/nsswitch.conf"};
    for (int index = 0; index < 4; ++index) {
        char destination[96];
        struct stat actual;
        struct statvfs flags;
        snprintf(destination, sizeof(destination), "%s%s", config, roles[index]);
        if (fstat(4 + index, &original) ||
            syscall(SYS_move_mount, clones[index], "", AT_FDCWD, destination,
                    MOVE_MOUNT_F_EMPTY_PATH) || close(clones[index]) ||
            mount(NULL, destination, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
                  MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) ||
            stat(destination, &actual) || original.st_dev != actual.st_dev ||
            original.st_ino != actual.st_ino || statvfs(destination, &flags) ||
            (flags.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
                (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC))
            return -1;
    }
    return 0;
}

/* No Samba state or data grants. Only the fixed staged native documents and
 * already prepared read-only code are visible to this capability-free probe. */
static int native_lookup_fixture(int handoff)
{
    const char lookup[] = "/run/phantowd-native-lookup";
    struct stat info, original, attached;
    struct statfs fs;
    if (owned_group_context() || lstat(lookup, &info) ||
        info.st_mode != (S_IFDIR | 0755) || info.st_uid || info.st_gid ||
        statfs(lookup, &fs) || fs.f_type != TMPFS_MAGIC)
        return fail();
    int clones[4];
    if (handoff && native_config_clones(clones))
        return fail();
    const char *files[] = {"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"};
    for (size_t i = 0; !handoff && i < sizeof(files) / sizeof(files[0]); ++i) {
        char path[96];
        snprintf(path, sizeof(path), "%s%s", lookup, files[i]);
        if (lstat(path, &info) || info.st_mode != (S_IFREG | 0644) ||
            info.st_uid || info.st_gid || info.st_nlink != 1 ||
            info.st_size <= 0 || info.st_size > 32768)
            return fail();
    }
    if (unshare(CLONE_NEWNS | CLONE_NEWNET) ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(lookup, lookup, NULL, MS_BIND, NULL) ||
        mount(NULL, lookup, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
              MS_NOSUID | MS_NODEV, NULL))
        return fail();
    const char *sources[] = {"/run/phantowd-samba-code/lib",
        "/run/phantowd-samba-code/usr", "/usr/sbin/phantowd-samba-charset-probe"};
    const char *destinations[] = {"/run/phantowd-native-lookup/lib",
        "/run/phantowd-native-lookup/usr", "/run/phantowd-native-lookup/fixture/charset"};
    for (size_t i = 0; i < 3; ++i) {
        struct statvfs flags;
        if (lstat(sources[i], &original) || original.st_uid || original.st_gid ||
            (original.st_mode & 0022) ||
            (i < 2 ? !S_ISDIR(original.st_mode) : !S_ISREG(original.st_mode)) ||
            mount(sources[i], destinations[i], NULL, MS_BIND, NULL) ||
            mount(NULL, destinations[i], NULL, MS_BIND | MS_REMOUNT |
                  MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) ||
            stat(destinations[i], &attached) || attached.st_dev != original.st_dev ||
            attached.st_ino != original.st_ino || statvfs(destinations[i], &flags) ||
            !(flags.f_flag & ST_RDONLY) || (flags.f_flag & ST_NOEXEC))
            return fail();
    }
    const char config[] = "/run/phantowd-native-lookup/etc";
    if ((handoff ? native_config_view(clones) : grant(config, config, 1)) ||
        chroot(lookup) || chdir("/") ||
        syscall(SYS_close_range, 3U, ~0U, 0) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0))
        return fail();
    unsigned int last = 0;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP)
                return fail();
            last = cap;
            break;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
            return fail();
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    if (!last || setgroups(0, NULL) || setresgid(65534, 65534, 65534) ||
        setresuid(65534, 65534, 65534) || syscall(SYS_capset, &header, data) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return fail();
    if (handoff)
        fputs("PHANTOWD_NATIVE_CONFIG_HANDOFF_READY inputs=4 "
              "source_path_masked=true same_objects=true closed_before_exec=true "
              "scope=qemu-only\n", stderr);
    char *args[] = {"native-libc-probe", "native-lookup", NULL};
    char *environment[] = {"LC_ALL=C", NULL};
    execve("/fixture/charset", args, environment);
    return fail();
}

/* Fixed disposable credential profile. It deliberately has no daemon/data
 * grants. Admission receives five original immutable config objects followed
 * by seven original mutable state directories; no pathname fallback is used. */
static int native_credential_fixture(const char *operation, const char *name)
{
    const char native_root[] = "/run/phantowd-native-samba-root";
    const char config[] = "/run/phantowd-native-samba-root/etc";
    const char state[] = "/run/phantowd-native-samba-state";
    const char *config_roles[] = {"", "/passwd", "/group", "/nsswitch.conf", "/samba/smb.conf"};
    const char *state_roles[] = {"", "/private", "/lock", "/state", "/cache", "/pid", "/rpc"};
    const char *attributes[] = {"system.posix_acl_access", "system.posix_acl_default", "security.capability"};
    int read_operation = !strcmp(operation, "check") || !strcmp(operation, "list") || !strcmp(operation, "status");
    int write_operation = !strcmp(operation, "create") || !strcmp(operation, "password") ||
        !strcmp(operation, "enable") || !strcmp(operation, "disable") || !strcmp(operation, "revoke");
    if (owned_group_context() || (!read_operation && !write_operation) ||
        (read_operation ? *name != '\0' : (strcmp(name, "qpmanaged") && strcmp(name, "qpsecond"))))
        return fail();
    struct stat input, objects[12];
    int input_flags = fcntl(0, F_GETFL);
    int seals = fcntl(0, F_GET_SEALS);
    const int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (input_flags < 0 || (input_flags & O_ACCMODE) != O_RDONLY ||
        seals < 0 || (seals & required) != required || fstat(0, &input) ||
        !S_ISREG(input.st_mode) || input.st_size < 0 || input.st_size > 514 ||
        (strcmp(operation, "password") && input.st_size))
        return fail();
    int clones[12];
    for (int index = 0; index < 12; ++index) {
        int fd = 4 + index;
        int directory = index == 0 || index >= 5;
        int flags = fcntl(fd, F_GETFL);
        struct statfs fs;
        mode_t mode = directory ? (S_IFDIR | (index ? 0700 : 0755)) :
            (S_IFREG | (index == 4 ? 0600 : 0644));
        unsigned long expected = ST_NOSUID | ST_NODEV | ST_NOEXEC |
            (index < 5 ? ST_RDONLY : 0);
        if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH) ||
            !!(flags & O_DIRECTORY) != directory || fstat(fd, &objects[index]) ||
            objects[index].st_mode != mode || objects[index].st_uid || objects[index].st_gid ||
            (!directory && (objects[index].st_nlink != 1 || objects[index].st_size <= 0 || objects[index].st_size > 32768)) ||
            fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC ||
            (fs.f_flags & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) != expected ||
            objects[index].st_dev != objects[index < 5 ? 0 : 5].st_dev)
            return fail();
        for (int prior = 0; prior < index; ++prior)
            if (objects[index].st_dev == objects[prior].st_dev && objects[index].st_ino == objects[prior].st_ino)
                return fail();
        for (size_t item = 0; item < sizeof(attributes) / sizeof(attributes[0]); ++item)
            if (fgetxattr(fd, attributes[item], NULL, 0) >= 0 || (errno != ENODATA && errno != ENOTSUP))
                return fail();
        clones[index] = syscall(SYS_open_tree, fd, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
        if (clones[index] < 0)
            return fail();
    }
    struct stat info;
    struct statfs fs;
    if (lstat(native_root, &info) || info.st_mode != (S_IFDIR | 0755) || info.st_uid || info.st_gid ||
        statfs(native_root, &fs) || fs.f_type != TMPFS_MAGIC || unshare(CLONE_NEWNS | CLONE_NEWNET) ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) || mount(native_root, native_root, NULL, MS_BIND, NULL))
        return fail();
    for (int index = 0; index < 2; ++index) {
        char source[96], destination[96];
        struct stat before, after;
        struct statvfs flags;
        snprintf(source, sizeof(source), "%s/%s", code_root, index ? "usr" : "lib");
        snprintf(destination, sizeof(destination), "%s/%s", native_root, index ? "usr" : "lib");
        if (lstat(source, &before) || !S_ISDIR(before.st_mode) || before.st_uid || before.st_gid || (before.st_mode & 0022) ||
            mount(source, destination, NULL, MS_BIND, NULL) ||
            mount(NULL, destination, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) ||
            stat(destination, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
            statvfs(destination, &flags) || !(flags.f_flag & ST_RDONLY) || (flags.f_flag & ST_NOEXEC))
            return fail();
    }
    /* Poison both child source paths before attaching detached originals. */
    struct stat masked;
    if (mount("tmpfs", config, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64k,mode=0755") ||
        stat(config, &masked) || (objects[0].st_dev == masked.st_dev && objects[0].st_ino == masked.st_ino) ||
        mount("tmpfs", state, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=64k,mode=0700") ||
        stat(state, &masked) || (objects[5].st_dev == masked.st_dev && objects[5].st_ino == masked.st_ino))
        return fail();
    for (int index = 0; index < 12; ++index) {
        char destination[128];
        struct stat actual;
        struct statvfs flags;
        unsigned long expected = ST_NOSUID | ST_NODEV | ST_NOEXEC | (index < 5 ? ST_RDONLY : 0);
        if (index < 5)
            snprintf(destination, sizeof(destination), "%s%s", config, config_roles[index]);
        else
            snprintf(destination, sizeof(destination), "%s/state%s", native_root, state_roles[index - 5]);
        if (syscall(SYS_move_mount, clones[index], "", AT_FDCWD, destination, MOVE_MOUNT_F_EMPTY_PATH) ||
            close(clones[index]) || mount(NULL, destination, NULL, MS_BIND | MS_REMOUNT |
                MS_NOSUID | MS_NODEV | MS_NOEXEC | (index < 5 ? MS_RDONLY : 0), NULL) ||
            stat(destination, &actual) || objects[index].st_dev != actual.st_dev || objects[index].st_ino != actual.st_ino ||
            statvfs(destination, &flags) || (flags.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC)) != expected)
            return fail();
    }
    if (mount(NULL, native_root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) ||
        chroot(native_root) || chdir("/") || syscall(SYS_close_range, 3U, ~0U, 0) || restrict_capabilities())
        return fail();
    for (int fd = 3; fd <= 64; ++fd)
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
            return fail();
    if (access("/proc", F_OK) != -1 || errno != ENOENT || access("/dev", F_OK) != -1 || errno != ENOENT ||
        access("/run", F_OK) != -1 || errno != ENOENT)
        return fail();
    char *arguments[8] = {NULL};
    const char *executable;
    if (!strcmp(operation, "check") || !strcmp(operation, "list") || !strcmp(operation, "status")) {
        executable = !strcmp(operation, "check") ? "/usr/bin/testparm" :
            (!strcmp(operation, "list") ? "/usr/bin/pdbedit" : "/usr/bin/smbstatus");
        arguments[0] = !strcmp(operation, "check") ? "testparm" : (!strcmp(operation, "list") ? "pdbedit" : "smbstatus");
        arguments[1] = !strcmp(operation, "check") ? "-s" : (!strcmp(operation, "list") ? "-L" : "-j");
        int index = 2;
        if (!strcmp(operation, "list"))
            arguments[index++] = "-v";
        if (strcmp(operation, "check"))
            arguments[index++] = "-s";
        arguments[index] = "/etc/samba/smb.conf";
    } else if (!strcmp(operation, "revoke")) {
        executable = "/usr/bin/smbcontrol";
        arguments[0] = "smbcontrol"; arguments[1] = "-s"; arguments[2] = "/etc/samba/smb.conf";
        arguments[3] = "smbd"; arguments[4] = "logoff-user"; arguments[5] = (char *)name;
    } else {
        executable = "/usr/bin/smbpasswd";
        arguments[0] = "smbpasswd";
        int index = 1;
        if (!strcmp(operation, "create")) { arguments[index++] = "-a"; arguments[index++] = "-d"; }
        else if (!strcmp(operation, "password")) { arguments[index++] = "-s"; arguments[index++] = "--set-password-disabled"; }
        else arguments[index++] = !strcmp(operation, "enable") ? "-e" : "-d";
        arguments[index++] = "-c"; arguments[index++] = "/etc/samba/smb.conf"; arguments[index] = (char *)name;
    }
    fputs("PHANTOWD_NATIVE_CREDENTIAL_HANDOFF_READY inputs=12 original_config=true original_state=true closed_before_exec=true scope=qemu-only\n", stderr);
    fflush(stderr);
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    execve(executable, arguments, environment);
    return fail();
}

int main(int argc, char **argv)
{
    if (guard())
        return fail();
    if (argc == 2 && !strcmp(argv[1], "guard"))
        return 0;
    if (argc == 2 && !strcmp(argv[1], "native-lookup"))
        return native_lookup_fixture(0);
    if (argc == 2 && !strcmp(argv[1], "native-lookup-retained"))
        return native_lookup_fixture(1);
    if (argc == 4 && !strcmp(argv[1], "native-credential"))
        return native_credential_fixture(argv[2], argv[3]);
    if (argc == 2 && !strcmp(argv[1], "runtime-bundle"))
        return inspect_runtime_bundle();
    if (argc == 2 && !strcmp(argv[1], "composed-code"))
        return inspect_runtime_bundle_mode("composed-code");
    if (argc == 2 && !strcmp(argv[1], "composed-code-copy"))
        return inspect_runtime_bundle_mode("composed-code-copy");
    if (argc == 2 && !strcmp(argv[1], "code-owner"))
        return code_owner_fixture();
    if (argc == 2 && !strcmp(argv[1], "configuration-owner"))
        return configuration_owner_fixture();
    if (argc == 2 && (!strcmp(argv[1], "acl-prepare") ||
        !strcmp(argv[1], "acl-grant") || !strcmp(argv[1], "acl-revoke")))
        return acl_fixture(argv[1]);
    if (argc == 2 && !strcmp(argv[1], "inheritance-prepare"))
        return inheritance_fixture(1);
    if (argc == 2 && !strcmp(argv[1], "inheritance-verify"))
        return inheritance_fixture(0);
    if (argc == 2 && !strcmp(argv[1], "ownership")) {
        struct stat created;
        if (lstat("/run/phantowd-samba-source/approved/created", &created) ||
            !S_ISREG(created.st_mode) || created.st_uid != 1801 ||
            created.st_gid != 1800 || (created.st_mode & 0007))
            return fail();
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "stream-bytes")) {
        /* Fixed test-owned tmpfs file; no arbitrary xattr path or raw device. */
        const char expected[] = "distinct-stream-fixture\n";
        char bytes[sizeof(expected) + 1];
        ssize_t count = lgetxattr("/run/phantowd-samba-source/approved/created",
            "user.DosStream.fixture:$DATA", bytes, sizeof(bytes));
        if (count != (ssize_t)sizeof(expected) ||
            memcmp(bytes, expected, sizeof(expected)))
            return fail();
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "client"))
        return client(argv[2], argv[3], argv[4]);
    int state_server = argc == 2 && !strcmp(argv[1], "owned-state-server");
    int state_observe = argc == 2 && !strcmp(argv[1], "owned-state-observe");
    int state_handoff = state_server || state_observe;
    int owned_server = state_server || (argc == 2 && !strcmp(argv[1], "owned-server"));
    int server = owned_server || (argc == 2 && !strcmp(argv[1], "server"));
    int charset = argc == 2 && !strcmp(argv[1], "charset");
    int enroll = argc == 3 && !strcmp(argv[1], "enroll") &&
        (!strcmp(argv[2], "qpwriter") || !strcmp(argv[2], "qpreader") ||
         !strcmp(argv[2], "qpoutsider"));
    if (!server && !enroll && !charset && !state_observe)
        return fail();
    if ((owned_server || state_observe) && owned_group_context())
        return fail();
    /* Descriptor ABI admission precedes namespace/mount/context effects. */
    if (state_handoff && state_inputs()) {
        return fail();
    }
    int clones[7] = {-1, -1, -1, -1, -1, -1, -1};
    if (state_handoff && state_clones(clones))
        return fail();
    pid_t owner_group = getpgrp();
    if (server && poison_inherited_context())
        return fail();
    struct stat info;
    int rootfd = open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootfd < 0 || fstat(rootfd, &info) || info.st_uid != 0 ||
        !S_ISDIR(info.st_mode) || (info.st_mode & 0022) ||
        unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(root, root, NULL, MS_BIND, NULL) ||
        /* A nonrecursive root bind hides its earlier config submount. Rebuild
         * this fixed protected view inside the new root before dropping caps. */
        grant("/run/phantowd-samba-root/etc", "/run/phantowd-samba-root/etc", 1) ||
        code_views() ||
        state_view(state_handoff, clones) ||
        grant("/run/phantowd-samba-source/approved", "/run/phantowd-samba-root/shares/rw", 0) ||
        grant("/run/phantowd-samba-source/approved", "/run/phantowd-samba-root/shares/ro", 1) ||
        grant("/run/phantowd-samba-source/denied", "/run/phantowd-samba-root/shares/denied", 0) ||
        mount(NULL, root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID, NULL)) {
        return fail();
    }
    /* Reopen the new root bind, not the pre-bind mount reference. Fixed paths
     * here are exclusively created inside the disposable guest, not an Owner
     * contract for production root construction or path-race qualification. */
    close(rootfd);
    rootfd = open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat current;
    if (rootfd < 0 || fstat(rootfd, &current) || current.st_dev != info.st_dev ||
        current.st_ino != info.st_ino || fchdir(rootfd) || chroot(".") || chdir("/") ||
        syscall(SYS_close_range, 3U, ~0U, 0) || restrict_capabilities())
        return fail();
    struct statvfs flags;
    if (statvfs("/", &flags) || !(flags.f_flag & ST_RDONLY) ||
        statvfs("/shares/ro", &flags) || !(flags.f_flag & ST_RDONLY) ||
        statvfs("/shares/rw", &flags) || (flags.f_flag & ST_RDONLY) ||
        access("/run/phantowd-samba-source", F_OK) != -1 || errno != ENOENT ||
        access("/proc", F_OK) != -1 || errno != ENOENT ||
        access("/dev/sda", F_OK) != -1 || errno != ENOENT)
        return fail();
    int fd = open("/shares/ro/native-denied", O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd != -1 || errno != EROFS)
        return fail();
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL))
        return fail();
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    for (int number = 1; number < NSIG; ++number) {
        if (number != SIGKILL && number != SIGSTOP &&
            sigaction(number, &action, NULL) && errno != EINVAL)
            return fail();
    }
    if (server && verify_restored_context())
        return fail();
    if ((owned_server || state_observe) ? (owned_group_context() || getpgrp() != owner_group) :
        setsid() < 0)
        return fail();
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    if (state_handoff) {
        for (int input = 4; input <= 10; ++input)
            if (fcntl(input, F_GETFD) != -1 || errno != EBADF)
                return fail();
    }
    if (state_observe) {
        fputs("PHANTOWD_SAMBA_STATE_OBSERVER_HANDOFF_READY inputs=7 source_path_masked=true same_objects=true closed_before_exec=true scope=qemu-only\n", stderr);
        fflush(stderr);
        /* Fixed read operation: no caller-selected account/action/config or
         * password bytes. Listing stays in private capture, never console. */
        char *args[] = {"pdbedit", "-L", "-u", "qpwriter", "-s", "/etc/samba/smb.conf", NULL};
        execve("/usr/bin/pdbedit", args, environment);
        return fail();
    }
    if (server) {
        if (state_server) {
            puts("PHANTOWD_SAMBA_STATE_HANDOFF_READY inputs=7 source_path_masked=true same_objects=true closed_before_exec=true scope=qemu-only");
        }
        puts("PHANTOWD_SAMBA_ROOT_CONTEXT_READY original_fds_closed=true signal_mask_empty=true dispositions_default=true scope=qemu-only");
        puts("PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db nnp=true original_denied=true kernel_ro=true");
        fflush(stdout);
        char *args[] = {"smbd", "-F", "--no-process-group", "-s", "/etc/samba/smb.conf", "-l", "/state", NULL};
        execve("/usr/sbin/smbd", args, environment);
    } else if (charset) {
        char *args[] = {"phantowd-samba-charset-probe", NULL};
        execve("/fixture/charset", args, environment);
    } else {
        char *args[] = {"smbpasswd", "-s", "-a", "-c", "/etc/samba/smb.conf", argv[2], NULL};
        execve("/usr/bin/smbpasswd", args, environment);
    }
    return fail();
}
