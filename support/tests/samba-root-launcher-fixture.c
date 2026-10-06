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
static int inspect_runtime_bundle(void)
{
    if (unshare(CLONE_NEWNS) ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        mount(root, root, NULL, MS_BIND, NULL) ||
        mount(NULL, root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID |
              MS_NODEV, NULL))
        return fail();
    int fd = open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
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
    char *args[] = {"qemu-runtime-bundle", NULL};
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

int main(int argc, char **argv)
{
    if (guard())
        return fail();
    if (argc == 2 && !strcmp(argv[1], "guard"))
        return 0;
    if (argc == 2 && !strcmp(argv[1], "runtime-bundle"))
        return inspect_runtime_bundle();
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
    int owned_server = argc == 2 && !strcmp(argv[1], "owned-server");
    int server = owned_server || (argc == 2 && !strcmp(argv[1], "server"));
    int charset = argc == 2 && !strcmp(argv[1], "charset");
    int enroll = argc == 3 && !strcmp(argv[1], "enroll") &&
        (!strcmp(argv[2], "qpwriter") || !strcmp(argv[2], "qpreader") ||
         !strcmp(argv[2], "qpoutsider"));
    if (!server && !enroll && !charset)
        return fail();
    if (owned_server && owned_group_context())
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
        grant("/run/phantowd-samba-state", "/run/phantowd-samba-root/state", 0) ||
        grant("/run/phantowd-samba-source/approved", "/run/phantowd-samba-root/shares/rw", 0) ||
        grant("/run/phantowd-samba-source/approved", "/run/phantowd-samba-root/shares/ro", 1) ||
        grant("/run/phantowd-samba-source/denied", "/run/phantowd-samba-root/shares/denied", 0) ||
        mount(NULL, root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID, NULL))
        return fail();
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
    if (owned_server ? (owned_group_context() || getpgrp() != owner_group) :
        setsid() < 0)
        return fail();
    char *environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", NULL};
    if (server) {
        puts("PHANTOWD_SAMBA_ROOT_CONTEXT_READY original_fds_closed=true signal_mask_empty=true dispositions_default=true scope=qemu-only");
        puts("PHANTOWD_SAMBA_ROOT_BOUNDARY_READY caps=00000000000000db nnp=true original_denied=true kernel_ro=true");
        fflush(stdout);
        char *args[] = {"smbd", "-F", "--no-process-group", "-s", "/etc/samba/smb.conf", "-l", "/state", NULL};
        execve("/usr/sbin/smbd", args, environment);
    } else if (charset) {
        char *args[] = {"phantowd-samba-charset-probe", NULL};
        execve("/usr/sbin/phantowd-samba-charset-probe", args, environment);
    } else {
        char *args[] = {"smbpasswd", "-s", "-a", "-c", "/etc/samba/smb.conf", argv[2], NULL};
        execve("/usr/bin/smbpasswd", args, environment);
    }
    return fail();
}
