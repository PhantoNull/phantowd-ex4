/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/nsfs.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

/* Disposable QEMU-only fixed ABI: bootstrap=3, code/config/state roots=4/5/6,
 * original role target=7; mountd additionally has channels=8..10/netns=11.
 * Only table-v1, rpcbind-v1 or mountd-v1 selects a fixed program;
 * no arbitrary command, path, UID or capability selector.
 * UID 0/capability-zero is NOT the product privilege design or an isolation
 * boundary against hostile guest-root code. No PID/user/network isolation. */
static int refuse(void)
{
    fputs("PHANTOWD_NFS_TABLE_BOOTSTRAP_REFUSED\n", stderr);
    return 1;
}

static int fixture_guard(void)
{
#if !defined(__arm__)
    return -1;
#endif
    char model[32], command[4097];
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t size = read(fd, model, sizeof(model));
    int closed = close(fd);
    if (size != 17 || memcmp(model, "ARM Versatile PB", 17) || closed)
        return -1;
    fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size = read(fd, command, sizeof(command));
    closed = close(fd);
    if (size <= 0 || size >= (ssize_t)sizeof(command) || closed)
        return -1;
    command[size] = '\0';
    int count = 0;
    char *save = NULL;
    for (char *word = strtok_r(command, " \t\r\n", &save); word;
         word = strtok_r(NULL, " \t\r\n", &save))
        count += !strcmp(word, "phantowd_nfs_code_fixture=1");
    return count == 1 ? 0 : -1;
}

static int descriptors(int daemon)
{
    struct stat st;
    struct statfs fs;
    if (fstat(0, &st) || (fcntl(0, F_GETFL) & O_ACCMODE) != O_RDONLY)
        return -1;
    if (daemon ? (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 1 || minor(st.st_rdev) != 3)
               : (!S_ISREG(st.st_mode) || st.st_size || lseek(0, 0, SEEK_CUR) != 0))
        return -1;
    for (int fd = 1; fd <= 2; ++fd)
        if (fstat(fd, &st) || !S_ISFIFO(st.st_mode) ||
            fstatfs(fd, &fs) || fs.f_type != PIPEFS_MAGIC ||
            (fcntl(fd, F_GETFL) & O_ACCMODE) != O_WRONLY)
            return -1;
    for (int fd = 4; fd <= 7; ++fd) {
        int flags = fcntl(fd, F_GETFL);
        unsigned long required = MS_NOSUID | MS_NODEV;
        if (fd != 6)
            required |= MS_RDONLY;
        if (fd == 5 || fd == 6)
            required |= MS_NOEXEC;
        if (flags < 0 || fstat(fd, &st) || st.st_uid || st.st_gid ||
            fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC ||
            (fs.f_flags & required) != required ||
            (fd == 6 && (fs.f_flags & MS_RDONLY)) ||
            ((fd == 4 || fd == 7) && (fs.f_flags & MS_NOEXEC)))
            return -1;
        if (fd < 7) {
            mode_t mode = S_IFDIR | (fd == 6 ? 0700 : 0755);
            if (!(flags & O_PATH) || !(flags & O_DIRECTORY) || st.st_mode != mode)
                return -1;
        } else if ((flags & O_PATH) || (flags & O_ACCMODE) != O_RDONLY ||
                   !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size <= 0 ||
                   st.st_size > 16 * 1024 * 1024 || (st.st_mode & 07022) ||
                   !(st.st_mode & S_IXUSR)) {
            return -1;
        }
    }
    return 0;
}

/* This rpcbind version's -h does not restrict TCP. Refuse its fixture role
 * unless lo is the sole UP interface; the harness additionally has no NIC or
 * forwarding. Down built-in tunnel interfaces are not active receivers.
 * This point-in-time guard is not a product network-namespace authority. */
static int loopback_only(void)
{
    struct if_nameindex *names = if_nameindex();
    if (!names)
        return -1;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int valid = fd >= 0, count = 0, loopback = 0;
    for (struct if_nameindex *entry = names; valid && entry->if_index; ++entry) {
        struct ifreq request = {0};
        if (++count > 16 || !entry->if_name || strlen(entry->if_name) >= IFNAMSIZ) {
            valid = 0;
            break;
        }
        strcpy(request.ifr_name, entry->if_name);
        if (ioctl(fd, SIOCGIFFLAGS, &request)) {
            valid = 0;
            break;
        }
        if (request.ifr_flags & IFF_UP) {
            if (strcmp(entry->if_name, "lo") || !(request.ifr_flags & IFF_LOOPBACK))
                valid = 0;
            else
                ++loopback;
        }
    }
    if_freenameindex(names);
    if (fd >= 0 && close(fd))
        valid = 0;
    return valid && loopback == 1 ? 0 : -1;
}

/* Open the detached clones BEFORE unshare: inherited O_PATH descriptors still
 * refer to the parent's mounts, which cannot be used as ordinary MS_BIND
 * sources from the child's new namespace. No source-path reopen or fallback. */
static int clone_input(int fd, unsigned long flags)
{
    int tree = syscall(SYS_open_tree, fd, "",
                       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH | AT_NO_AUTOMOUNT);
    if (tree < 0)
        return -1;
    struct mount_attr attributes = {
        .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                    ((flags & MS_RDONLY) ? MOUNT_ATTR_RDONLY : 0) |
                    ((flags & MS_NOEXEC) ? MOUNT_ATTR_NOEXEC : 0)
    };
    if (syscall(SYS_mount_setattr, tree, "", AT_EMPTY_PATH, &attributes, sizeof(attributes)))
        return -1; /* Every private descriptor is closed by process exit. */
    return tree;
}

static int bind_input(int tree, int fd, const char *target, unsigned long flags)
{
    struct stat original, view;
    struct statfs fs;
    if (syscall(SYS_move_mount, tree, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH) ||
        fstat(fd, &original) || stat(target, &view) ||
        original.st_dev != view.st_dev || original.st_ino != view.st_ino ||
        fstatfs(fd, &fs) || fs.f_type != (fd >= 8 ? PROC_SUPER_MAGIC : TMPFS_MAGIC) ||
        statfs(target, &fs) || (fs.f_flags & flags) != flags || close(tree))
        return -1;
    return 0;
}

static const char *channel_names[] = {"auth.unix.ip", "nfsd.export", "nfsd.fh"};

static int channel_inputs(void)
{
    struct stat st, current;
    struct statfs fs;
    for (int fd = 8; fd <= 10; ++fd)
        if (fstat(fd, &st) || st.st_mode != (S_IFREG | 0600) || st.st_uid || st.st_gid ||
            !(fcntl(fd, F_GETFL) & O_PATH) || fstatfs(fd, &fs) || fs.f_type != PROC_SUPER_MAGIC)
            return -1;
    if (fstat(11, &st) || fstatfs(11, &fs) || fs.f_type != NSFS_MAGIC ||
        (fcntl(11, F_GETFL) & (O_PATH | O_ACCMODE)) != O_RDONLY ||
        ioctl(11, NS_GET_NSTYPE) != CLONE_NEWNET ||
        stat("/proc/thread-self/ns/net", &current) || st.st_ino != current.st_ino || st.st_dev != current.st_dev)
        return -1;
    return 0;
}

static int private_view(int mountd)
{
    struct stat before, after;
    unsigned long common = MS_NOSUID | MS_NODEV;
    int code = clone_input(4, common | MS_RDONLY);
    int configuration = clone_input(5, common | MS_RDONLY | MS_NOEXEC);
    int state = clone_input(6, common | MS_NOEXEC);
    int channels[3] = {-1, -1, -1};
    if (code < 0 || configuration < 0 || state < 0)
        return -1;
    if (mountd)
        for (int i = 0; i < 3; ++i)
            if ((channels[i] = clone_input(8 + i, common | MS_NOEXEC)) < 0)
                return -1;
    if (stat("/proc/self/ns/mnt", &before) || unshare(CLONE_NEWNS) ||
        stat("/proc/self/ns/mnt", &after) || before.st_ino == after.st_ino ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        lstat("/run", &after) || !S_ISDIR(after.st_mode) ||
        mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "mode=0700,size=2m") ||
        mkdir("/run/root", 0755) || mkdir("/run/root/code", 0755) ||
        mkdir("/run/root/etc", 0755) || mkdir("/run/root/run", 0700) ||
        mkdir("/run/root/var", 0755) ||
        symlink("code/lib", "/run/root/lib") ||
        symlink("code/usr", "/run/root/usr") ||
        symlink("../run", "/run/root/var/run"))
        return -1;
    if (mountd) {
        if (mkdir("/run/root/proc", 0755) || mkdir("/run/root/proc/net", 0755) || mkdir("/run/root/proc/net/rpc", 0755))
            return -1;
        for (int i = 0; i < 3; ++i) {
            char path[128];
            if (snprintf(path, sizeof(path), "/run/root/proc/net/rpc/%s", channel_names[i]) <= 0 || mkdir(path, 0755))
                return -1;
            strcat(path, "/channel");
            int placeholder = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0000);
            if (placeholder < 0 || close(placeholder) || bind_input(channels[i], 8 + i, path, common | MS_NOEXEC))
                return -1;
        }
    }
    if (bind_input(code, 4, "/run/root/code", common | MS_RDONLY) ||
        bind_input(configuration, 5, "/run/root/etc", common | MS_RDONLY | MS_NOEXEC) ||
        bind_input(state, 6, "/run/root/run", common | MS_NOEXEC) ||
        mount(NULL, "/run", NULL, MS_REMOUNT | MS_RDONLY | common | MS_NOEXEC, NULL) ||
        chdir("/run/root") || chroot(".") || chdir("/"))
        return -1;
    for (size_t i = 0; i < 3; ++i) {
        const char *missing[] = {mountd ? "/proc/fs" : "/proc", "/dev", "/srv"};
        errno = 0;
        if (!lstat(missing[i], &after) || errno != ENOENT)
            return -1;
    }
    return 0;
}

static int fixed_capabilities(unsigned long long allowed)
{
    if (setgroups(0, NULL) || prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        return -1;
    unsigned int last = 0;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP)
                return -1;
            last = cap;
            break;
        }
        if (!(allowed & (1ULL << cap)) && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
            return -1;
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    data[0].effective = data[0].permitted = (unsigned int)allowed;
    data[1].effective = data[1].permitted = (unsigned int)(allowed >> 32);
    if (!last || syscall(SYS_capset, &header, data) || syscall(SYS_capget, &header, data))
        return -1;
    for (size_t i = 0; i < 2; ++i)
        if (data[i].effective != (unsigned int)(allowed >> (i * 32)) ||
            data[i].permitted != data[i].effective || data[i].inheritable)
            return -1;
    for (unsigned int cap = 0; cap < last; ++cap)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != !!(allowed & (1ULL << cap)) ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
            return -1;
    return getgroups(0, NULL) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 ? 0 : -1;
}

static int reset_signals(void)
{
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL))
        return -1;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    for (int number = 1; number < NSIG; ++number)
        if (number != SIGKILL && number != SIGSTOP &&
            sigaction(number, &action, NULL) && errno != EINVAL)
            return -1;
    return 0;
}

int main(int argc, char **argv)
{
    int daemon = argc == 2 && !strcmp(argv[1], "rpcbind-v1");
    int mountd = argc == 2 && !strcmp(argv[1], "mountd-v1");
    if (argc != 2 || (!daemon && !mountd && strcmp(argv[1], "table-v1")) ||
        getuid() || geteuid() || getgid() || getegid() || getpgrp() != getpid())
        return refuse();
    if (fixture_guard())
        return refuse();
    if (descriptors(daemon || mountd) || (mountd && channel_inputs()))
        return refuse();
    if ((daemon || mountd) && loopback_only())
        return refuse();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || private_view(mountd))
        return refuse();
    if (syscall(SYS_close_range, 3U, 6U, 0) ||
        syscall(SYS_close_range, 8U, ~0U, 0) ||
        fcntl(7, F_SETFD, FD_CLOEXEC))
        return refuse();
    /* Only the fixed rpcbind role retains these three startup capabilities;
     * rpcbind -s subsequently drops to the synthetic daemon account. Parent
     * observation must verify actual UID/GID and zero effective/permitted caps. */
    unsigned long long allowed = daemon ? (1ULL << CAP_NET_BIND_SERVICE) |
        (1ULL << CAP_SETUID) | (1ULL << CAP_SETGID) : 0;
    if (fixed_capabilities(allowed) || reset_signals())
        return refuse();
    umask(0077);
    char *args[] = {"/usr/sbin/exportfs", "-s", NULL};
    char *daemon_args[] = {"/usr/sbin/rpcbind", "-f", "-s", "-h", "127.0.0.1", NULL};
    char *mountd_args[] = {"/usr/sbin/rpc.mountd", "-F", "-N", "2", "-N", "4", "-V", "3", "-u", "-p", "20048", NULL};
    char *environment[] = {"PATH=/usr/sbin:/usr/bin", "LC_ALL=C", NULL};
    fputs(mountd ? "PHANTOWD_NFS_MOUNTD_HANDOFF private_view=true capabilities_zero=true channels=3 active_interfaces=lo fixed_mountd=true\n" :
          daemon ? "PHANTOWD_NFS_RPCBIND_HANDOFF private_view=true initial_caps=bind-setuid-setgid active_interfaces=lo fixed_rpcbind=true\n" :
          "PHANTOWD_NFS_TABLE_HANDOFF private_view=true capabilities_zero=true fixed_exportfs=true\n", stderr);
    if (fflush(stderr))
        return refuse();
    syscall(SYS_execveat, 7, "", mountd ? mountd_args : daemon ? daemon_args : args, environment, AT_EMPTY_PATH);
    return refuse();
}
