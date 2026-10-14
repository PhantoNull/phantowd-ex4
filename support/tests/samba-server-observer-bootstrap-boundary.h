/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Private fixed QEMU boundary shared by two distinct compile-time entries.
 * Never an extra-FD option on the native or product launcher. */
#ifndef PHANTOWD_OBSERVER_BOOTSTRAP_BOUNDARY_H
#define PHANTOWD_OBSERVER_BOOTSTRAP_BOUNDARY_H
#define main phantowd_legacy_fixture_unused_entry
#include "samba-root-launcher-fixture.c"
#undef main
#include "samba-server-observer-endpoint.h"

static int observer_enter_root_qemu(void)
{
    if (guard()) return fail();
    const char native_root[] = "/run/phantowd-native-samba-root";
    const char config[] = "/run/phantowd-native-samba-root/etc";
    const char state[] = "/run/phantowd-native-samba-state";
    const char *config_roles[] = {"", "/passwd", "/group", "/nsswitch.conf", "/samba/smb.conf"};
    const char *state_roles[] = {"", "/private", "/lock", "/state", "/cache", "/pid", "/rpc"};
    const char *attributes[] = {"system.posix_acl_access", "system.posix_acl_default", "security.capability"};
    struct observer_endpoint original, inherited;
    struct ucred creator = {.pid = getppid(), .uid = 0, .gid = 0};
    if (owned_group_context() || verify_restored_context() ||
        observer_sender_snapshot(18, creator, &original))
        return fail();
    struct stat input, objects[12];
    int input_flags = fcntl(0, F_GETFL);
    if (input_flags < 0 || (input_flags & O_ACCMODE) != O_RDONLY || fstat(0, &input))
        return fail();
    if (!S_ISCHR(input.st_mode) || major(input.st_rdev) != 1 || minor(input.st_rdev) != 3)
        return fail();
    int data_clones[2];
    struct stat data_objects[2];
    if (native_data_clones(data_clones, data_objects))
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
        statfs(native_root, &fs) || fs.f_type != TMPFS_MAGIC || unshare(CLONE_NEWNS) ||
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
    if (native_data_view(native_root, data_clones, data_objects) ||
        mount(NULL, native_root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) ||
        chroot(native_root) || chdir("/") ||
        observer_sender_snapshot(18, creator, &inherited) ||
        !observer_endpoint_equal(&original, &inherited) ||
        dup3(18, 3, 0) != 3 || syscall(SYS_close_range, 4U, ~0U, 0) ||
        restrict_capabilities() ||
        observer_sender_snapshot(3, creator, &inherited) ||
        !observer_endpoint_equal(&original, &inherited))
        return fail();
    for (int fd = 4; fd <= 64; ++fd)
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
            return fail();
    if (access("/proc", F_OK) != -1 || errno != ENOENT || access("/dev", F_OK) != -1 || errno != ENOENT ||
        access("/run", F_OK) != -1 || errno != ENOENT)
        return fail();
    return 0;
}
#endif
