/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

/* Internal v1 descriptor contract: ELF=3 (read-only), root=4 (O_PATH).
 * No setuid installation, path lookup, fallback, mount grants or HTTP input.
 * The future privileged owner must build/pin the complete restricted root. */
enum { executable_fd = 3, root_fd = 4, max_groups = 32, max_args = 64 };

static int fail(void)
{
    fputs("service launcher refused\n", stderr);
    return 1;
}

static int number(const char *text, unsigned int *value)
{
    if (!text || !*text || strlen(text) > 5 || (*text == '0' && text[1]))
        return -1;
    unsigned int result = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9')
            return -1;
        result = result * 10 + (unsigned int)(*p - '0');
    }
    if (result < 1000 || result > 60000)
        return -1;
    *value = result;
    return 0;
}

static int groups(const char *text, gid_t out[max_groups], size_t *count)
{
    if (!text || strlen(text) > max_groups * 6)
        return -1;
    if (!strcmp(text, "-")) {
        *count = 0;
        return 0;
    }
    char copy[max_groups * 6 + 1];
    strcpy(copy, text);
    char *next = copy;
    *count = 0;
    while (next) {
        char *part = next;
        char *comma = strchr(part, ',');
        next = comma ? comma + 1 : NULL;
        if (comma)
            *comma = '\0';
        unsigned int id;
        if (*count == max_groups || number(part, &id) ||
            (*count && id <= out[*count - 1]))
            return -1;
        out[(*count)++] = (gid_t)id;
    }
    return 0;
}

/* The first increment supports only static native ELF. An interpreter needs
 * an independently qualified runtime-root manifest, not implicit host paths. */
static int static_elf(int fd)
{
    unsigned char ident[EI_NIDENT];
    if (pread(fd, ident, sizeof(ident), 0) != sizeof(ident) ||
        memcmp(ident, ELFMAG, SELFMAG) || ident[EI_VERSION] != EV_CURRENT ||
        ident[EI_DATA] != ELFDATA2LSB)
        return -1;
#if defined(__arm__)
    Elf32_Ehdr header;
    Elf32_Phdr program;
    if (ident[EI_CLASS] != ELFCLASS32 ||
        pread(fd, &header, sizeof(header), 0) != sizeof(header) ||
        header.e_machine != EM_ARM)
        return -1;
#elif defined(__x86_64__)
    Elf64_Ehdr header;
    Elf64_Phdr program;
    if (ident[EI_CLASS] != ELFCLASS64 ||
        pread(fd, &header, sizeof(header), 0) != sizeof(header) ||
        header.e_machine != EM_X86_64)
        return -1;
#else
#error Unsupported launcher architecture
#endif
    if ((header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
        header.e_ehsize != sizeof(header) ||
        header.e_phentsize != sizeof(program) ||
        !header.e_phnum || header.e_phnum > 128)
        return -1;
    struct stat info;
    if (fstat(fd, &info) || header.e_phoff > (uint64_t)info.st_size ||
        (uint64_t)header.e_phnum * sizeof(program) >
        (uint64_t)info.st_size - header.e_phoff)
        return -1;
    for (unsigned int i = 0; i < header.e_phnum; ++i) {
        off_t offset = (off_t)(header.e_phoff + (uint64_t)i * sizeof(program));
        if (pread(fd, &program, sizeof(program), offset) != sizeof(program) ||
            program.p_type == PT_INTERP)
            return -1;
    }
    return 0;
}

static int descriptors(void)
{
    struct stat executable, root, original;
    int executable_flags = fcntl(executable_fd, F_GETFL);
    int root_flags = fcntl(root_fd, F_GETFL);
    if (executable_flags < 0 || root_flags < 0 ||
        (executable_flags & (O_ACCMODE | O_PATH)) != O_RDONLY ||
        !(root_flags & O_PATH) || !(root_flags & O_DIRECTORY) ||
        fstat(executable_fd, &executable) || fstat(root_fd, &root) ||
        stat("/", &original) || !S_ISREG(executable.st_mode) ||
        executable.st_uid != 0 || !(executable.st_mode & 0111) ||
        (executable.st_mode & (0022 | S_ISUID | S_ISGID)) ||
        !S_ISDIR(root.st_mode) || root.st_uid != 0 || (root.st_mode & 0022) ||
        (root.st_dev == original.st_dev && root.st_ino == original.st_ino))
        return -1;
    errno = 0;
    if (fgetxattr(executable_fd, "security.capability", NULL, 0) >= 0 ||
        (errno != ENODATA && errno != ENOTSUP) || static_elf(executable_fd))
        return -1;
    /* No inherited filesystem directory/device handles through stdio. stdin
     * must be /dev/null; diagnostics must be anonymous pipes from the owner. */
    struct stat input, output, error;
    struct stat null_device;
    if (stat("/dev/null", &null_device) || fstat(0, &input) ||
        fstat(1, &output) || fstat(2, &error) || !S_ISCHR(input.st_mode) ||
        input.st_rdev != null_device.st_rdev || !S_ISFIFO(output.st_mode) ||
        !S_ISFIFO(error.st_mode) || (fcntl(0, F_GETFL) & O_ACCMODE) != O_RDONLY)
        return -1;
    return 0;
}

static int remove_privileges(uid_t uid, gid_t gid, const gid_t *list, size_t count)
{
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
        return -1;
    unsigned int last = 0;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (present < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP)
                return -1;
            last = cap;
            break;
        }
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))
            return -1;
    }
    if (!last || setgroups(count, list) || setresgid(gid, gid, gid) ||
        setresuid(uid, uid, uid))
        return -1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, data) ||
        syscall(SYS_capget, &header, data))
        return -1;
    for (size_t i = 0; i < 2; ++i)
        if (data[i].effective || data[i].permitted || data[i].inheritable)
            return -1;
    for (unsigned int cap = 0; cap < last; ++cap)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 0 ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
            return -1;
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    gid_t actual[max_groups];
    int actual_count = getgroups(max_groups, actual);
    if (getresuid(&real_uid, &effective_uid, &saved_uid) ||
        getresgid(&real_gid, &effective_gid, &saved_gid) ||
        real_uid != uid || effective_uid != uid || saved_uid != uid ||
        real_gid != gid || effective_gid != gid || saved_gid != gid ||
        actual_count != (int)count ||
        (count && memcmp(actual, list, count * sizeof(gid_t))) ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return -1;
    return 0;
}

static int reset_signals(void)
{
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL))
        return -1;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    for (int signal_number = 1; signal_number < NSIG; ++signal_number) {
        if (signal_number == SIGKILL || signal_number == SIGSTOP)
            continue;
        /* libc reserves two real-time signals; they cannot be changed. */
        if (sigaction(signal_number, &action, NULL) && errno != EINVAL)
            return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned int uid, gid;
    gid_t list[max_groups];
    size_t count;
    if (argc < 7 || argc > max_args + 6 || strcmp(argv[1], "v1") ||
        number(argv[2], &uid) || number(argv[3], &gid) ||
        groups(argv[4], list, &count) || strcmp(argv[5], "--"))
        return fail();
    for (int i = 6; i < argc; ++i)
        if (!argv[i][0] || strlen(argv[i]) > 4096)
            return fail();
    if (getuid() != 0 || geteuid() != 0 || descriptors() ||
        getpgrp() != getpid() ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        fchdir(root_fd) || chroot(".") || chdir("/") ||
        syscall(SYS_close_range, 4U, ~0U, 0) ||
        fcntl(executable_fd, F_SETFD, FD_CLOEXEC) ||
        remove_privileges((uid_t)uid, (gid_t)gid, list, count) || reset_signals())
        return fail();
    umask(0077);
    char *environment[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", NULL};
    syscall(SYS_execveat, executable_fd, "", &argv[6], environment, AT_EMPTY_PATH);
    return fail();
}
