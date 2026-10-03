/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define BASE "/run/phantowd-launcher-fixture"
#define ROOT BASE "/root"
#define ORIGINAL BASE "/original"
#define HELPER "/usr/sbin/phantowd-service-launcher"
#define PROBE "/usr/sbin/phantowd-service-launcher-fixture"

enum { leaked_high_fd = 511 };

static volatile sig_atomic_t stopped;

static void stop(int signal_number)
{
    (void)signal_number;
    stopped = 1;
}

static int probe(const char *pid_text)
{
    gid_t groups[2];
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    char cwd[32], marker[16] = {0};
    struct sigaction action = {.sa_handler = stop};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || getpid() != atoi(pid_text) ||
        getpgrp() != getpid() || getuid() != 1000 || geteuid() != 1000 ||
        getgid() != 1000 || getegid() != 1000 || getgroups(2, groups) != 1 ||
        groups[0] != 1000 || !getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/") ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, data))
        return 2;
    for (size_t i = 0; i < 2; ++i)
        if (data[i].effective || data[i].permitted || data[i].inheritable)
            return 3;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int result = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (result < 0) {
            if (errno == EINVAL && cap > CAP_LAST_CAP)
                break;
            return 4;
        }
        if (result || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0))
            return 4;
    }
    for (int fd = 3; fd < 32; ++fd) {
        errno = 0;
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
            return 5;
    }
    errno = 0;
    if (fcntl(leaked_high_fd, F_GETFD) != -1 || errno != EBADF)
        return 5;
    const char *denied[] = {ORIGINAL "/marker", "/sibling", "/proc", "/dev",
        "/private", "/srv/phantowd/volumes/qemu-only/public/marker",
        "/srv/phantowd/volumes/qemu-plan/public/marker"};
    for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
        errno = 0;
        int fd = open(denied[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0 || errno != ENOENT)
            return 6;
    }
    int fd = open("/share/marker", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, marker, sizeof(marker)) != 8 ||
        strcmp(marker, "approved") || close(fd))
        return 7;
    errno = 0;
    fd = open("/share/forbidden-write", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0 || errno != EROFS || setuid(0) == 0)
        return 8;
    /* No environment inherited from the privileged parent. */
    if (getenv("PHANTOWD_TEST_SECRET") || !getenv("LC_ALL") ||
        strcmp(getenv("LC_ALL"), "C"))
        return 9;
    if (printf("PHANTOWD_SERVICE_SANDBOX_READY pid=%ld pgid=%ld\n",
               (long)getpid(), (long)getpgrp()) < 0 || fflush(stdout))
        return 10;
    while (!stopped)
        pause();
    return 0;
}

static int write_marker(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
    if (fd < 0)
        return -1;
    int result = write(fd, "approved", 8) == 8 && close(fd) == 0 ? 0 : -1;
    return result;
}

/* All objects belong to this one fixed disposable guest fixture. */
static pid_t start_child(int output[2], int invalid)
{
    if (pipe2(output, O_CLOEXEC))
        return -1;
    pid_t child = fork();
    if (child != 0)
        return child;
    if (invalid != 7 && setpgid(0, 0))
        _exit(20);
    int executable = open(invalid == 4 ? BASE "/bad-elf" : PROBE,
                          O_RDONLY | O_CLOEXEC);
    int root = open(invalid == 2 ? "/" : ROOT, O_PATH | O_DIRECTORY | O_CLOEXEC);
    int null_input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int original_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int stdout_output = invalid == 8 ?
        open(BASE "/diagnostics.fifo", O_WRONLY | O_NONBLOCK | O_CLOEXEC) :
        (invalid == 9 ? output[0] : output[1]);
    int stderr_output = invalid == 10 ?
        open(BASE "/diagnostics.fifo", O_WRONLY | O_NONBLOCK | O_CLOEXEC) :
        (invalid == 11 ? output[0] : output[1]);
    if (executable < 0 || root < 0 || null_input < 0 || original_root < 0)
        _exit(21);
    /* Relocate first; dup2 destinations must not clobber source descriptors. */
    executable = fcntl(executable, F_DUPFD_CLOEXEC, 32);
    root = fcntl(root, F_DUPFD_CLOEXEC, 32);
    null_input = fcntl(null_input, F_DUPFD_CLOEXEC, 32);
    original_root = fcntl(original_root, F_DUPFD_CLOEXEC, 32);
    int diagnostics = fcntl(stderr_output, F_DUPFD_CLOEXEC, 32);
    stdout_output = fcntl(stdout_output, F_DUPFD_CLOEXEC, 32);
    if (executable < 0 || root < 0 || null_input < 0 || original_root < 0 ||
        diagnostics < 0 || stdout_output < 0 || dup2(null_input, 0) < 0 ||
        dup2(stdout_output, 1) < 0 ||
        dup2(diagnostics, 2) < 0 || dup2(executable, 3) < 0 || dup2(root, 4) < 0 ||
        dup2(original_root, 9) < 0 || dup2(original_root, leaked_high_fd) < 0)
        _exit(22);
    if (invalid == 1)
        close(3);
    char pid_text[24];
    snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
    setenv("PHANTOWD_TEST_SECRET", "must-not-inherit", 1);
    /* The launcher must reset inherited ignored/blocked termination. */
    signal(SIGTERM, SIG_IGN);
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL))
        _exit(24);
    execl(HELPER, HELPER, "v1", "1000", "1000",
          invalid == 3 ? "1000,1000" : "1000", "--", "/probe",
          "--probe", pid_text, (char *)NULL);
    _exit(23);
}

static int case_child(int invalid)
{
    if ((invalid == 5 && chmod(PROBE, 04755)) ||
        (invalid == 6 && chmod(ROOT, 0777)))
        return -1;
    int output[2];
    /* Keep a reader alive for the named FIFO; never block child admission. */
    int named_diagnostic = invalid == 8 || invalid == 10;
    int fifo_hold = named_diagnostic ?
        open(BASE "/diagnostics.fifo", O_RDWR | O_NONBLOCK | O_CLOEXEC) : -1;
    if (named_diagnostic && fifo_hold < 0)
        return -1;
    pid_t child = start_child(output, invalid);
    if (child < 0) {
        if (fifo_hold >= 0)
            close(fifo_hold);
        return -1;
    }
    close(output[1]);
    struct pollfd waiter = {.fd = output[0], .events = POLLIN};
    char result[256] = {0};
    int failed = 0;
    ssize_t length = -1;
    char named_output[128] = {0};
    ssize_t named_length = -1;
    if (poll(&waiter, 1, 8000) > 0)
        length = read(output[0], result, sizeof(result) - 1);
    if (invalid == 10 || invalid == 11) {
        /* Invalid stderr can only carry a refusal through the named FIFO,
         * or no output at all when it is the read end of a pipe. */
        failed = length != 0;
    } else if (invalid) {
        failed = length != (ssize_t)strlen("service launcher refused\n") ||
            strcmp(result, "service launcher refused\n");
    } else {
        char expected[128];
        snprintf(expected, sizeof(expected),
                 "PHANTOWD_SERVICE_SANDBOX_READY pid=%ld pgid=%ld\n",
                 (long)child, (long)child);
        struct stat parent_ns, child_ns;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/ns/mnt", (long)child);
        failed = length < 0 || strcmp(result, expected) ||
            getpgid(child) != child || stat("/proc/self/ns/mnt", &parent_ns) ||
            stat(path, &child_ns) || parent_ns.st_ino == child_ns.st_ino;
    }
    if (fifo_hold >= 0) {
        errno = 0;
        named_length = read(fifo_hold, named_output, sizeof(named_output) - 1);
        if (invalid == 10) {
            if (named_length != (ssize_t)strlen("service launcher refused\n") ||
                strcmp(named_output, "service launcher refused\n"))
                failed = 1;
        } else if (named_length != -1 || errno != EAGAIN) {
            failed = 1;
        }
    }
    /* Cleanup also on failed evidence: this fixture owns exactly this group. */
    if (!invalid || failed)
        kill(-child, failed ? SIGKILL : SIGTERM);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != (invalid ? 1 : 0))
        failed = 1;
    close(output[0]);
    if (fifo_hold >= 0)
        close(fifo_hold);
    errno = 0;
    if (kill(-child, 0) == 0 || errno != ESRCH)
        failed = 1;
    if ((invalid == 5 && chmod(PROBE, 0755)) ||
        (invalid == 6 && chmod(ROOT, 0755)))
        failed = 1;
    if (failed)
        fprintf(stderr, "PHANTOWD_SERVICE_LAUNCHER_CASE_FAILED case=%d status=%d output=%.*s fifo_output=%.*s\n",
                invalid, status, length > 0 ? (int)length : 0, result,
                named_length > 0 ? (int)named_length : 0, named_output);
    return failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--probe"))
        return probe(argv[2]);
    if (argc == 2 && !strcmp(argv[1], "--owner-probe")) {
        char pid_text[24];
        snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
        return probe(pid_text);
    }
#if !defined(__arm__)
    return 1;
#else
    if ((argc != 1 && !(argc == 2 &&
        (!strcmp(argv[1], "--prepare") || !strcmp(argv[1], "--cleanup")))) ||
        getuid() || geteuid())
        return 1;
    char machine[32] = {0};
    FILE *model = fopen("/sys/firmware/devicetree/base/model", "r");
    if (!model || fread(machine, 1, sizeof(machine), model) != sizeof("ARM Versatile PB") ||
        fclose(model) || memcmp(machine, "ARM Versatile PB", sizeof("ARM Versatile PB")))
        return 1;
    int cleanup_only = argc == 2 && !strcmp(argv[1], "--cleanup");
    if (!cleanup_only && (mkdir(BASE, 0755) || mkdir(ROOT, 0755) || mkdir(ORIGINAL, 0755) ||
        chown(ORIGINAL, 1000, 1000) ||
        write_marker(ORIGINAL "/marker") || write_marker(BASE "/sibling") ||
        write_marker(BASE "/bad-elf") || chmod(BASE "/bad-elf", 0755) ||
        mkfifo(BASE "/diagnostics.fifo", 0600) ||
        mount("tmpfs", ROOT, "tmpfs", MS_NOSUID | MS_NODEV, "size=1m,mode=0755") ||
        mkdir(ROOT "/share", 0755) ||
        mount(ORIGINAL, ROOT "/share", NULL, MS_BIND, NULL) ||
        mount(NULL, ROOT "/share", NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
              NULL)))
        return 1;
    if (argc == 2 && !strcmp(argv[1], "--prepare"))
        return 0;
    int failed = 0;
    for (int invalid = 1; !cleanup_only && invalid <= 11; ++invalid)
        if (case_child(invalid)) {
            failed = 1;
            break;
        }
    if (!cleanup_only && !failed && case_child(0))
        failed = 1;
    struct stat untouched;
    if (stat(ORIGINAL "/marker", &untouched) ||
        access(ORIGINAL "/forbidden-write", F_OK) == 0 ||
        umount(ROOT "/share") || umount(ROOT) ||
        unlink(ORIGINAL "/marker") || unlink(BASE "/sibling") ||
        unlink(BASE "/bad-elf") ||
        unlink(BASE "/diagnostics.fifo") ||
        rmdir(ROOT) || rmdir(ORIGINAL) || rmdir(BASE))
        failed = 1;
    if (failed)
        return 1;
    if (cleanup_only)
        return 0;
    puts("PHANTOWD_SERVICE_LAUNCHER_READY private_namespace=true root_restricted=true nonroot=true capabilities_zero=true fd_cleanup=true high_fd_cleanup=true diagnostic_pipes=true pid_preserved=true read_only=true signals_reset=true denied_cases=11");
    return 0;
#endif
}
