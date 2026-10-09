/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Real Linux descriptor tests; no mount, privilege drop, ARM or SMB proof. */
#define main launcher_main
#include "samba-pending-write-launcher-fixture.c"
#undef main
#include <stdlib.h>
#include <sys/wait.h>

static void require_at(int condition, int line)
{
    if (!condition) { fprintf(stderr, "launcher host assertion line=%d\n", line); _Exit(2); }
}
#define require(condition) require_at((condition), __LINE__)

static void pipe_case(int failure, int regular, int fifo)
{
    pid_t child = fork(); require(child >= 0);
    if (!child) {
        if (failure != 6) require(!setpgid(0, 0));
        int channels[4][2];
        for (int i = 0; i < 4; ++i) {
            int raw[2]; require(!pipe(raw));
            for (int end = 0; end < 2; ++end) {
                channels[i][end] = fcntl(raw[end], F_DUPFD_CLOEXEC, 16);
                require(channels[i][end] >= 16 && !close(raw[end]));
            }
        }
        for (int i = 0; i < 4; ++i)
            require(dup2(channels[i][i == 0 || i == 3 ? 0 : 1], i) == i);
        if (failure == 1) require(dup2(channels[0][0], 3) == 3); /* secret/control alias */
        if (failure == 2) require(dup2(channels[1][0], 1) == 1); /* wrong access */
        if (failure == 3) require(dup2(channels[1][1], 2) == 2); /* output alias */
        if (failure == 4) require(dup2(regular, 0) == 0); /* regular file */
        if (failure == 5) require(dup2(fifo, 3) == 3); /* named FIFO */
        if (failure == 7) require(!fcntl(3, F_SETFL, O_NONBLOCK));
        require((pipe_context() == 0) == (failure == 0));
        _Exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void)
{
    require(guard() == -1); /* Actual host guard refuses, not a mocked platform. */
    char *args[] = {"test", NULL};
    pid_t child = fork(); require(child >= 0);
    if (!child) { launcher_main(1, args); _Exit(99); }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1);
    child = fork(); require(child >= 0);
    if (!child) { launcher_main(2, args); _Exit(99); }
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1);

    char path[] = "/tmp/phantowd-launcher-host.XXXXXX";
    require(mkdtemp(path) != NULL);
    int rootfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(rootfd >= 0 && !mkdirat(rootfd, "fixture", 0755));
    int output = openat(rootfd, program, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
    require(output >= 0 && write(output, "fixed", 5) == 5 && !close(output));
    int pin = openat(rootfd, program, O_RDONLY | O_CLOEXEC);
    struct stat original, observed;
    require(pin >= 0 && !fstat(pin, &original) && !readonly_descriptor(pin, 0, &observed) &&
        same_object(&original, &observed) && !bound_program(rootfd, &original));
    require(!readonly_descriptor(rootfd, 1, &observed));
    require(readonly_descriptor(rootfd, 0, &observed) == -1 &&
        readonly_descriptor(pin, 1, &observed) == -1 && readonly_descriptor(-1, 0, &observed) == -1);
    int opaque = openat(rootfd, program, O_PATH | O_CLOEXEC);
    int writable = openat(rootfd, program, O_RDWR | O_CLOEXEC);
    require(opaque >= 0 && writable >= 0 && readonly_descriptor(opaque, 0, &observed) == -1 &&
        readonly_descriptor(writable, 0, &observed) == -1);

    require(!mkfifoat(rootfd, "named", 0600));
    int fifo = openat(rootfd, "named", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    require(fifo >= 0 && !fcntl(fifo, F_SETFL, 0));
    for (int i = 0; i < 8; ++i) pipe_case(i, pin, fifo);

    /* Same bytes and mode never authorize a substituted inode or symlink. */
    require(!renameat(rootfd, program, rootfd, "fixture/original"));
    require(!fstat(pin, &original));
    output = openat(rootfd, program, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0755);
    require(output >= 0 && write(output, "fixed", 5) == 5 && !close(output));
    require(bound_program(rootfd, &original) == -1);
    require(!unlinkat(rootfd, program, 0) && !symlinkat("original", rootfd, program));
    require(bound_program(rootfd, &original) == -1);
    require(!unlinkat(rootfd, program, 0) && !mkdirat(rootfd, program, 0755));
    require(bound_program(rootfd, &original) == -1);
    require(!unlinkat(rootfd, program, AT_REMOVEDIR));
    require(bound_program(rootfd, &original) == -1);
    require(!renameat(rootfd, "fixture/original", rootfd, program) && !fstat(pin, &original));
    require(!bound_program(rootfd, &original));
    observed = original; observed.st_size++;
    require(bound_program(rootfd, &observed) == -1);
    observed = original; observed.st_ctim.tv_nsec ^= 1;
    require(bound_program(rootfd, &observed) == -1);

    require(!close(opaque) && !close(writable) && !close(fifo) && !close(pin));
    require(!unlinkat(rootfd, program, 0) && !unlinkat(rootfd, "named", 0) &&
        !unlinkat(rootfd, "fixture", AT_REMOVEDIR) && !close(rootfd) && !rmdir(path));
    puts("PHANTOWD_SMB_WRITE_LAUNCHER_HOST_DONE descriptors=true substitution_refused=true guest=false mounts=false privileges=false smb=false scope=host-only");
    return 0;
}
