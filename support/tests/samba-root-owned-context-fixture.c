/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Process-local tests only: never invoke the ARM/bootstrap entrypoint. */
#define main guarded_launcher_not_invoked
#include "samba-root-launcher-fixture.c"
#undef main
#include <stdlib.h>

static int check_case(int test)
{
    if (test != 1 && setpgid(0, 0))
        return 1;
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) ||
        dup2(descriptors[1], 1) != 1 || dup2(descriptors[1], 2) != 2)
        return 1;
    if (test == 2 && dup2(descriptors[0], 1) != 1)
        return 1;
    if (close(descriptors[0]) || close(descriptors[1]))
        return 1;
    if (test == 3 || test == 6) {
        char path[] = "/tmp/phantowd-owned-file.XXXXXX";
        int temporary = mkstemp(path);
        if (temporary < 0 || close(temporary))
            return 1;
        int fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 || unlink(path) || dup2(fd, test == 3 ? 1 : 2) < 0 ||
            close(fd))
            return 1;
    }
    if (test == 4 && close(1))
        return 1;
    if (test == 5) {
        char directory[] = "/tmp/phantowd-owned-fifo.XXXXXX";
        char path[128];
        if (!mkdtemp(directory) ||
            snprintf(path, sizeof(path), "%s/fifo", directory) >= (int)sizeof(path) ||
            mkfifo(path, 0600))
            return 1;
        int reader = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        int writer = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (reader < 0 || writer < 0 || unlink(path) || rmdir(directory) ||
            dup2(writer, 1) != 1 || close(reader) || close(writer))
            return 1;
    }
    return test == 0 ? owned_group_context() != 0 : owned_group_context() != -1;
}

int main(int argc, char **argv)
{
    if (argc == 2)
        return client_operation_allowed(argv[1]) ? 0 : 1;
    if (argc != 1)
        return 1;
    for (int test = 0; test <= 6; ++test) {
        pid_t child = fork();
        if (child < 0)
            return 1;
        if (child == 0)
            _exit(check_case(test));
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            return 1;
    }
    puts("PHANTOWD_SAMBA_OWNED_CONTEXT_NATIVE_READY accepted=1 denied=6 scope=host-process-only");
    return 0;
}
