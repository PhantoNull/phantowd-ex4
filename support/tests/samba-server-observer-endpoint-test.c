/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
#define _GNU_SOURCE
#include "samba-server-observer-endpoint.h"
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>

static void require(int ok) { if (!ok) { fputs("observer endpoint assertion failed\n", stderr); exit(1); } }
static void refused(int fd, struct ucred creator)
{
    struct observer_endpoint output, empty = {0};
    memset(&output, 0xff, sizeof(output));
    require(observer_sender_snapshot(fd, creator, &output) == -1);
    require(memcmp(&output, &empty, sizeof(output)) == 0);
}
int main(void)
{
    int pair[2];
    require(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0);
    int enabled = 1;
    require(setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0);
    struct ucred creator = {.pid = getpid(), .uid = getuid(), .gid = getgid()};
    /* Originals stay CLOEXEC in the controller. Only the inherited sender
     * duplicate is eligible; refusal must not fix or otherwise mutate it. */
    refused(pair[1], creator);
    require(fcntl(pair[1], F_GETFD) == FD_CLOEXEC);
    pid_t child = fork();
    require(child >= 0);
    if (!child) {
        struct observer_endpoint original, inherited;
        require(fcntl(pair[1], F_SETFD, 0) == 0);
        require(observer_sender_snapshot(pair[1], creator, &original) == 0);
        int duplicate = fcntl(pair[1], F_DUPFD, 100);
        require(duplicate >= 100 && close(pair[1]) == 0);
        require(observer_sender_snapshot(duplicate, creator, &inherited) == 0);
        require(observer_endpoint_equal(&original, &inherited));
        refused(pair[0], creator);
        require(fcntl(pair[0], F_SETFD, 0) == 0);
        refused(pair[0], creator); /* Credential-bearing receiver is not sender. */
        struct ucred wrong = creator;
        wrong.pid = getpid(); /* Child is sender, not socketpair creator. */
        refused(duplicate, wrong);
        wrong = creator; wrong.uid++;
        refused(duplicate, wrong);
        wrong = creator; wrong.gid++;
        refused(duplicate, wrong);
        wrong = creator; wrong.pid = 0;
        refused(duplicate, wrong);
        require(fcntl(duplicate, F_SETFL, O_RDWR | O_NONBLOCK) == 0);
        refused(duplicate, creator);
        require(fcntl(duplicate, F_GETFL) == (O_RDWR | O_NONBLOCK));
        require(fcntl(duplicate, F_SETFL, O_RDWR) == 0);
        int enabled = 1, disabled = 0;
        require(setsockopt(duplicate, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0);
        refused(duplicate, creator);
        require(setsockopt(duplicate, SOL_SOCKET, SO_PASSCRED, &disabled, sizeof(disabled)) == 0);
        require(setsockopt(duplicate, SOL_SOCKET, SO_PASSPIDFD, &enabled, sizeof(enabled)) == 0);
        refused(duplicate, creator);
        require(setsockopt(duplicate, SOL_SOCKET, SO_PASSPIDFD, &disabled, sizeof(disabled)) == 0);
        int security_result = setsockopt(duplicate, SOL_SOCKET, SO_PASSSEC, &enabled, sizeof(enabled));
        if (security_result == 0) {
            refused(duplicate, creator);
            require(setsockopt(duplicate, SOL_SOCKET, SO_PASSSEC, &disabled, sizeof(disabled)) == 0);
        } else {
            require(errno == EOPNOTSUPP);
        }
        require(observer_sender_snapshot(duplicate, creator, &inherited) == 0);
        require(observer_endpoint_equal(&original, &inherited));
        int other[2];
        require(socketpair(AF_UNIX, SOCK_STREAM, 0, other) == 0);
        struct ucred child_creator = {.pid = getpid(), .uid = getuid(), .gid = getgid()};
        refused(other[1], child_creator);
        require(close(other[0]) == 0 && close(other[1]) == 0);
        require(socketpair(AF_UNIX, SOCK_DGRAM, 0, other) == 0);
        refused(other[1], child_creator);
        require(close(other[0]) == 0 && close(other[1]) == 0);
        require(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, other) == 0);
        require(observer_sender_snapshot(other[1], child_creator, &inherited) == 0);
        require(!observer_endpoint_equal(&original, &inherited));
        require(dup2(other[1], duplicate) == duplicate);
        require(observer_sender_snapshot(duplicate, child_creator, &inherited) == 0);
        require(!observer_endpoint_equal(&original, &inherited)); /* Same FD != same original. */
        refused(duplicate, creator);
        require(close(other[0]) == 0 && close(other[1]) == 0);
        int plain = open("/dev/null", O_RDWR);
        require(plain >= 0);
        refused(plain, creator);
        require(close(plain) == 0);
        require(close(duplicate) == 0 && close(pair[0]) == 0);
        refused(duplicate, creator);
        refused(-1, creator);
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct stat original;
    require(fstat(pair[0], &original) == 0 && fstat(pair[1], &original) == 0);
    require(close(pair[0]) == 0 && close(pair[1]) == 0);
    puts("observer original sender/duplicate lifetime and kernel refusals passed");
    return 0;
}
