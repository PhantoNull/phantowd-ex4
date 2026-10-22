/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Test-only fixed command; alarm survives exec and cannot report success. */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    sigset_t signals;
    struct sigaction action = {0};
    char *config;
    char *command[] = {"/usr/bin/smbstatus", "-j", "-p", "-s", NULL, NULL};

    if (argc != 2) return 1;
    if (strcmp(argv[1], "empty") == 0)
        config = "/run/phantowd-status-producer/empty/smb.conf";
    else if (strcmp(argv[1], "malformed") == 0)
        config = "/run/phantowd-status-producer/malformed/smb.conf";
    else
        return 1;
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0 ||
        sigaction(SIGALRM, &action, NULL) != 0 ||
        sigemptyset(&signals) != 0 || sigaddset(&signals, SIGALRM) != 0 ||
        sigprocmask(SIG_UNBLOCK, &signals, NULL) != 0) return 1;
    command[4] = config;
    alarm(4);
    execv(command[0], command);
    return 127;
}
