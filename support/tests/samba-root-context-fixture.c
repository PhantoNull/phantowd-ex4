/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Host-only process-local feedback for the actual guarded launcher check.
 * Do not invoke its ARM/bootstrap entrypoint or attach a namespace/device. */
#define main guarded_launcher_not_invoked
#include "samba-root-launcher-fixture.c"
#undef main

static int restore_test_context(void)
{
    sigset_t empty;
    struct sigaction action = {.sa_handler = SIG_DFL};
    if (syscall(SYS_close_range, 3U, ~0U, 0) || sigemptyset(&empty) ||
        sigemptyset(&action.sa_mask) ||
        sigprocmask(SIG_SETMASK, &empty, NULL))
        return -1;
    const int altered[] = {SIGTERM, SIGHUP, SIGINT};
    for (size_t i = 0; i < sizeof(altered) / sizeof(altered[0]); ++i) {
        if (sigaction(altered[i], &action, NULL))
            return -1;
    }
    return 0;
}

static int denied_then_restored(void)
{
    return verify_restored_context() != -1 || restore_test_context() ||
        verify_restored_context() ? -1 : 0;
}

int main(void)
{
    if (restore_test_context() || verify_restored_context())
        return fail();
    const int descriptors[] = {63, 64};
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0 || fd >= 63 || dup2(fd, descriptors[i]) != descriptors[i] ||
            close(fd) || denied_then_restored())
            return fail();
    }
    /* SIGUSR1 also checks the complete mask, not just injected stop signals. */
    const int blocked[] = {SIGTERM, SIGHUP, SIGUSR1};
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        sigset_t mask;
        if (sigemptyset(&mask) || sigaddset(&mask, blocked[i]) ||
            sigprocmask(SIG_SETMASK, &mask, NULL) || denied_then_restored())
            return fail();
    }
    const int ignored[] = {SIGTERM, SIGHUP, SIGINT};
    struct sigaction action = {.sa_handler = SIG_IGN};
    if (sigemptyset(&action.sa_mask))
        return fail();
    for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); ++i) {
        if (sigaction(ignored[i], &action, NULL) || denied_then_restored())
            return fail();
    }
    puts("PHANTOWD_SAMBA_CONTEXT_NATIVE_READY denied=8 restored=true scope=host-process-only");
    return 0;
}
