/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Dedicated read-only client; never an installed helper or WRITE authority. */
#if !defined(PHANTOWD_SAMBA_CAPTURE_CLIENT_FIXTURE) || PHANTOWD_SAMBA_CAPTURE_CLIENT_FIXTURE != 1
#error "Disposable host/QEMU fixture only"
#endif
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
#include "samba-pending-handle-observer-fixture.h"

_Static_assert(sizeof(off_t) == 8, "Samba ARM stat/seek ABI requires 64-bit offsets");
_Static_assert(sizeof(((struct stat *)0)->st_size) == 8, "Samba ARM stat ABI requires 64-bit sizes");
static char secret[129];
static int auth_refused;

static void forget_secret(void)
{
    volatile unsigned char *p = (volatile unsigned char *)secret;
    for (size_t i = 0; i < sizeof(secret); ++i) p[i] = 0;
}
static void authenticate(SMBCCTX *context, const char *server, const char *share,
    char *group, int group_size, char *user, int user_size, char *password, int password_size)
{
    (void)context;
    if (group && group_size > 0) group[0] = 0;
    if (user && user_size > 0) user[0] = 0;
    if (password && password_size > 0) password[0] = 0;
    if (auth_refused || !server || strcmp(server, "127.0.0.1") || !share ||
        strcmp(share, "readonly") || !group || group_size < 1 || !user ||
        user_size < (int)sizeof("nobody") || !password || !secret[0] ||
        password_size <= (int)strlen(secret)) {
        auth_refused = 1; return;
    }
    memcpy(user, "nobody", sizeof("nobody"));
    memcpy(password, secret, strlen(secret) + 1);
}
static int pipe_descriptor(int fd, int access)
{
    struct stat s; struct statfs fs;
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == access && !fstat(fd, &s) &&
        S_ISFIFO(s.st_mode) && !fstatfs(fd, &fs) && fs.f_type == PIPEFS_MAGIC;
}
static int guard(void)
{
#if !defined(__arm__)
    return -1;
#else
    char model[32] = {0};
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t size = read(fd, model, sizeof(model));
    if (close(fd) || size != sizeof("ARM Versatile PB") ||
        memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB"))) return -1;
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    struct statvfs root;
    if (getpid() <= 1 || getpgrp() != getpid() || getuid() != 65534 || geteuid() != 65534 ||
        getgid() != 65534 || getegid() != 65534 || getgroups(0, NULL) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || syscall(SYS_capget, &h, caps) ||
        caps[0].effective || caps[0].permitted || caps[0].inheritable ||
        caps[1].effective || caps[1].permitted || caps[1].inheritable ||
        statvfs("/", &root) || !(root.f_flag & ST_RDONLY)) return -1;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int bound = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bound < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP) return -1;
            break;
        }
        if (bound || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0)) return -1;
    }
    return 0;
#endif
}
static int read_secret(void)
{
    size_t used = 0; char byte;
    for (;;) {
        if (read(3, &byte, 1) != 1) return -1;
        if (byte == '\n') break;
        if ((unsigned char)byte < 33 || (unsigned char)byte > 126 || used == sizeof(secret) - 1) return -1;
        secret[used++] = byte;
    }
    if (!used || read(3, &byte, 1) != 0 || close(3)) return -1;
    return 0;
}
static int notice(const char *text)
{
    return fputs(text, stdout) < 0 || fflush(stdout) ? -1 : 0;
}
static int same_handle(const struct phantowd_pending_handle_observation_v1 *a,
    const struct phantowd_pending_handle_observation_v1 *b)
{
    return a->session_id == b->session_id && a->tree_id == b->tree_id &&
        a->persistent_id == b->persistent_id && a->volatile_id == b->volatile_id;
}
static int handle_notice(const struct phantowd_pending_handle_observation_v1 *h)
{
    char text[256];
    if (!h->session_id || h->session_id == UINT64_MAX || !h->tree_id || h->tree_id == UINT32_MAX ||
        !h->persistent_id || h->persistent_id == UINT64_MAX || !h->volatile_id || h->volatile_id == UINT64_MAX) return -1;
    int size = snprintf(text, sizeof(text),
        "PHANTOWD_CAPTURE_CLIENT_HANDLE session=%" PRIu64 " tree=%" PRIu32
        " persistent=%" PRIu64 " volatile=%" PRIu64 " scope=qemu-only proof=false\n",
        h->session_id, h->tree_id, h->persistent_id, h->volatile_id);
    return size <= 0 || (size_t)size >= sizeof(text) ? -1 : notice(text);
}
static int observe_same(SMBCCTX *context, SMBCFILE *file,
    const struct phantowd_pending_handle_observation_v1 *initial)
{
    struct phantowd_pending_handle_observation_v1 current = {0};
    return phantowd_qemu_observe_smb_handle_v1(context, file, &current) ||
        auth_refused || !same_handle(initial, &current) ? -1 : 0;
}
/* Fixed one OPEN, at most two R commands, then explicit C. Local seek resets
 * the same client handle to offset0; it does not reopen a file. All uncertain
 * outcomes return without protocol CLOSE/retry/reconnect or context cleanup.
 * Copied tuple/notice bytes are telemetry, not server or retained authority. */
static int transfer(SMBCCTX *context)
{
    smbc_open_fn open_file = smbc_getFunctionOpen(context);
    smbc_fstat_fn stat_file = smbc_getFunctionFstat(context);
    smbc_read_fn read_file = smbc_getFunctionRead(context);
    smbc_lseek_fn seek_file = smbc_getFunctionLseek(context);
    smbc_close_fn close_file = smbc_getFunctionClose(context);
    if (!open_file || !stat_file || !read_file || !seek_file || !close_file || auth_refused) return -1;
    SMBCFILE *file = open_file(context, "smb://127.0.0.1/readonly/capture-read", O_RDONLY, 0);
    if (!file || auth_refused) return -1;
    struct stat s;
    struct phantowd_pending_handle_observation_v1 initial = {0};
    if (stat_file(context, file, &s) || auth_refused || !S_ISREG(s.st_mode) || s.st_size != 4 ||
        phantowd_qemu_observe_smb_handle_v1(context, file, &initial) || auth_refused ||
        handle_notice(&initial) || notice("PHANTOWD_CAPTURE_CLIENT_OPEN scope=qemu-only proof=false\n")) return -1;
    unsigned int samples = 0;
    for (;;) {
        char command;
        if (read(0, &command, 1) != 1) return -1;
        if (command == 'C') {
            if (observe_same(context, file, &initial) || close_file(context, file) || auth_refused) return -1;
            return notice("PHANTOWD_CAPTURE_CLIENT_CLOSE scope=qemu-only proof=false\n");
        }
        if (command != 'R' || samples >= 2 || observe_same(context, file, &initial)) return -1;
        unsigned char byte = 0;
        if (read_file(context, file, &byte, 1) != 1 || auth_refused || byte != 'd' ||
            seek_file(context, file, 0, SEEK_SET) != 0 || auth_refused ||
            observe_same(context, file, &initial)) return -1;
        ++samples;
        if (notice(samples == 1 ? "PHANTOWD_CAPTURE_CLIENT_READ sequence=1 scope=qemu-only proof=false\n" :
            "PHANTOWD_CAPTURE_CLIENT_READ sequence=2 scope=qemu-only proof=false\n")) return -1;
    }
}
static int client_main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || guard() || !pipe_descriptor(0, O_RDONLY) || !pipe_descriptor(1, O_WRONLY) ||
        !pipe_descriptor(2, O_WRONLY) || !pipe_descriptor(3, O_RDONLY) ||
        syscall(SYS_close_range, 4U, ~0U, 0)) goto refused;
    alarm(30);
    if (read_secret()) goto refused;
    SMBCCTX *context = smbc_new_context();
    if (!context) goto refused;
    smbc_setDebug(context, 0); smbc_setTimeout(context, 2000); smbc_setPort(context, 1445);
    smbc_setOptionNoAutoAnonymousLogin(context, 1); smbc_setOptionUseKerberos(context, 0); smbc_setOptionUseCCache(context, 0);
    smbc_setFunctionAuthDataWithContext(context, authenticate);
    if (!smbc_setOptionProtocols(context, "SMB3_11", "SMB3_11") ||
        smbc_init_context(context) != context || transfer(context)) goto refused;
    forget_secret();
    if (smbc_free_context(context, 1)) goto refused;
    return 0;
refused:
    forget_secret();
    fputs("PHANTOWD_CAPTURE_CLIENT_REFUSED scope=qemu-only\n", stderr);
    return 1;
}
int main(int argc, char **argv)
{
    int result = client_main(argc, argv);
    fflush(stderr);
    _Exit(result); /* No uncertain library atexit actions; Owner must settle group. */
}
