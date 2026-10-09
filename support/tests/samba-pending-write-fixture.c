/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Test-only same-open client. Not installed or wired to any guest/product. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <libsmbclient.h>

static char secret[129];
static int auth_refused;
static const char remote[] = "smb://127.0.0.1/Writable/pending-write";

static void forget_secret(void)
{
    volatile unsigned char *bytes = (volatile unsigned char *)secret;
    for (size_t i = 0; i < sizeof(secret); ++i)
        bytes[i] = 0;
}

/* Never display or forward a secret to an alternate server/share/identity.
 * Empty callback buffers are not success: every operation checks the latch. */
static void authenticate(SMBCCTX *context, const char *server, const char *share,
                         char *workgroup, int group_size, char *user, int user_size,
                         char *password, int password_size)
{
    (void)context;
    if (workgroup && group_size > 0) workgroup[0] = 0;
    if (user && user_size > 0) user[0] = 0;
    if (password && password_size > 0) password[0] = 0;
    if (auth_refused || !server || strcmp(server, "127.0.0.1") ||
        !share || strcmp(share, "Writable") || !workgroup || group_size < 1 ||
        !user || user_size < (int)sizeof("qpsecond") || !password ||
        !secret[0] || password_size <= (int)strlen(secret)) {
        auth_refused = 1;
        return;
    }
    memcpy(user, "qpsecond", sizeof("qpsecond"));
    memcpy(password, secret, strlen(secret) + 1);
}

static int pipe_descriptor(int descriptor, int access)
{
    struct stat info;
    struct statfs filesystem;
    int flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == access &&
        !fstat(descriptor, &info) && S_ISFIFO(info.st_mode) &&
        !fstatfs(descriptor, &filesystem) && filesystem.f_type == PIPEFS_MAGIC;
}

/* This platform/isolation refusal is NOT retained-code execution authority.
 * A future fixed launcher must independently bind code/configuration/root and
 * original process ownership. No existing root helper is widened here. */
static int guard(void)
{
#if !defined(__arm__)
    return -1;
#else
    char model[32] = {0};
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    ssize_t count = read(fd, model, sizeof(model));
    int closed = close(fd);
    if (closed || count != sizeof("ARM Versatile PB") ||
        memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB"))) return -1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    struct statvfs root;
    if (getpid() <= 1 || getpgrp() != getpid() || getuid() != 65534 ||
        geteuid() != 65534 || getgid() != 65534 || getegid() != 65534 ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, caps) || caps[0].effective ||
        caps[0].permitted || caps[0].inheritable || caps[1].effective ||
        caps[1].permitted || caps[1].inheritable || statvfs("/", &root) ||
        !(root.f_flag & ST_RDONLY)) return -1;
    for (unsigned int cap = 0; cap < 64; ++cap) {
        int bounded = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bounded < 0) {
            if (errno != EINVAL || cap <= CAP_LAST_CAP) return -1;
            break;
        }
        if (bounded || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0)) return -1;
    }
    return 0;
#endif
}

/* A single bounded printable-ASCII fixture secret, terminated by newline/EOF.
 * No stdin prompt, environment, argv credential or credential-file lookup. */
static int read_secret(void)
{
    size_t used = 0;
    char byte;
    for (;;) {
        if (read(3, &byte, 1) != 1) return -1;
        if (byte == '\n') break;
        if ((unsigned char)byte < 33 || (unsigned char)byte > 126 || used == sizeof(secret) - 1) return -1;
        secret[used++] = byte;
    }
    if (!used || read(3, &byte, 1) != 0 || close(3)) return -1;
    return 0;
}

/* A notice is intent/return telemetry, NEVER a server opening, pending I/O,
 * stable identity, wire-request count or durable-write witness. */
static int notice(const char *message)
{
    return fputs(message, stdout) < 0 || fflush(stdout) ? -1 : 0;
}

static int transfer(SMBCCTX *context)
{
    smbc_open_fn open_file = smbc_getFunctionOpen(context);
    smbc_fstat_fn observe = smbc_getFunctionFstat(context);
    smbc_lseek_fn seek = smbc_getFunctionLseek(context);
    smbc_write_fn write_file = smbc_getFunctionWrite(context);
    smbc_close_fn close_file = smbc_getFunctionClose(context);
    if (!open_file || !observe || !seek || !write_file || !close_file || auth_refused) return -1;
    SMBCFILE *file = open_file(context, remote, O_RDWR, 0); /* ONCE, no create/truncate. */
    if (!file || auth_refused) return -1;
    struct stat info;
    if (observe(context, file, &info) || auth_refused ||
        !S_ISREG(info.st_mode) || info.st_size != 4096) return -1;
    if (notice("PHANTOWD_SMB_WRITE_CLIENT_OPEN_NOTICE scope=qemu-only proof=false\n")) return -1;
    char command;
    if (read(0, &command, 1) != 1) return -1;
    if (command == 'W') {
        unsigned char payload[512];
        memset(payload, 0xa5, sizeof(payload));
        if (seek(context, file, 512, SEEK_SET) != 512 || auth_refused ||
            notice("PHANTOWD_SMB_WRITE_CLIENT_CALL_NOTICE scope=qemu-only proof=false\n")) return -1;
        /* libsmbclient may issue remainder requests after a positive partial
         * wire write. This is ONE library call, not necessarily ONE SMB WRITE. */
        ssize_t written = write_file(context, file, payload, sizeof(payload));
        if (written != (ssize_t)sizeof(payload) || auth_refused) return -1;
        if (notice("PHANTOWD_SMB_WRITE_CLIENT_RETURN_NOTICE scope=qemu-only proof=false durable=false\n") ||
            read(0, &command, 1) != 1) return -1;
    }
    if (command != 'C') return -1;
    /* A close error is uncertain, not repeatable. No error path issues CLOSE,
     * reopens, reconnects or retries via this wrapper. Process exit settles only
     * local descriptors, not server state or the containing service authority. */
    if (close_file(context, file) || auth_refused) return -1;
    return notice("PHANTOWD_SMB_WRITE_CLIENT_CLOSE_NOTICE scope=qemu-only proof=false\n");
}

static int client_main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || guard() || !pipe_descriptor(0, O_RDONLY) ||
        !pipe_descriptor(1, O_WRONLY) || !pipe_descriptor(2, O_WRONLY) ||
        !pipe_descriptor(3, O_RDONLY) || syscall(SYS_close_range, 4U, ~0U, 0)) goto refused;
    alarm(30); /* Disposable process budget, not a supervised service deadline. */
    if (read_secret()) goto refused;
    SMBCCTX *context = smbc_new_context();
    if (!context) goto refused;
    smbc_setDebug(context, 0);
    smbc_setTimeout(context, 2000);
    smbc_setPort(context, 1445);
    smbc_setOptionNoAutoAnonymousLogin(context, 1);
    smbc_setOptionUseKerberos(context, 0);
    smbc_setOptionUseCCache(context, 0);
    smbc_setFunctionAuthDataWithContext(context, authenticate);
    if (!smbc_setOptionProtocols(context, "SMB3_11", "SMB3_11") ||
        smbc_init_context(context) != context || transfer(context)) goto refused;
    forget_secret();
    if (smbc_free_context(context, 1)) goto refused;
    return 0;
refused:
    forget_secret();
    fputs("PHANTOWD_SMB_WRITE_CLIENT_REFUSED scope=qemu-only\n", stderr);
    return 1;
}

int main(int argc, char **argv)
{
    int result = client_main(argc, argv);
    fflush(stderr);
    /* Do not run library atexit handlers after an uncertain operation. The
     * future original process Owner must separately reap/verify the group. */
    _Exit(result);
}
