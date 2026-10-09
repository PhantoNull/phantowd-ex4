/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Mock-only C orchestration tests, NEVER guest/SMB/transport qualification. */
#define main fixture_main
#include "samba-pending-write-fixture.c"
#undef main
#include <stdlib.h>
#include <sys/wait.h>

static int context_token, file_token;
static SMBCCTX *const expected_context = (SMBCCTX *)&context_token;
static SMBCFILE *const expected_file = (SMBCFILE *)&file_token;
static int phase, missing, opened, observed, sought, written, closed, contexts;
static off_t remote_size;
static mode_t remote_mode;

static void require_at(int condition, int line)
{
    if (!condition) { fprintf(stderr, "mock orchestration assertion failed line=%d\n", line); exit(2); }
}
#define require(condition) require_at((condition), __LINE__)

static SMBCFILE *mock_open(SMBCCTX *context, const char *name, int flags, mode_t mode)
{
    require(context == expected_context && !strcmp(name, remote) && flags == O_RDWR && mode == 0);
    opened++;
    if (phase == 6) auth_refused = 1;
    return phase == 1 ? NULL : expected_file;
}
static int mock_stat(SMBCCTX *context, SMBCFILE *file, struct stat *info)
{
    require(context == expected_context && file == expected_file);
    observed++;
    memset(info, 0, sizeof(*info)); info->st_mode = remote_mode; info->st_size = remote_size;
    if (phase == 7) auth_refused = 1;
    return phase == 2 ? -1 : 0;
}
static off_t mock_seek(SMBCCTX *context, SMBCFILE *file, off_t offset, int whence)
{
    require(context == expected_context && file == expected_file && offset == 512 && whence == SEEK_SET);
    sought++;
    if (phase == 8) auth_refused = 1;
    return phase == 3 ? -1 : offset;
}
static ssize_t mock_write(SMBCCTX *context, SMBCFILE *file, const void *buffer, size_t size)
{
    require(context == expected_context && file == expected_file && size == 512);
    const unsigned char *bytes = buffer;
    for (size_t i = 0; i < size; ++i) require(bytes[i] == 0xa5);
    written++;
    if (phase == 9) auth_refused = 1;
    if (phase == 4) return -1;
    if (phase == 11) return 0;
    if (phase == 12) return 511;
    if (phase == 13) return 513;
    return (ssize_t)size;
}
static int mock_close(SMBCCTX *context, SMBCFILE *file)
{
    require(context == expected_context && file == expected_file);
    closed++;
    if (phase == 10) auth_refused = 1;
    return phase == 5 ? -1 : 0;
}
smbc_open_fn smbc_getFunctionOpen(SMBCCTX *c) { require(c == expected_context); return missing == 1 ? NULL : mock_open; }
smbc_fstat_fn smbc_getFunctionFstat(SMBCCTX *c) { require(c == expected_context); return missing == 2 ? NULL : mock_stat; }
smbc_lseek_fn smbc_getFunctionLseek(SMBCCTX *c) { require(c == expected_context); return missing == 3 ? NULL : mock_seek; }
smbc_write_fn smbc_getFunctionWrite(SMBCCTX *c) { require(c == expected_context); return missing == 4 ? NULL : mock_write; }
smbc_close_fn smbc_getFunctionClose(SMBCCTX *c) { require(c == expected_context); return missing == 5 ? NULL : mock_close; }
SMBCCTX *smbc_new_context(void) { contexts++; return expected_context; }
SMBCCTX *smbc_init_context(SMBCCTX *c) { require(c == expected_context); return c; }
int smbc_free_context(SMBCCTX *c, int shutdown) { require(c == expected_context && shutdown == 1); return 0; }
void smbc_setDebug(SMBCCTX *c, int level) { require(c == expected_context && level == 0); }
void smbc_setTimeout(SMBCCTX *c, int timeout) { require(c == expected_context && timeout == 2000); }
void smbc_setPort(SMBCCTX *c, uint16_t port) { require(c == expected_context && port == 1445); }
void smbc_setOptionNoAutoAnonymousLogin(SMBCCTX *c, smbc_bool b) { require(c == expected_context && b == 1); }
void smbc_setOptionUseKerberos(SMBCCTX *c, smbc_bool b) { require(c == expected_context && b == 0); }
void smbc_setOptionUseCCache(SMBCCTX *c, smbc_bool b) { require(c == expected_context && b == 0); }
void smbc_setFunctionAuthDataWithContext(SMBCCTX *c, smbc_get_auth_data_with_context_fn fn) { require(c == expected_context && fn == authenticate); }
smbc_bool smbc_setOptionProtocols(SMBCCTX *c, const char *min, const char *max) { require(c == expected_context && !strcmp(min, "SMB3_11") && !strcmp(max, "SMB3_11")); return 1; }

static void reset(void)
{
    phase = missing = opened = observed = sought = written = closed = auth_refused = 0;
    remote_size = 4096; remote_mode = S_IFREG | 0640; forget_secret();
}

static int run_transfer(const char *commands)
{
    int saved = dup(0), input[2]; require(saved >= 0 && !pipe(input));
    size_t size = strlen(commands);
    require(write(input[1], commands, size) == (ssize_t)size && !close(input[1]));
    require(dup2(input[0], 0) == 0 && !close(input[0]));
    int result = transfer(expected_context);
    require(dup2(saved, 0) == 0 && !close(saved));
    return result;
}

static void secret_case(const unsigned char *bytes, size_t size, int valid)
{
    int input[2]; require(!pipe(input));
    require(write(input[1], bytes, size) == (ssize_t)size && !close(input[1]));
    if (input[0] != 3) require(dup2(input[0], 3) == 3 && !close(input[0]));
    forget_secret();
    require((read_secret() == 0) == valid);
    if (!valid) close(3); /* Only mock harness cleanup, never a network retry. */
    forget_secret();
    for (size_t i = 0; i < sizeof(secret); ++i) require(secret[i] == 0);
}

static void forbidden_exit_cleanup(void)
{
    _Exit(98); /* Actual fixture entry must bypass arbitrary library hooks. */
}

int main(void)
{
    /* Real host entry must refuse before allocating any Samba context. */
    char *args[] = {"test", NULL};
    require(client_main(1, args) == 1 && contexts == 0);
    require(client_main(2, args) == 1 && contexts == 0);
    pid_t child = fork(); require(child >= 0);
    if (!child) { require(!atexit(forbidden_exit_cleanup)); fixture_main(1, args); _Exit(99); }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1);
    int output = open("/dev/null", O_WRONLY | O_CLOEXEC), saved_output = fcntl(1, F_DUPFD_CLOEXEC, 64);
    require(output >= 0 && saved_output >= 64 && dup2(output, 1) == 1 && !close(output));
    reset(); require(run_transfer("WC") == 0 && opened == 1 && observed == 1 && sought == 1 && written == 1 && closed == 1);
    reset(); require(run_transfer("C") == 0 && opened == 1 && observed == 1 && sought == 0 && written == 0 && closed == 1);
    for (int failure = 1; failure <= 13; ++failure) {
        reset(); phase = failure;
        require(run_transfer("WC") == -1 && opened == 1 && written <= 1);
        require(closed == (failure == 5 || failure == 10));
    }
    for (int accessor = 1; accessor <= 5; ++accessor) {
        reset(); missing = accessor;
        require(run_transfer("WC") == -1 && opened == 0 && written == 0 && closed == 0);
    }
    reset(); remote_size = 4095; require(run_transfer("WC") == -1 && written == 0 && closed == 0);
    reset(); remote_mode = S_IFDIR | 0755; require(run_transfer("WC") == -1 && written == 0 && closed == 0);
    const char *bad[] = {"", "X", "WW", "W"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        reset(); require(run_transfer(bad[i]) == -1 && opened == 1 && written <= 1 && closed == 0);
    }
    reset(); auth_refused = 1; require(run_transfer("WC") == -1 && opened == 0);
    char group[16], user[32], password[160];
    auth_refused = 0; /* Independent callback case; the earlier latch stays sticky within its case. */
    memcpy(secret, "mock-only-password", sizeof("mock-only-password"));
    authenticate(expected_context, "127.0.0.1", "Writable", group, sizeof(group), user, sizeof(user), password, sizeof(password));
    require(!auth_refused && !group[0] && !strcmp(user, "qpsecond") && !strcmp(password, secret));
    const char *servers[] = {"example.invalid", "127.0.0.1", NULL};
    const char *shares[] = {"Writable", "readonly", "Writable"};
    for (size_t i = 0; i < 3; ++i) {
        auth_refused = 0;
        memset(user, 'X', sizeof(user)); memset(password, 'X', sizeof(password));
        authenticate(expected_context, servers[i], shares[i], group, sizeof(group), user, sizeof(user), password, sizeof(password));
        require(auth_refused && !user[0] && !password[0]);
        authenticate(expected_context, "127.0.0.1", "Writable", group, sizeof(group), user, sizeof(user), password, sizeof(password));
        require(auth_refused && !user[0] && !password[0]);
    }
    auth_refused = 0;
    authenticate(expected_context, "127.0.0.1", "Writable", group, sizeof(group), user, 2, password, sizeof(password));
    require(auth_refused && !user[0] && !password[0]);
    const unsigned char valid[] = "mock-only-password\n";
    secret_case(valid, sizeof(valid) - 1, 1);
    const unsigned char *invalid[] = {(const unsigned char *)"\n", (const unsigned char *)"x", (const unsigned char *)"x\ny", (const unsigned char *)"x \n", (const unsigned char *)"x\r\n", (const unsigned char *)"x\0\n"};
    const size_t lengths[] = {1, 1, 3, 3, 3, 3};
    for (size_t i = 0; i < 6; ++i) secret_case(invalid[i], lengths[i], 0);
    unsigned char longest[130]; memset(longest, 'x', sizeof(longest)); longest[128] = '\n';
    secret_case(longest, 129, 1); longest[128] = 'x'; longest[129] = '\n'; secret_case(longest, 130, 0);
    forget_secret();
    require(dup2(saved_output, 1) == 1 && !close(saved_output));
    puts("PHANTOWD_SMB_WRITE_CLIENT_HOST_MOCK_DONE actual_smb=false guest=false transport=false scope=host-mock-only");
    return 0;
}
