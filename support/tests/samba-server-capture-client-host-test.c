/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Orchestration mocks only: no actual SMB, guest, worker or lease proof. */
#define PHANTOWD_SAMBA_CAPTURE_CLIENT_FIXTURE 1
#if defined(PHANTOWD_CAPTURE_WITHHELD_READ_HOST_TEST)
#define PHANTOWD_CAPTURE_WITHHELD_READ_FIXTURE 1
#elif defined(PHANTOWD_CAPTURE_WAIT_READ_HOST_TEST)
#define PHANTOWD_CAPTURE_WITHHELD_READ_FIXTURE 2
#endif
#define main capture_fixture_main
#include "samba-server-capture-client-qemu.c"
#undef main
#include <stdlib.h>
#include <sys/wait.h>
#include <poll.h>

static int context_token, file_token;
static SMBCCTX *const context = (SMBCCTX *)&context_token;
static SMBCFILE *const file = (SMBCFILE *)&file_token;
static int opens, reads, seeks, closes, handles, contexts;
static int fault, missing, handle_at, handle_fault;
static unsigned int refusals;

static void require_at(int condition, int line)
{
    if (!condition) { fprintf(stderr, "capture client mock failed line=%d\n", line); exit(2); }
}
#define require(c) require_at((c), __LINE__)

static SMBCFILE *mock_open(SMBCCTX *c, const char *path, int flags, mode_t mode)
{
    require(c == context && !strcmp(path, "smb://127.0.0.1/readonly/capture-read") &&
        flags == O_RDONLY && mode == 0 && opens == 0);
    opens++;
    if (fault == 2) auth_refused = 1;
    return fault == 1 ? NULL : file;
}
static int mock_stat(SMBCCTX *c, SMBCFILE *f, struct stat *s)
{
    require(c == context && f == file && closes == 0);
    memset(s, 0, sizeof(*s)); s->st_mode = S_IFREG | 0444; s->st_size = 4;
    if (fault == 4) s->st_size = 3;
    if (fault == 5) s->st_mode = S_IFDIR | 0755;
    if (fault == 6) auth_refused = 1;
    return fault == 3 ? -1 : 0;
}
static ssize_t mock_read(SMBCCTX *c, SMBCFILE *f, void *bytes, size_t size)
{
    require(c == context && f == file && size == 1 && reads < 2 && reads == seeks && closes == 0);
    reads++; *(char *)bytes = fault == 11 ? 'x' : 'd';
    if (fault == 12) auth_refused = 1;
    if (fault == 7) return -1;
    if (fault == 8) return 0;
    if (fault == 9) return 2;
    return 1;
}
static off_t mock_seek(SMBCCTX *c, SMBCFILE *f, off_t offset, int whence)
{
    require(c == context && f == file && offset == 0 && whence == SEEK_SET && reads == seeks + 1 && closes == 0);
    seeks++;
    if (fault == 15) auth_refused = 1;
    if (fault == 13) return -1;
    if (fault == 14) return 1;
    return 0;
}
static int mock_close(SMBCCTX *c, SMBCFILE *f)
{
    require(c == context && f == file && closes == 0); closes++;
    if (fault == 17) auth_refused = 1;
    return fault == 16 ? -1 : 0;
}
int phantowd_qemu_observe_smb_handle_v1(SMBCCTX *c, SMBCFILE *f,
    struct phantowd_pending_handle_observation_v1 *out)
{
    require(c == context && f == file && closes == 0 && reads == seeks);
    handles++;
    *out = (struct phantowd_pending_handle_observation_v1){
        .session_id = UINT64_C(4294967297), .tree_id = 3,
        .persistent_id = UINT64_C(4294967301), .volatile_id = UINT64_C(4294967303)};
    if (handles == handle_at) {
        if (handle_fault == 1) return -1;
        if (handle_fault == 2) auth_refused = 1;
        uint64_t invalid = handle_fault % 2 ? 0 : UINT64_MAX;
        switch (handle_fault) {
        case 3: case 4: out->session_id = invalid; break;
        case 5: case 6: out->tree_id = (uint32_t)invalid; break;
        case 7: case 8: out->persistent_id = invalid; break;
        case 9: case 10: out->volatile_id = invalid; break;
        case 11: out->session_id++; break;
        case 12: out->tree_id++; break;
        case 13: out->persistent_id++; break;
        case 14: out->volatile_id++; break;
        }
    }
    return 0;
}
smbc_open_fn smbc_getFunctionOpen(SMBCCTX *c) { require(c == context); return missing == 1 ? NULL : mock_open; }
smbc_fstat_fn smbc_getFunctionFstat(SMBCCTX *c) { require(c == context); return missing == 2 ? NULL : mock_stat; }
smbc_read_fn smbc_getFunctionRead(SMBCCTX *c) { require(c == context); return missing == 3 ? NULL : mock_read; }
smbc_lseek_fn smbc_getFunctionLseek(SMBCCTX *c) { require(c == context); return missing == 4 ? NULL : mock_seek; }
smbc_close_fn smbc_getFunctionClose(SMBCCTX *c) { require(c == context); return missing == 5 ? NULL : mock_close; }
SMBCCTX *smbc_new_context(void) { contexts++; return context; }
SMBCCTX *smbc_init_context(SMBCCTX *c) { return c; }
int smbc_free_context(SMBCCTX *c, int shutdown) { require(c == context && shutdown == 1); return 0; }
void smbc_setDebug(SMBCCTX *c, int v) { require(c == context && v == 0); }
void smbc_setTimeout(SMBCCTX *c, int v) { require(c == context && v == 2000); }
void smbc_setPort(SMBCCTX *c, uint16_t v) { require(c == context && v == 1445); }
void smbc_setOptionNoAutoAnonymousLogin(SMBCCTX *c, smbc_bool v) { require(c == context && v == 1); }
void smbc_setOptionUseKerberos(SMBCCTX *c, smbc_bool v) { require(c == context && v == 0); }
void smbc_setOptionUseCCache(SMBCCTX *c, smbc_bool v) { require(c == context && v == 0); }
void smbc_setFunctionAuthDataWithContext(SMBCCTX *c, smbc_get_auth_data_with_context_fn fn)
{ require(c == context && fn == authenticate); }
smbc_bool smbc_setOptionProtocols(SMBCCTX *c, const char *min, const char *max)
{ require(c == context && !strcmp(min, "SMB3_11") && !strcmp(max, "SMB3_11")); return 1; }

static int run(const char *commands)
{
    int saved = dup(0), input[2]; require(saved >= 0 && !pipe(input));
    size_t size = strlen(commands);
    require(write(input[1], commands, size) == (ssize_t)size && !close(input[1]));
    require(dup2(input[0], 0) == 0 && !close(input[0]));
    int result = transfer(context);
    require(dup2(saved, 0) == 0 && !close(saved));
    return result;
}
static void reset(void)
{
    opens = reads = seeks = closes = handles = auth_refused = 0;
    fault = missing = handle_at = handle_fault = 0;
    forget_secret();
}
static void secret_case(const unsigned char *bytes, size_t size, int valid)
{
    int input[2]; require(!pipe(input));
    require(write(input[1], bytes, size) == (ssize_t)size && !close(input[1]));
    if (input[0] != 3) require(dup2(input[0], 3) == 3 && !close(input[0]));
    forget_secret();
    require((read_secret() == 0) == valid);
    if (!valid) { close(3); refusals++; }
    forget_secret();
    for (size_t i = 0; i < sizeof(secret); ++i) require(secret[i] == 0);
}
static void forbidden_exit_cleanup(void) { _Exit(98); }
#if !defined(PHANTOWD_CAPTURE_WITHHELD_READ_HOST_TEST) && !defined(PHANTOWD_CAPTURE_WAIT_READ_HOST_TEST)
int main(void)
{
    /* Real host entry refuses before context allocation, without atexit calls. */
    char *argv[] = {"test", NULL};
    require(client_main(1, argv) == 1 && contexts == 0);
    require(client_main(2, argv) == 1 && contexts == 0);
    pid_t child = fork(); require(child >= 0);
    if (!child) { require(!atexit(forbidden_exit_cleanup)); capture_fixture_main(1, argv); _Exit(99); }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1);
    int saved_output = fcntl(1, F_DUPFD_CLOEXEC, 64), output[2];
    require(saved_output >= 64 && !pipe(output) && dup2(output[1], 1) == 1 && !close(output[1]));
    require(run("RRC") == 0 && opens == 1 && reads == 2 && seeks == 2 && closes == 1 && handles == 6);
    int sink = open("/dev/null", O_WRONLY | O_CLOEXEC);
    require(sink >= 0 && dup2(sink, 1) == 1 && !close(sink));
    char receipt[1024] = {0};
    ssize_t received = read(output[0], receipt, sizeof(receipt));
    require(received > 0 && received < (ssize_t)sizeof(receipt) && !close(output[0]));
    const char expected[] =
        "PHANTOWD_CAPTURE_CLIENT_HANDLE session=4294967297 tree=3 persistent=4294967301 volatile=4294967303 scope=qemu-only proof=false\n"
        "PHANTOWD_CAPTURE_CLIENT_OPEN scope=qemu-only proof=false\n"
        "PHANTOWD_CAPTURE_CLIENT_READ sequence=1 scope=qemu-only proof=false\n"
        "PHANTOWD_CAPTURE_CLIENT_READ sequence=2 scope=qemu-only proof=false\n"
        "PHANTOWD_CAPTURE_CLIENT_CLOSE scope=qemu-only proof=false\n";
    require(received == (ssize_t)strlen(expected) && !strcmp(receipt, expected));
    reset(); require(run("C") == 0 && opens == 1 && reads == 0 && closes == 1 && handles == 2);
    reset(); require(run("RC") == 0 && opens == 1 && reads == 1 && seeks == 1 && closes == 1 && handles == 4);
    const char *invalid[] = {"", "W", "WC", "X", "R", "RR", "RRRC", "RXC", "RW"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        reset(); require(run(invalid[i]) == -1 && opens == 1 && reads <= 2 && closes == 0); refusals++;
    }
    for (int f = 1; f <= 17; ++f) {
        if (f == 10) continue;
        reset(); fault = f;
        require(run("RRC") == -1 && opens == 1 && reads <= 2 && closes == (f >= 16)); refusals++;
    }
    for (int accessor = 1; accessor <= 5; ++accessor) {
        reset(); missing = accessor;
        require(run("RRC") == -1 && opens == 0 && reads == 0 && closes == 0); refusals++;
    }
    for (int f = 1; f <= 10; ++f) {
        reset(); handle_at = 1; handle_fault = f;
        require(run("RRC") == -1 && opens == 1 && reads == 0 && closes == 0); refusals++;
    }
    for (int at = 2; at <= 6; ++at) {
        for (int f = 1; f <= 14; ++f) {
            reset(); handle_at = at; handle_fault = f;
            require(run("RRC") == -1 && opens == 1 && reads <= 2 && closes == 0); refusals++;
        }
    }
    reset(); auth_refused = 1; require(run("RRC") == -1 && opens == 0); refusals++;
    char group[16], user[16], password[160];
    memcpy(secret, "synthetic", sizeof("synthetic"));
    auth_refused = 0;
    authenticate(context, "127.0.0.1", "readonly", group, sizeof(group), user, sizeof(user), password, sizeof(password));
    require(!auth_refused && !group[0] && !strcmp(user, "nobody") && !strcmp(password, "synthetic"));
    const char *servers[] = {"localhost", "127.0.0.2", NULL};
    for (size_t i = 0; i < sizeof(servers) / sizeof(servers[0]); ++i) {
        auth_refused = 0;
        authenticate(context, servers[i], "readonly", group, sizeof(group), user, sizeof(user), password, sizeof(password));
        require(auth_refused && !group[0] && !user[0] && !password[0]);
        authenticate(context, "127.0.0.1", "readonly", group, sizeof(group), user, sizeof(user), password, sizeof(password));
        require(auth_refused && !user[0] && !password[0]); refusals++;
    }
    auth_refused = 0;
    authenticate(context, "127.0.0.1", "writable", group, sizeof(group), user, sizeof(user), password, sizeof(password));
    require(auth_refused && !user[0] && !password[0]); refusals++;
    auth_refused = 0;
    authenticate(context, "127.0.0.1", "readonly", group, sizeof(group), user, 6, password, sizeof(password));
    require(auth_refused && !user[0] && !password[0]); refusals++;
    secret_case((const unsigned char *)"synthetic\n", 10, 1);
    secret_case((const unsigned char *)"\n", 1, 0);
    secret_case((const unsigned char *)"synthetic", 9, 0);
    secret_case((const unsigned char *)"synthetic\nextra", 15, 0);
    secret_case((const unsigned char *)"bad token\n", 10, 0);
    unsigned char maximum[130]; memset(maximum, 'x', sizeof(maximum)); maximum[128] = '\n';
    secret_case(maximum, 129, 1); maximum[128] = 'x'; maximum[129] = '\n';
    secret_case(maximum, 130, 0);
    require(dup2(saved_output, 1) == 1 && !close(saved_output));
    printf("PHANTOWD_CAPTURE_CLIENT_HOST_DONE same_open=true reads=2 refusals=%u actual_smb=false scope=host-mock-only\n", refusals);
    return 0;
}
#elif defined(PHANTOWD_CAPTURE_WITHHELD_READ_HOST_TEST)
int main(void)
{
    (void)secret_case; (void)forbidden_exit_cleanup;
    int saved_output = fcntl(1, F_DUPFD_CLOEXEC, 64), output[2];
    require(saved_output >= 64 && !pipe(output) && dup2(output[1], 1) == 1 && !close(output[1]));
    reset();
    require(run("RRC") == -1 && opens == 1 && reads == 1 && seeks == 1 && closes == 0 && handles == 3);
    require(dup2(saved_output, 1) == 1 && !close(saved_output));
    char receipt[1024] = {0};
    ssize_t received = read(output[0], receipt, sizeof(receipt));
    require(received > 0 && received < (ssize_t)sizeof(receipt) && !close(output[0]));
    const char expected[] =
        "PHANTOWD_CAPTURE_CLIENT_HANDLE session=4294967297 tree=3 persistent=4294967301 volatile=4294967303 scope=qemu-only proof=false\n"
        "PHANTOWD_CAPTURE_CLIENT_OPEN scope=qemu-only proof=false\n";
    require(received == (ssize_t)(sizeof(expected) - 1) && !memcmp(receipt, expected, sizeof(expected) - 1));
    printf("PHANTOWD_CAPTURE_WITHHELD_HOST_DONE completed_mock_read=true read_ack=false close=false retries=false actual_smb=false scope=host-mock-only\n");
    return 0;
}
#else
int main(void)
{
    (void)secret_case; (void)forbidden_exit_cleanup; (void)run;
    int command[2], output[2];
    require(!pipe(command) && !pipe(output));
    pid_t child = fork();
    require(child >= 0);
    if (!child) {
        require(!close(command[1]) && !close(output[0]));
        require(dup2(command[0], 0) == 0 && dup2(output[1], 1) == 1);
        require(!close(command[0]) && !close(output[1]));
        reset();
        require(transfer(context) == -1 && opens == 1 && reads == 1 && seeks == 1 && closes == 0 && handles == 3);
        _Exit(0);
    }
    require(!close(command[0]) && !close(output[1]) && write(command[1], "R", 1) == 1);
    const char expected[] =
        "PHANTOWD_CAPTURE_CLIENT_HANDLE session=4294967297 tree=3 persistent=4294967301 volatile=4294967303 scope=qemu-only proof=false\n"
        "PHANTOWD_CAPTURE_CLIENT_OPEN scope=qemu-only proof=false\n";
    char receipt[sizeof(expected) - 1];
    size_t received = 0;
    while (received < sizeof(receipt)) {
        ssize_t n = read(output[0], receipt + received, sizeof(receipt) - received);
        require(n > 0); received += (size_t)n;
    }
    require(!memcmp(receipt, expected, sizeof(receipt)));
    struct pollfd waiting = {.fd = output[0], .events = POLLIN};
    int status = 0;
    require(poll(&waiting, 1, 100) == 0 && waitpid(child, &status, WNOHANG) == 0);
    require(!close(command[1]));
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char extra;
    require(read(output[0], &extra, 1) == 0 && !close(output[0]));
    puts("PHANTOWD_CAPTURE_WAIT_HOST_DONE blocked_without_ack=true eof_refused=true close=false retries=false actual_smb=false scope=host-mock-only");
    return 0;
}
#endif
