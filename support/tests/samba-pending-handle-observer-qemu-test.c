/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors */
/* Actual pinned Samba types + fnum/idr allocation/removal, mocked connection
 * getters. No SMB server/transport/client opening or execution-authority proof.
 * Combined upstream translation unit retains GPL-3.0-or-later terms. */
#include "samba-pending-handle-observer-fixture.c"
#include <dlfcn.h>
#include <sys/statvfs.h>

static char connection_token, session_token, tree_token;
static int connected = 1;
static enum protocol_types protocol = PROTOCOL_SMB3_11;
static uint64_t session_id = 0x123456789abcdef0;
static uint32_t tree_id = 17;
static unsigned checks;

static void require_at(bool value, int line)
{
    if (!value) { fprintf(stderr, "handle observer assertion line=%d\n", line); _Exit(1); }
}
#define require(value) require_at((value), __LINE__)

/* Opaque token comparison only, never fabricated private connection layouts.
 * These mocks are local to this standalone executable, not the observer DSO. */
bool smbXcli_conn_is_connected(struct smbXcli_conn *conn)
{ require(conn == (struct smbXcli_conn *)&connection_token); return connected; }
enum protocol_types smbXcli_conn_protocol(struct smbXcli_conn *conn)
{ require(conn == (struct smbXcli_conn *)&connection_token); return protocol; }
uint64_t smb2cli_session_current_id(struct smbXcli_session *session)
{ require(session == (struct smbXcli_session *)&session_token); return session_id; }
uint32_t smb2cli_tcon_current_id(struct smbXcli_tcon *tree)
{ require(tree == (struct smbXcli_tcon *)&tree_token); return tree_id; }

static void refused(SMBCCTX *context, SMBCFILE *file)
{
    struct phantowd_pending_handle_observation_v1 output;
    memset(&output, 0xa5, sizeof(output));
    require(phantowd_qemu_observe_smb_handle_v1(context, file, &output) == -1);
    const unsigned char *bytes = (const unsigned char *)&output;
    for (size_t i = 0; i < sizeof(output); ++i) require(bytes[i] == 0);
    checks++;
}

int main(void)
{
#if !defined(__arm__)
    return 1;
#else
    char model[32] = {0};
    int fd = open("/sys/firmware/devicetree/base/model", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    require(fd >= 0);
    ssize_t count = read(fd, model, sizeof(model));
    require(!close(fd) && count == sizeof("ARM Versatile PB") &&
        !memcmp(model, "ARM Versatile PB", sizeof("ARM Versatile PB")));
    struct statvfs root;
    require(!statvfs("/", &root) && (root.f_flag & ST_RDONLY));
    alarm(5);
    /* Independently load the one-export DSO, but exercise ONLY early refusals:
     * its connection getters are real, unlike the positive seam below. */
    void *module = dlopen("/usr/lib/phantowd-pending-handle-fixture.so", RTLD_NOW | RTLD_LOCAL);
    require(module != NULL);
    int (*loaded)(SMBCCTX *, SMBCFILE *, struct phantowd_pending_handle_observation_v1 *) =
        dlsym(module, "phantowd_qemu_observe_smb_handle_v1");
    require(loaded != NULL);
    struct phantowd_pending_handle_observation_v1 empty;
    memset(&empty, 0xa5, sizeof(empty));
    require(loaded(NULL, NULL, &empty) == -1);
    const unsigned char *empty_bytes = (const unsigned char *)&empty;
    for (size_t i = 0; i < sizeof(empty); ++i) require(empty_bytes[i] == 0);
    SMBCCTX uninitialized = {0};
    require(loaded(&uninitialized, (SMBCFILE *)(uintptr_t)1, &empty) == -1 &&
        loaded(NULL, NULL, NULL) == -1 && !dlclose(module));
    struct cli_state *cli = talloc_zero(NULL, struct cli_state);
    require(cli != NULL);
    cli->conn = (struct smbXcli_conn *)&connection_token;
    cli->smb2.session = (struct smbXcli_session *)&session_token;
    cli->smb2.tcon = (struct smbXcli_tcon *)&tree_token;
    uint16_t fnum = 0;
    require(NT_STATUS_IS_OK(map_smb2_handle_to_fnum(cli, 0x1111222233334444,
        0x5555666677778888, false, &fnum)));
    SMBCFILE file = {.cli_fd = fnum, .targetcli = cli, .file = true};
    struct SMBC_internal_data internal = {.initialized = true, .files = &file};
    SMBCCTX context = {.internal = &internal};
    struct phantowd_pending_handle_observation_v1 original, output;
    require(!phantowd_qemu_observe_smb_handle_v1(&context, &file, &original));
    require(original.session_id == session_id && original.tree_id == tree_id &&
        original.persistent_id == 0x1111222233334444 &&
        original.volatile_id == 0x5555666677778888);
    require(phantowd_qemu_observe_smb_handle_v1(&context, &file, NULL) == -1); checks++;
    refused(NULL, &file); refused(&context, NULL);
    refused(&context, (SMBCFILE *)(uintptr_t)1); /* Must not dereference foreign. */
    context.internal = NULL; refused(&context, &file); context.internal = &internal;
    internal.initialized = false; refused(&context, &file); internal.initialized = true;
    internal.files = NULL; refused(&context, &file); internal.files = &file;
    file.next = &file; refused(&context, &file); file.next = NULL;
    file.prev = &file; refused(&context, &file); file.prev = NULL;
    file.file = false; refused(&context, &file); file.file = true;
    file.dir_list = (struct smbc_dir_list *)&connection_token;
    refused(&context, &file); file.dir_list = NULL;
    file.dirplus_list = (struct smbc_dirplus_list *)&connection_token;
    refused(&context, &file); file.dirplus_list = NULL;
    for (off_t offset = -1; offset <= 1; offset += 2) {
        file.offset = offset; refused(&context, &file);
    }
    file.offset = 0;
    int invalid[] = {-1, 0, 0xffff, 0x10001};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        file.cli_fd = invalid[i]; refused(&context, &file);
    }
    file.cli_fd = fnum + 1; refused(&context, &file); file.cli_fd = fnum;
    file.targetcli = NULL; refused(&context, &file); file.targetcli = cli;
    cli->conn = NULL; refused(&context, &file); cli->conn = (struct smbXcli_conn *)&connection_token;
    cli->smb2.session = NULL; refused(&context, &file); cli->smb2.session = (struct smbXcli_session *)&session_token;
    cli->smb2.tcon = NULL; refused(&context, &file); cli->smb2.tcon = (struct smbXcli_tcon *)&tree_token;
    connected = 0; refused(&context, &file); connected = 1;
    protocol = PROTOCOL_SMB3_00; refused(&context, &file); protocol = PROTOCOL_SMB3_11;
    struct idr_context *idr = cli->smb2.open_handles;
    cli->smb2.open_handles = NULL; refused(&context, &file); cli->smb2.open_handles = idr;
    struct smb2_hnd *handle = NULL;
    require(NT_STATUS_IS_OK(map_fnum_to_smb2_handle(cli, fnum, &handle)) && handle);
    handle->posix = true; refused(&context, &file); handle->posix = false;
    uint64_t invalid64[] = {0, UINT64_MAX};
    for (size_t i = 0; i < 2; ++i) {
        handle->fid_persistent = invalid64[i]; refused(&context, &file);
        handle->fid_persistent = original.persistent_id;
        handle->fid_volatile = invalid64[i]; refused(&context, &file);
        handle->fid_volatile = original.volatile_id;
        session_id = invalid64[i]; refused(&context, &file); session_id = original.session_id;
        tree_id = (uint32_t)invalid64[i]; refused(&context, &file); tree_id = original.tree_id;
    }
    require(!phantowd_qemu_observe_smb_handle_v1(&context, &file, &output) &&
        output.session_id == original.session_id && output.tree_id == original.tree_id &&
        output.persistent_id == original.persistent_id && output.volatile_id == original.volatile_id);
    /* Real upstream deletion invalidates the old map, without issuing CLOSE. */
    require(NT_STATUS_IS_OK(delete_smb2_handle_mapping(cli, &handle, fnum)) && !handle);
    refused(&context, &file);
    /* Reused local fnum is not persistent identity. The reader exposes the new
     * tuple; a containing original-observation fence must reject that change. */
    uint16_t reused = 0;
    require(NT_STATUS_IS_OK(map_smb2_handle_to_fnum(cli, 23, 29, false, &reused)) && reused == fnum);
    require(!phantowd_qemu_observe_smb_handle_v1(&context, &file, &output) &&
        output.persistent_id == 23 && output.volatile_id == 29 &&
        output.persistent_id != original.persistent_id && output.volatile_id != original.volatile_id);
    require(!talloc_free(cli) && checks == 36);
    printf("PHANTOWD_PENDING_HANDLE_SOURCE_READY refusals=%u real_idr=true reused_fnum_distinct=true getters=mocked dso_early_refusals=3 network=false server=false authority=false scope=qemu-only\n", checks);
    return 0;
#endif
}
